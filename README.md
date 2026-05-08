# Komodor Image Vulnerability Watcher

A Kubernetes-native watcher that detects container image vulnerabilities and publishes actionable security events to Komodor.

## Overview

This application provides a secure, low-noise bridge between running Kubernetes workloads, vulnerability scanners (Trivy, Trivy Operator reports, Snyk, Wiz, Clair), and Komodor. It:

- Watches Kubernetes workloads (Deployments, StatefulSets, DaemonSets, Jobs, CronJobs)
- Extracts container images from running workloads
- Resolves mutable tags to immutable digests
- Scans images for vulnerabilities using pluggable scanner drivers
- Normalises scanner-specific results into a common model
- Publishes meaningful vulnerability events to Komodor
- Deduplicates scan results to avoid alert fatigue

## Security Model

The watcher is designed with a strong security posture:

- **No host access**: No hostPath mounts, runtime sockets, or privileged containers
- **No Secret access**: Does not require Kubernetes API permissions to read Secrets
- **No impersonation**: Does not impersonate workload ServiceAccounts
- **Minimal RBAC**: Read-only access to workload metadata only
- **Restricted container**: Runs as non-root with read-only filesystem and dropped capabilities

See [RFC](docs/rfc.md) for full security principles.

## Quick Start

### Prerequisites

- Kubernetes 1.24+
- A container image scanner (e.g., Trivy)
- Komodor account and API key

### Installation

```bash
# Using make
make install-tools
make build

# Or manually
go install ./cmd/komodor-security-reporter
```

### Configuration

Copy and customise the example configuration:

```bash
cp docs/example-config.yaml config.yaml
```

Key configuration options:

```yaml
clusterName: prod-eks-01

# Namespaces to watch
namespaces:
  include:
    - production
    - platform
  exclude:
    - kube-system

# Workload kinds to watch
workloads:
  kinds:
    - Deployment
    - StatefulSet

# Scanners to use
scanners:
  scanners:
    - name: trivy
      type: trivy
      enabled: true
      command:
        binary: /usr/local/bin/trivy
        timeout: 5m

# Publishing policies
publishing:
  mode: komodor
  minimumSeverity: high
  includeTopFindings: 5
  publishCleanScans: false
  dedupeTTL: 24h

komodor:
  baseURL: https://app.komodor.io
```

### Running Locally

```bash
# Set Komodor API key (required for publish mode: komodor or both)
export KOMODOR_API_KEY=your-api-key

# Run with config
./bin/komodor-security-reporter -config config.yaml

# Enable debug logging
./bin/komodor-security-reporter -config config.yaml -log-level debug
```

## Development

See [DEVELOPMENT.md](./docs/DEVELOPMENT.md) for more info

## Architecture

### Components

1. **Kubernetes Workload Watcher**: Observes supported workload resources and detects image references
2. **Image Extractor**: Reads images from containers, initContainers, and ephemeralContainers
3. **Digest Resolver**: Resolves image tags to immutable digests using go-containerregistry
4. **Scanner Registry**: Loads configured scanner drivers and invokes them
5. **Scanner Drivers**: Scan images and return structured results (Trivy, Trivy Operator, Snyk, Wiz, Clair)
6. **Finding Normaliser**: Converts scanner-specific results to a common model
7. **Policy Evaluator**: Determines whether to publish based on severity and deduplication
8. **Komodor Publisher**: Publishes normalised events to Komodor
9. **State Store**: ConfigMap-backed deduplication state

### Data Flow

```plain
Kubernetes Workload
  ↓
Image Extractor
  ↓
Digest Resolver
  ↓
Scanner Registry
  ↓
Finding Normaliser
  ↓
Policy Evaluator
  ↓
Komodor Event Publisher
  ↓
State / Dedupe Store
```

## Testing

```bash
# Run all tests
make test

# Run with coverage
make coverage

# Run short tests only (excludes integration tests)
make test-short

# Run specific test
go test -run TestFingerprint ./internal/policy
```

### Test Strategy

- **Unit tests**: All core logic components (config, scanners, registry, policy)
- **Table-driven tests**: For parsing logic and policy evaluation
- **Mock/fake clients**: For Kubernetes and Komodor interactions
- **Integration tests**: Optional for scanner drivers (skipped by default)

## Deployment

### Kubernetes Manifests

See `helm/` directory for complete Helm chart.

Minimal ServiceAccount and RBAC:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: komodor-security-reporter
  namespace: security

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: komodor-security-reporter
rules:
  - apiGroups: [""]
    resources: [namespaces]
    verbs: [get, list, watch]
  - apiGroups: [apps]
    resources: [deployments, statefulsets, daemonsets]
    verbs: [get, list, watch]
  - apiGroups: [batch]
    resources: [jobs, cronjobs]
    verbs: [get, list, watch]
  # For ConfigMap-backed state store
  - apiGroups: [""]
    resources: [configmaps]
    verbs: [get, list, create, update]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: komodor-security-reporter
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: komodor-security-reporter
subjects:
  - kind: ServiceAccount
    name: komodor-security-reporter
    namespace: security
```

### Pod Security

```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    readOnlyRootFilesystem: true
    allowPrivilegeEscalation: false
    capabilities:
      drop:
        - ALL

  containers:
    - name: watcher
      image: komodor-security-reporter:latest
      imagePullPolicy: IfNotPresent

      env:
        - name: KOMODOR_API_KEY
          valueFrom:
            secretKeyRef:
              name: komodor-credentials
              key: api-key

      ports:
        - name: metrics
          containerPort: 8080

      volumeMounts:
        - name: config
          mountPath: /etc/komodor-security-reporter
          readOnly: true
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /var/cache/komodor-security-reporter

  volumes:
    - name: config
      configMap:
        name: komodor-security-reporter
    - name: tmp
      emptyDir: {}
    - name: cache
      emptyDir: {}
```

## Metrics

Prometheus metrics are exposed on `:8080/metrics`:

- `image_vuln_watcher_images_observed_total` - Total images observed
- `image_vuln_watcher_images_resolved_total` - Total images resolved to digest
- `image_vuln_watcher_image_resolution_errors_total` - Resolution failures
- `image_vuln_watcher_scans_total` - Total scans performed
- `image_vuln_watcher_scan_errors_total` - Scan failures
- `image_vuln_watcher_scan_duration_seconds` - Scan duration histogram
- `image_vuln_watcher_events_published_total` - Events published
- `image_vuln_watcher_event_publish_errors_total` - Publishing failures
- `image_vuln_watcher_dedupe_hits_total` - Deduplicated events

## Debugging Kubernetes Events

When running with `--publish-mode=events` or `--publish-mode=both`, the reporter creates native Kubernetes `Warning` Events on the affected workload. You can inspect these with `kubectl`:

```bash
# List all VulnerabilityScan events across all namespaces
kubectl get events -A --field-selector reason=VulnerabilityScan

# Filter to a specific namespace
kubectl get events -n <namespace> --field-selector reason=VulnerabilityScan

# Watch events in real time
kubectl get events -A --field-selector reason=VulnerabilityScan -w

# Show full event details for a specific workload
kubectl describe deployment/<name> -n <namespace> | grep -A5 VulnerabilityScan

# Filter by the reporting component
kubectl get events -A \
  --field-selector reportingComponent=komodor-security-reporter
```

Events use `reason=VulnerabilityScan` and `type=Warning` (or `Normal` for clean scans). The `MESSAGE` column contains the vulnerability summary, e.g.:

```plain
summary="critical=3 high=21 medium=16 low=1 total=49" scanner=trivy image=... findings=49 (critical=3 high=21 medium=16 low=1)
```

> **Note:** For human-readable local output, add `--log-format=text` to the reporter flags.

## Logging

Structured logging uses JSON output with contextual fields:

```json
{"level":"info","msg":"loaded configuration","cluster":"prod-eks-01","time":"2024-01-15T10:30:45Z"}
{"level":"warn","msg":"failed to resolve image digest","image":"ghcr.io/acme/app:1.0","error":"404 not found"}
```

Log levels: `debug`, `info` (default), `warn`, `error`

## Observability

### Health Checks

`GET /healthz` - Returns 200 OK if service is healthy

### Metrics

`GET /metrics` - Prometheus-format metrics

### Logs

All events are structured with fields:

- `cluster` - Cluster name
- `namespace` - Workload namespace
- `workloadKind` - Kind of workload (Deployment, etc)
- `workloadName` - Workload name
- `container` - Container name
- `image` - Image reference
- `digest` - Image digest
- `scanner` - Scanner name

## Release

### Build Release Locally

```bash
# Build snapshot (development)
make release-snapshot

# Create a release (requires git tag)
# 1. Tag the release: git tag v0.1.0
# 2. Run release:
make release
```

The release process:

1. Builds binaries for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64
2. Creates archives and checksums
3. Builds and pushes Docker images (requires Docker credentials)
4. Creates GitHub release with binaries
5. Generates changelog from commits

### Docker Images

Images are published to: `ghcr.io/davidcollom/komodor-security-reporter`

Tags:

- `vX.Y.Z` - Specific release
- `latest` - Latest release

## Configuration Reference

See [docs/example-config.yaml](docs/example-config.yaml) for full configuration options.

## Architecture Decision Records

See [docs/rfc.md](docs/rfc.md#decision-record) for design decisions:

- No CRDs in v1
- No Kubernetes Secret read RBAC
- No impersonation
- No host-level access

## Contributing

1. Ensure tests pass: `make test`
2. Format code: `make fmt`
3. Run linters: `make lint`
4. Create a pull request

## License

Apache License 2.0

## Support

For issues, questions, or suggestions, please open a GitHub issue.
