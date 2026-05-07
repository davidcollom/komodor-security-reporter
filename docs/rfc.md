# RFC: Komodor Image Vulnerability Watcher

## Status

Draft

## Authors

* David Collom

## Summary

This RFC proposes a Kubernetes-native watcher that detects container images used by workloads in a cluster, resolves those images to immutable digests where possible, scans or queries vulnerability information using pluggable scanner drivers, normalises the results, and publishes actionable security events to Komodor.

The watcher is designed to be deployed into an individual Kubernetes cluster and configured using standard Kubernetes primitives such as ConfigMaps, Secrets, ServiceAccounts, and Helm values. It intentionally avoids CRDs for the initial implementation.

A key goal is to provide a strong and reviewable security model suitable for platform and security teams.

> The watcher must never require hostPath mounts, runtime sockets, or privileged container access.

## Motivation

Kubernetes clusters commonly run workloads built from container images stored in private registries. Vulnerability scanners such as Snyk, Wiz, Trivy, and others may already identify risks in those images, but the findings are often disconnected from the operational context of the running workload.

Komodor provides a useful operational event timeline. Publishing image vulnerability findings into Komodor allows teams to correlate image risk with deployments, incidents, rollouts, and service health.

The goal is not to build another vulnerability scanner. The goal is to build a secure, low-noise bridge between running Kubernetes workloads, scanner findings, and Komodor events.

## Goals

* Watch Kubernetes workloads in a single cluster.
* Extract container image references from supported workload types.
* Resolve mutable image tags to immutable digests where possible.
* Use scanner drivers to scan or query vulnerability findings.
* Support scanner implementations backed by CLIs or APIs.
* Require structured scanner output such as JSON or YAML.
* Normalise scanner-specific results into a common internal model.
* Publish meaningful vulnerability events to Komodor.
* Deduplicate scan results to avoid noisy repeat events.
* Use ConfigMaps and Secrets for configuration and credentials.
* Avoid CRDs for the initial implementation.
* Avoid Kubernetes Secret read RBAC.
* Avoid impersonation.
* Avoid workload mutation.
* Avoid admission webhooks.
* Avoid host-level access.

## Non-goals

* Building a new vulnerability scanner.
* Replacing Snyk, Wiz, Trivy, or other scanner platforms.
* Mutating Kubernetes workloads.
* Blocking deployments.
* Acting as an admission controller.
* Reading application image pull secrets from namespaces.
* Impersonating workload ServiceAccounts.
* Mounting Docker, containerd, CRI-O, or Kubernetes node runtime sockets.
* Mounting node-local image stores.
* Requiring privileged containers.
* Requiring hostPath mounts.
* Introducing CRDs in the first version.

## Security Principles

The watcher should be acceptable to platform and security teams as a security tool with a constrained runtime model.

### Hard security requirement

The watcher must never require:

* `hostPath` mounts
* Docker socket access
* containerd socket access
* CRI-O socket access
* Kubernetes node filesystem access
* privileged containers
* host PID namespace access
* host network namespace access
* host IPC namespace access
* runtime socket access of any kind

All image inspection must happen through one of the following safe paths:

* registry access using the watcher Pod's own runtime identity
* scanner APIs
* scanner processes running inside the watcher Pod
* structured scanner output returned from a non-privileged process

### Kubernetes API permissions

The watcher should only require read-only access to workload metadata.

It must not require Kubernetes API permissions to:

* read Secrets
* impersonate users or ServiceAccounts
* create Pods
* update workloads
* delete workloads
* exec into Pods
* read Pod logs
* create admission webhooks
* mutate cluster state outside of its own optional state storage

### Registry credentials

The watcher should rely on the ServiceAccount and Pod context it runs under.

Registry access should be configured using standard Kubernetes mechanisms, for example:

* ServiceAccount `imagePullSecrets`
* externally managed Secrets using ESO
* Kyverno or OPA/Gatekeeper policies that inject or validate image pull configuration
* cloud-native workload identity where scanner tooling supports it

The watcher should not discover or read application `imagePullSecrets`.

The watcher should not require Kubernetes Secret read RBAC.

### Scanner driver security contract

A scanner driver is acceptable only if it can operate without requiring:

* host mounts
* runtime sockets
* privileged mode
* Kubernetes Secret API access
* workload impersonation
* node-local image cache access

Scanner CLI drivers must:

* execute a known binary path
* pass arguments directly without shell interpolation
* enforce a context timeout
* cap stdout and stderr size
* require JSON, YAML, or another deterministic structured output format
* parse scanner output into the internal `ScanResult` model
* never require privileged container access

## High-level Architecture

```text
Kubernetes Workload Watcher
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

## Components

### Kubernetes Workload Watcher

The watcher observes supported workload resources and detects image references from their Pod templates.

Initial supported workload kinds:

* Deployment
* StatefulSet
* DaemonSet
* Job
* CronJob

Possible future workload kinds:

* Argo Rollout
* Knative Service
* OpenShift DeploymentConfig

### Image Extractor

The image extractor reads images from:

* `containers`
* `initContainers`
* optionally `ephemeralContainers`, if useful later

It should retain workload context:

* cluster name
* namespace
* workload kind
* workload name
* container name
* image string
* labels
* annotations

### Digest Resolver

The digest resolver attempts to resolve image tags to immutable digests.

Example:

```text
ghcr.io/acme/checkout-api:1.4.2
```

becomes:

```text
ghcr.io/acme/checkout-api@sha256:abc123...
```

Digest-first tracking reduces noise and avoids treating mutable tags as stable identifiers.

The resolver should use `go-containerregistry` and Kubernetes-aware keychain behaviour where possible.

The resolver must use the watcher Pod's own runtime identity and must not read workload image pull Secrets.

### Scanner Registry

The scanner registry loads configured scanner drivers and invokes them for resolved images.

The controller-facing scanner interface should be intentionally simple.

```go
type Scanner interface {
	Name() string
	Scan(ctx context.Context, image ImageRef) (*ScanResult, error)
}
```

The controller should not need to know whether a scanner uses:

* a vendor API
* a CLI process
* existing scanner findings
* registry-sourced image analysis
* an uploaded artefact

That is the responsibility of the scanner driver.

### Scanner Drivers

Initial candidate drivers:

* Trivy
* Snyk
* Wiz

The first implementation should prioritise one scanner driver to validate the abstraction.

Trivy is a strong candidate for early development because it can provide a self-contained registry-sourced scan flow suitable for local development and demos.

Snyk and Wiz drivers may initially be implemented as lookup or API-backed drivers, depending on the available API capabilities and organisational scanner configuration.

### Finding Normaliser

Scanner-specific results should be converted into a shared model.

Example internal structures:

```go
type ImageRef struct {
	Original   string
	Registry   string
	Repository string
	Tag        string
	Digest     string
	Resolved   string
}

type ScanResult struct {
	Scanner   string
	Image     ImageRef
	ScannedAt time.Time
	Summary   VulnerabilitySummary
	Findings  []Finding
	ReportURL string
	SBOMURL   string
}

type VulnerabilitySummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

type Finding struct {
	ID          string
	CVE         string
	Package     string
	Installed   string
	Fixed       string
	Severity    Severity
	Title       string
	URL         string
	Exploitable bool
}
```

### Policy Evaluator

The policy evaluator decides whether a result should be published.

Example policy options:

* minimum severity
* publish only on first seen
* publish only on severity increase
* publish when new critical findings appear
* optionally publish clean scans
* include top N findings
* dedupe TTL

### Komodor Event Publisher

The publisher sends normalised vulnerability events to Komodor.

Events should be scoped to the affected workload or service where possible.

Example event details:

```json
{
  "scanner": "trivy",
  "image": "ghcr.io/acme/checkout-api@sha256:abc123",
  "container": "checkout-api",
  "critical": "2",
  "high": "7",
  "medium": "14",
  "topFindings": "CVE-2026-1234,CVE-2025-9876,CVE-2024-1111",
  "digest": "sha256:abc123",
  "policy": "minimumSeverity=high"
}
```

### State and Deduplication

The watcher should avoid repeatedly publishing the same vulnerability event.

For v1, state should be stored without a CRD.

Possible options:

* ConfigMap state
* local file state with a mounted volume
* SQLite with a PVC

For the simplest Kubernetes-native MVP, use ConfigMap-backed state.

State should include:

* image digest
* scanner name
* workload reference
* last scanned timestamp
* last published timestamp
* vulnerability summary
* fingerprint

The fingerprint should be derived from stable result data such as:

* scanner name
* image digest
* severity counts
* top finding IDs
* relevant fix availability information

## Configuration

Configuration should be supplied through a ConfigMap.

Example:

```yaml
clusterName: prod-eks-01

namespaces:
  include:
    - production
    - platform
  exclude:
    - kube-system
    - cert-manager

workloads:
  kinds:
    - Deployment
    - StatefulSet
    - DaemonSet
    - Job
    - CronJob

registry:
  resolveDigest: true

scanners:
  - name: trivy
    type: trivy
    enabled: true
    command:
      binary: /usr/local/bin/trivy
      timeout: 5m

  - name: snyk
    type: snyk
    enabled: false
    command:
      binary: /usr/local/bin/snyk
      timeout: 5m

publishing:
  minimumSeverity: high
  includeTopFindings: 5
  publishCleanScans: false
  dedupeTTL: 24h
```

## Credentials

Credentials should be provided through normal Pod runtime mechanisms.

Examples:

* environment variables sourced from Secrets
* mounted files sourced from Secrets
* projected ServiceAccount tokens
* cloud workload identity
* scanner-specific configuration files

The watcher application should not need Kubernetes API permissions to read Secrets.

Example environment variables:

```yaml
env:
  - name: KOMODOR_API_KEY
    valueFrom:
      secretKeyRef:
        name: komodor-security-reporter-komodor
        key: api-key

  - name: SNYK_TOKEN
    valueFrom:
      secretKeyRef:
        name: komodor-security-reporter-snyk
        key: token
```

## RBAC

The watcher should use minimal read-only RBAC.

Example:

```yaml
rules:
  - apiGroups: [""]
    resources:
      - namespaces
    verbs:
      - get
      - list
      - watch

  - apiGroups: ["apps"]
    resources:
      - deployments
      - statefulsets
      - daemonsets
      - replicasets
    verbs:
      - get
      - list
      - watch

  - apiGroups: ["batch"]
    resources:
      - jobs
      - cronjobs
    verbs:
      - get
      - list
      - watch
```

The watcher should not require:

```yaml
resources:
  - secrets
```

The watcher should not require:

```yaml
verbs:
  - impersonate
```

## Pod Security Context

The watcher should run with a restrictive security context.

Example:

```yaml
securityContext:
  runAsNonRoot: true
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
```

If scanner CLIs require cache directories, those should be backed by `emptyDir` or a PVC.

Example:

```yaml
volumeMounts:
  - name: tmp
    mountPath: /tmp
  - name: scanner-cache
    mountPath: /var/cache/komodor-security-reporter

volumes:
  - name: tmp
    emptyDir: {}
  - name: scanner-cache
    emptyDir: {}
```

No hostPath volumes should be used.

## Scanner Process Execution

Scanner CLI drivers may execute scanner binaries when the scanner provides structured output.

Scanner commands must be executed without shell interpolation.

Acceptable:

```go
exec.CommandContext(ctx, "trivy", "image", "--format", "json", image.Resolved)
```

Not acceptable:

```go
exec.CommandContext(ctx, "sh", "-c", "trivy image " + image.Resolved)
```

Scanner execution should include:

* timeout enforcement
* stdout size limit
* stderr size limit
* structured output validation
* clear error wrapping
* scanner-specific parser tests

## Event Publishing Behaviour

The watcher should publish only meaningful events.

Suggested defaults:

```yaml
publishing:
  minimumSeverity: high
  publishCleanScans: false
  includeTopFindings: 5
  dedupeTTL: 24h
```

Events should be published when:

* an image is scanned for the first time and findings exceed policy
* severity increases
* new critical findings appear
* the result fingerprint changes meaningfully

Events should not be published when:

* the same result has already been published recently
* findings are below configured policy
* only noisy scanner metadata changes

## Example Event Summary

```text
2 critical vulnerabilities found in checkout-api
```

## Example Event Details

```json
{
  "cluster": "prod-eks-01",
  "namespace": "production",
  "workloadKind": "Deployment",
  "workloadName": "checkout-api",
  "container": "checkout-api",
  "scanner": "trivy",
  "image": "ghcr.io/acme/checkout-api@sha256:abc123",
  "critical": "2",
  "high": "7",
  "medium": "14",
  "low": "3",
  "topFindings": "CVE-2026-1234,CVE-2025-9876,CVE-2024-1111",
  "reportURL": "https://scanner.example/report/123",
  "fingerprint": "sha256:deadbeef"
}
```

## Deployment Model

The watcher should be deployed using Helm.

Initial chart resources:

* ServiceAccount
* ClusterRole or Role
* ClusterRoleBinding or RoleBinding
* ConfigMap
* Deployment
* optional Secret templates for development only

Production environments should normally manage Secrets externally.

Example Helm values:

```yaml
serviceAccount:
  create: true
  name: komodor-security-reporter
  imagePullSecrets:
    - name: registry-readonly-auth

rbac:
  create: true
  scope: cluster

config:
  clusterName: prod-eks-01
  namespaces:
    include:
      - production
      - platform
    exclude:
      - kube-system
      - cert-manager

komodor:
  apiKeySecret:
    name: komodor-security-reporter-komodor
    key: api-key

scanner:
  trivy:
    enabled: true
    cache:
      emptyDir: true
```

## Failure Handling

The watcher should handle failures gracefully.

Examples:

* registry digest resolution failure
* scanner unavailable
* scanner timeout
* scanner output parse failure
* Komodor API failure
* state persistence failure

Failures should be logged with enough context to debug:

* scanner name
* image reference
* namespace
* workload kind
* workload name
* container name

Retries should use bounded exponential backoff.

The watcher should avoid publishing scanner failure events by default unless explicitly configured, to avoid noise.

## Observability

The watcher should expose Prometheus metrics.

Suggested metrics:

```text
image_vuln_watcher_images_observed_total
image_vuln_watcher_images_resolved_total
image_vuln_watcher_image_resolution_errors_total
image_vuln_watcher_scans_total
image_vuln_watcher_scan_errors_total
image_vuln_watcher_scan_duration_seconds
image_vuln_watcher_events_published_total
image_vuln_watcher_event_publish_errors_total
image_vuln_watcher_dedupe_hits_total
```

Structured logs should include:

* cluster
* namespace
* workload kind
* workload name
* container
* image
* digest
* scanner
* correlation ID where applicable

## Implementation Plan

### Phase 1: Core watcher

* Create Go project structure.
* Add Kubernetes workload watchers.
* Extract images from workload Pod templates.
* Add namespace include/exclude filtering.
* Add basic config loading from ConfigMap-mounted YAML.

### Phase 2: Digest resolution

* Add `go-containerregistry`.
* Resolve image tags to digests.
* Use watcher runtime identity/keychain where possible.
* Add tests for image reference parsing and digest resolution logic.

### Phase 3: Scanner abstraction

* Add `Scanner` interface.
* Add normalised `ScanResult` model.
* Add scanner registry.
* Add command runner abstraction for CLI-backed scanners.
* Add stdout/stderr limits and timeout handling.

### Phase 4: First scanner driver

* Implement Trivy driver.
* Parse Trivy JSON output.
* Add parser fixtures.
* Add table-driven tests.

### Phase 5: Komodor publisher

* Implement Komodor event client.
* Add event mapping.
* Add severity mapping.
* Add retry/backoff.
* Add unit tests around event payloads.

### Phase 6: State and dedupe

* Add fingerprinting.
* Add ConfigMap-backed state store.
* Add dedupe policy.
* Add tests for publish/no-publish decisions.

### Phase 7: Helm chart

* Add ServiceAccount.
* Add minimal RBAC.
* Add Deployment.
* Add ConfigMap.
* Add restrictive security context.
* Add optional cache volumes.
* Add README security model.

## Open Questions

* Should state initially be ConfigMap-backed or file-backed with an `emptyDir`/PVC?
* Should the first scanner driver be Trivy, Snyk, or Wiz?
* Should scanner failures optionally publish Komodor warning events?
* How should Komodor service mapping be derived from Kubernetes workload metadata?
* Should Rollouts be included in v1 or deferred?
* Should scan concurrency be global, per namespace, or per scanner?
* Should clean scans ever be published by default?
* How long should dedupe state be retained?

## Decision Record

### Decision: No CRDs in v1

Use ConfigMaps, Secrets, ServiceAccounts, and Helm values for the first version.

Rationale:

* simpler deployment
* lower operational complexity
* easier to review
* sufficient for single-cluster deployment

### Decision: No Kubernetes Secret read RBAC

The watcher should not request API permissions to read Secrets.

Rationale:

* stronger security posture
* easier security review
* avoids reading application Secrets
* aligns with platform-managed credential models

### Decision: No impersonation

The watcher should not impersonate workload ServiceAccounts.

Rationale:

* impersonation can be difficult to reason about
* broad impersonation increases review complexity
* workload image pull access does not necessarily imply Secret read API access

### Decision: No host access

The watcher must never require hostPath mounts, runtime sockets, or privileged container access.

Rationale:

* preserves strong security posture
* avoids node-level blast radius
* avoids container runtime coupling
* keeps scanner drivers constrained and reviewable

### Decision: No ScannerMode in the public scanner abstraction

Scanner implementation details should remain internal to each scanner driver.

Rationale:

* keeps the controller simple
* avoids leaking vendor-specific behaviour
* keeps the scanner contract focused on input and normalised output

## Proposed Repository Name

Options:

* `komodor-image-vulnerability-watcher`
* `kube-image-risk-publisher`
* `image-vuln-event-watcher`
* `komodor-image-risk-watcher`

Recommended initial name:

```text
komodor-image-vulnerability-watcher
```

## Appendix: Suggested Go Package Layout

```text
cmd/komodor-security-reporter/
  main.go

internal/config/
  config.go
  loader.go

internal/controller/
  workload_controller.go
  image_extractor.go

internal/registry/
  resolver.go
  image_ref.go

internal/scanners/
  scanner.go
  result.go
  severity.go

internal/scanners/command/
  runner.go
  limited_buffer.go

internal/scanners/trivy/
  scanner.go
  parser.go
  parser_test.go
  testdata/

internal/komodor/
  client.go
  publisher.go
  event.go

internal/policy/
  evaluator.go
  fingerprint.go

internal/state/
  store.go
  configmap_store.go

internal/metrics/
  metrics.go
```

## Appendix: Example Scanner Interface

```go
package scanners

import (
	"context"
	"time"
)

type Scanner interface {
	Name() string
	Scan(ctx context.Context, image ImageRef) (*ScanResult, error)
}

type ImageRef struct {
	Original   string
	Registry   string
	Repository string
	Tag        string
	Digest     string
	Resolved   string
}

type ScanResult struct {
	Scanner   string
	Image     ImageRef
	ScannedAt time.Time
	Summary   VulnerabilitySummary
	Findings  []Finding
	ReportURL string
	SBOMURL   string
}

type VulnerabilitySummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityUnknown  Severity = "unknown"
)

type Finding struct {
	ID          string
	CVE         string
	Package     string
	Installed   string
	Fixed       string
	Severity    Severity
	Title       string
	URL         string
	Exploitable bool
}
```

## Appendix: Example Safe Command Runner

```go
package command

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
)

type Runner struct {
	StdoutLimitBytes int64
	StderrLimitBytes int64
}

func (r Runner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd.Stdout = &limitedWriter{
		writer: &stdout,
		limit:  r.StdoutLimitBytes,
	}
	cmd.Stderr = &limitedWriter{
		writer: &stderr,
		limit:  r.StderrLimitBytes,
	}

	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("run command %q: %w", name, err)
	}

	return stdout.Bytes(), stderr.Bytes(), nil
}

type limitedWriter struct {
	writer io.Writer
	limit  int64
	seen   int64
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	remaining := w.limit - w.seen
	if remaining <= 0 {
		return len(p), nil
	}

	if int64(len(p)) > remaining {
		p = p[:remaining]
	}

	n, err := w.writer.Write(p)
	w.seen += int64(n)

	return len(p), err
}
```
