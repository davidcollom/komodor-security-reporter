# Development Guide

This guide explains the project structure, development workflows, and best practices for contributing to the Komodor Image Vulnerability Watcher.

## Project Structure

```plain
cmd/
├── komodor-security-reporter/          # Application entry point
│   └── main.go                  # CLI and initialization

internal/
├── config/                      # Configuration loading and validation
│   ├── config.go                # Configuration types
│   ├── loader.go                # YAML parsing
│   ├── config_test.go           # Config validation tests
│   └── loader_test.go           # Loader tests

├── controller/                  # Kubernetes workload watching
│   ├── image_extractor.go       # Extract images from Pod specs
│   └── image_extractor_test.go  # Image extraction tests

├── komodor/                     # Komodor integration
│   ├── client.go                # HTTP API client
│   ├── publisher.go             # Event conversion and publishing
│   └── publisher_test.go        # Publisher tests

├── metrics/                     # Prometheus metrics
│   └── metrics.go               # Metric definitions

├── policy/                      # Policy evaluation and deduplication
│   ├── evaluator.go             # Fingerprinting and publish decisions
│   └── evaluator_test.go        # Policy tests

├── registry/                    # Container image registry operations
│   ├── image_ref.go             # Image reference parsing
│   ├── image_ref_test.go        # Parsing tests
│   └── resolver.go              # Digest resolution

├── scanners/                    # Scanner abstraction
│   ├── scanner.go               # Scanner interface and types
│   ├── severity.go              # Severity parsing
│   ├── severity_test.go         # Severity tests
│   │
│   ├── command/                 # CLI command execution
│   │   ├── runner.go            # Safe command runner
│   │   └── runner_test.go       # Command runner tests
│   │
│   └── trivy/                   # Trivy scanner driver
│       ├── scanner.go           # Trivy implementation
│       └── scanner_test.go      # Trivy tests

├── state/                       # State persistence
│   └── configmap_store.go       # ConfigMap-backed state store

└── version/                     # Version information
    └── version.go               # Version variables

docs/
├── rfc.md                       # Architecture and design RFC
├── example-config.yaml          # Example configuration
└── DEVELOPMENT.md               # This file

helm/
└── komodor-security-reporter/    # Helm chart
    ├── Chart.yaml
    ├── values.yaml
    └── templates/

.github/
└── workflows/                   # GitHub Actions
    ├── tests.yml                # Test and lint workflow
    └── release.yml              # Release workflow

Dockerfile                       # Container image build
Makefile                         # Development tasks
.golangci.yml                    # Linter configuration
.pre-commit-config.yaml          # Pre-commit hooks
.goreleaser.yml                  # Release configuration
```

## Development Workflow

### 1. Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/davidcollom/komodor-security-reporter.git
cd komodor-security-reporter

# Install development tools
make install-tools

# Install pre-commit hooks (optional)
make pre-commit-install

# Verify setup
go version
golangci-lint --version
```

### 2. Running Tests Locally

```bash
# Run all tests
make test

# Run with coverage
make coverage

# Run short tests only (no integration tests)
make test-short

# Run specific test
go test -run TestName ./internal/package

# Run with verbose output
go test -v ./...
```

### 3. Code Quality

```bash
# Format code
make fmt

# Run linters
make lint

# Run vet
make vet

# Run all checks
make check
```

### 4. Building Locally

```bash
# Build binary
make build

# Run built binary
./bin/komodor-security-reporter -config docs/example-config.yaml

# Build Docker images via GoReleaser snapshot (no push)
make docker-build

# Equivalent direct command
goreleaser release --snapshot --clean --skip=publish
```

Notes:

- Docker image builds are driven by GoReleaser configuration in .goreleaser.yml.
- The Dockerfile is runtime-focused and expects the binary to be provided by GoReleaser.

## Key Components

### Scanner Interface

All scanners implement the `Scanner` interface:

```go
type Scanner interface {
    Name() string
    Scan(ctx context.Context, image ImageRef) (*ScanResult, error)
}
```

Implementations convert vendor-specific output to our normalized `ScanResult` type.

### Configuration

Configuration is loaded from YAML files structured as:

```yaml
clusterName: prod-eks-01
namespaces:
  include: [production]
  exclude: [kube-system]
workloads:
  kinds: [Deployment, StatefulSet]
scanners:
  scanners:
    - name: trivy
      type: trivy
      enabled: true
      command:
        binary: /usr/bin/trivy
        timeout: 5m
```

### Image Resolution

Images are parsed and resolved to digests:

```plain
ubuntu:22.04
  ↓
docker.io/library/ubuntu@sha256:abc123...
```

The `registry.ImageRef` type handles parsing and resolution state.

### Deduplication

State is tracked using fingerprints:

```go
fingerprint := policy.Fingerprint(result)
// fingerprint = "sha256:abc123..."
```

The same result won't be published twice within the dedup TTL.

## Testing Strategy

### Unit Tests

All packages have unit tests covering:

- Success and failure paths
- Edge cases (empty inputs, invalid data)
- Boundary conditions

Tests use table-driven approaches where appropriate:

```go
tests := []struct {
    name      string
    input     string
    expected  string
    wantError bool
}{
    {"case 1", "input1", "expected1", false},
    {"case 2", "input2", "expected2", true},
}

for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        // test body
    })
}
```

### Mocking Strategy

- Prefer fake implementations over mocks for Kubernetes clients
- Use testable dependency injection
- Mock only external I/O (HTTP, file systems)

Example:

```go
// Fake instead of mock
type fakeScanner struct {
    results []*ScanResult
}

func (f *fakeScanner) Scan(ctx context.Context, img ImageRef) (*ScanResult, error) {
    // Return predefined results
}
```

### Integration Tests

- Marked with `if testing.Short() { t.Skip(...) }`
- Run only when needed (full test suite)
- Require external tools (e.g., trivy)

## Code Style

### General Rules

- Use meaningful variable and function names
- Keep functions focused and reasonably short (< 50 lines)
- Comment the "why", not the obvious "what"
- Use `logrus` for logging (never `fmt.Print*`)

### Error Handling

```go
// Good: wrap with context
if err != nil {
    return nil, fmt.Errorf("load config: %w", err)
}

// Good: structured logging
log.WithError(err).WithField("image", img).Warn("failed to scan")

// Avoid: losing context
if err != nil {
    return nil, err
}
```

### Package Organization

- Keep exported surface area minimal
- Use `internal/` for non-public packages
- Group related functionality together
- Place tests in `*_test.go` files in the same package

## Adding a New Scanner

### Step 1: Create Scanner Package

```bash
mkdir -p internal/scanners/newscanner
```

### Step 2: Implement Scanner Interface

```go
// internal/scanners/newscanner/scanner.go
package newscanner

import (
    "context"
    "github.com/davidcollom/komodor-security-reporter/internal/scanners"
)

type Scanner struct {
    // fields
}

func (s *Scanner) Name() string {
    return "newscanner"
}

func (s *Scanner) Scan(ctx context.Context, image scanners.ImageRef) (*scanners.ScanResult, error) {
    // Implementation
}
```

### Step 3: Add Tests

```go
// internal/scanners/newscanner/scanner_test.go
func TestScan(t *testing.T) {
    // Tests
}
```

### Step 4: Register in Main

```go
// cmd/komodor-security-reporter/main.go
case "newscanner":
    registry[scannerCfg.Name] = newscanner.NewScanner(...)
```

## Performance Considerations

### Image Resolution

- Digest resolution requires registry access (can be slow)
- Consider caching resolved digests per tag
- Implement configurable timeout

### Scanning

- Scans can take minutes for large images
- Use context timeouts to prevent hangs
- Limit concurrent scans to avoid resource exhaustion

### State Storage

- ConfigMap size is limited (1MB)
- May need to migrate to PVC for larger states
- Consider pruning old entries

## Common Tasks

### Viewing Test Coverage

```bash
make coverage
open coverage.html
```

### Running Pre-commit Checks

```bash
make pre-commit-install
pre-commit run --all-files
```

### Building Release Snapshot

```bash
make release-snapshot
ls -la dist/
```

This maps to:

```bash
goreleaser build --snapshot --clean
```

### Generating Docs

```bash
# Add godoc comments to all public symbols
# Generate static docs if needed
```

## Debugging

### Enable Debug Logging

```bash
./bin/komodor-security-reporter -config config.yaml -log-level debug
```

### Run with Delve Debugger

```bash
go install github.com/go-delve/delve/cmd/dlv@latest
dlv debug ./cmd/komodor-security-reporter -- -config config.yaml
```

### Inspect Kubernetes Resources

```bash
# Check deployment
kubectl get deployment -n security komodor-security-reporter

# View logs
kubectl logs -n security deployment/komodor-security-reporter -f

# Port-forward metrics
kubectl port-forward -n security svc/komodor-security-reporter 8080:8080

# Edit ConfigMap
kubectl edit cm -n security komodor-security-reporter
```

## Contributing

### Before Submitting PR

1. Run full test suite: `make check`
2. Ensure coverage for new code
3. Update documentation if needed
4. Follow code style guidelines
5. Test locally with example config

### PR Review Process

- Automated tests must pass
- Linters must pass
- Code review feedback must be addressed
- At least one approval before merge

## References

- [RFC](./rfc.md) - Architecture and design decisions
- [README](./README.md) - User documentation
- [Go Best Practices](https://golang.org/doc/effective_go)
