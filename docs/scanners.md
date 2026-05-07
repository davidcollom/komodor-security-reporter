# Container Vulnerability Scanners

This alerter supports multiple container image vulnerability scanning backends. Each scanner has different strengths and trade-offs.

## Supported Scanners

### Trivy (Recommended for most uses)

**Status**: ✅ Enabled by default

**What it is**: Native Go application from Aqua Security. Comprehensive vulnerability scanner supporting:

- OS package vulnerabilities
- Application dependency vulnerabilities (multiple languages)
- Infrastructure-as-Code (IaC) misconfigurations
- Secrets detection
- SBOM generation

**Binary**: Native Go application; no separate binary installation required.

- Omit `command.binary` to use system `$PATH` (recommended)
- Or set `command.binary: /path/to/trivy` to override

**Strengths**:

- Broadest feature set of any scanner
- Very fast (native Go)
- Highly maintained (Aqua Security, 34.9k GitHub stars)
- Excellent vulnerability database coverage
- Supports most container registries

**Performance**: ~2-5s per image scan (varies with image size and layer count)

**Configuration**:

```yaml
- name: trivy
  type: trivy
  enabled: true
  command:
    timeout: 5m
```

---

### Snyk Container

**Status**: ⚠️ Available, requires authentication

**What it is**: Commercial vulnerability scanner from Snyk with developer-friendly approach:

- Container image scanning
- Fix recommendations (for supported languages)
- License compliance scanning
- Integrated vulnerability prioritization

**Binary**: Requires `snyk` CLI to be installed.

```bash
brew install snyk  # macOS
# or see https://docs.snyk.io/snyk-cli/install-the-snyk-cli
```

**Requirements**:

- Requires Snyk authentication (API token)
- CLI must be installed separately

**Strengths**:

- Excellent fix recommendations
- Good for DevSecOps workflows
- Integrates with IDEs and Git platforms
- Prioritises vulnerabilities using real-world data

**Performance**: ~3-8s per image (slower than Trivy due to API calls)

**Configuration**:

```yaml
- name: snyk
  type: snyk
  enabled: false
  command:
    timeout: 5m
```

---

### Clair

**Status**: ⚠️ Available, requires Clair CLI

**What it is**: Open-source container vulnerability analysis from the Quay ecosystem.

**Binary**: Requires `clairctl` binary to be installed.

**Requirements**:

- Requires access to a configured Clair instance
- CLI must be installed separately

**Strengths**:

- Open-source scanner ecosystem
- Good fit for organizations already running Clair
- Structured JSON output suitable for normalization

**Performance**: Depends on Clair deployment and registry latency.

**Configuration**:

```yaml
- name: clair
  type: clair
  enabled: false
  command:
    timeout: 5m
```

---

### Wiz Container Scanner

**Status**: ⚠️ Available, enterprise-focused

**What it is**: Enterprise cloud security platform with container image scanning:

- Container image vulnerability scanning
- Graph-based risk analysis
- Cloud workload context
- Includes secrets and IaC scanning

**Binary**: Requires `wizcli` binary to be installed.

```bash
# Installation: https://docs.wiz.io/wiz-docs/docs/wizcli
```

**Requirements**:

- Requires Wiz authentication
- CLI must be installed separately

**Strengths**:

- Enterprise-grade cloud security platform
- Context-aware risk prioritization
- Integrates with cloud environments
- Includes secrets scanning

**Performance**: ~5-15s per image (variable based on Wiz cloud API)

**Configuration**:

```yaml
- name: wiz
  type: wiz
  enabled: false
  command:
    timeout: 5m
```

---

## Comparison

| Feature | Trivy | Snyk | Wiz | Clair |
| ------- | ----- | ---- | --- | ----- |
| **Speed** | Very Fast | Medium | Medium | Medium |
| **Open Source** | ✅ Yes | ❌ Commercial | ❌ Commercial | ✅ Yes |
| **Cost** | Free | Freemium/Paid | Enterprise | Free |
| **Authentication** | None | Required | Required | Clair environment dependent |
| **Fix Recommendations** | Limited | ✅ Excellent | ⚠️ Basic | ⚠️ Basic |
| **IaC Scanning** | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No |
| **Secrets Detection** | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No |
| **Multi-Cloud** | ⚠️ Limited | ⚠️ Limited | ✅ Excellent | ⚠️ Limited |
| **Easy to Deploy** | ✅ Yes | ⚠️ Requires auth | ⚠️ Requires auth | ⚠️ Requires Clair setup |

---

## Recommended Configuration

### For Kubernetes clusters (default)

Use **Trivy** alone:

```yaml
scanners:
  concurrency: 4
  scanners:
    - name: trivy
      type: trivy
      enabled: true
      command:
        timeout: 5m
```

### For development teams using Snyk

Combine Trivy with Snyk for developer insights:

```yaml
scanners:
  concurrency: 4
  scanners:
    - name: trivy
      type: trivy
      enabled: true
      command:
        timeout: 5m
    - name: snyk
      type: snyk
      enabled: true
      command:
        timeout: 5m
```

### For enterprise cloud security

Use Wiz with Trivy as primary:

```yaml
scanners:
  concurrency: 4
  scanners:
    - name: trivy
      type: trivy
      enabled: true
    - name: wiz
      type: wiz
      enabled: true
      command:
        timeout: 10m  # Wiz may be slower
```

### For organizations using Clair

Use Trivy and Clair together:

```yaml
scanners:
  concurrency: 4
  scanners:
    - name: trivy
      type: trivy
      enabled: true
    - name: clair
      type: clair
      enabled: true
      command:
        timeout: 5m
```

---

## Alternative Open-Source Scanners (Future)

These scanners have Go libraries and could be added in the future:

- **Grype** (Anchore): Lightweight, vulnerability-focused scanner
- **Syft** (Anchore): SBOM generation (complements Grype)
- **Clair** (Red Hat): Registry-integrated scanner for Kubernetes

---

## Scanner Concurrency

All scanners run in parallel (bounded by `scanners.concurrency`):

```yaml
scanners:
  concurrency: 4  # Run up to 4 scanners in parallel per workload
```

With 3 scanners and concurrency=4:

- Each workload image is scanned by all 3 scanners simultaneously
- Maximum 4 parallel scan operations across all workloads
- Bottleneck is typically the slowest scanner (Snyk/Wiz)

---

## Troubleshooting

### "command not found: trivy"

Ensure Trivy is installed and on your `$PATH`:

```bash
which trivy          # Check if installed
trivy --version      # Check version
```

Or explicitly set the binary path in config:

```yaml
command:
  binary: /opt/homebrew/bin/trivy
```

### Snyk/Wiz scanner skipped

Ensure authentication is set up:

```bash
snyk auth  # For Snyk
wiz auth   # For Wiz
```

### Slow scans

Check scanner timeouts in config. Snyk and Wiz may be slower than Trivy due to API calls.

---

## Contributing New Scanners

To add a new scanner (e.g., Grype), implement the `scanners.Scanner` interface:

```go
type Scanner interface {
    Name() string
    Scan(ctx context.Context, image ImageRef) (*ScanResult, error)
}
```

See `internal/scanners/trivy/scanner.go` for an example implementation.
