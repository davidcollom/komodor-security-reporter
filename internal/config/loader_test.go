package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadFromFile(t *testing.T) {
	// Create a temporary config file
	content := []byte(`
clusterName: test-cluster
namespaces:
  include:
    - default
workloads:
  kinds:
    - Deployment
scanners:
  concurrency: 2
  scanners:
    - name: trivy
      type: trivy
      enabled: true
      command:
        binary: /usr/bin/trivy
komodor:
  baseURL: https://app.komodor.io
`)

	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	require.NoError(t, err)

	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write(content)
	require.NoError(t, err)
	tmpFile.Close()

	cfg, err := LoadFromFile(tmpFile.Name())

	require.NoError(t, err)
	require.Equal(t, "test-cluster", cfg.ClusterName)
	require.Equal(t, 1, len(cfg.Namespaces.Include))
	require.Equal(t, 1, len(cfg.Workloads.Kinds))
	require.Equal(t, 2, cfg.Scanners.Concurrency)
}

func TestLoadFromFileNotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/path/config.yaml")

	require.Error(t, err)
}

func TestLoadFromBytesParseError(t *testing.T) {
	_, err := LoadFromBytes([]byte("invalid: yaml: content: ["))

	require.Error(t, err)
}

func TestLoadFromBytesDefaultTimeouts(t *testing.T) {
	yaml := []byte(`
clusterName: test
workloads:
  kinds:
    - Deployment
scanners:
  scanners:
    - name: trivy
      type: trivy
      enabled: true
      command:
        binary: /usr/bin/trivy
komodor:
  baseURL: https://app.komodor.io
`)

	cfg, err := LoadFromBytes(yaml)

	require.NoError(t, err)
	require.Equal(t, 4, cfg.Scanners.Concurrency)
	require.Equal(t, 72*time.Hour, cfg.State.TTL)
	require.Equal(t, StateBackendConfigMap, NormalizeStateBackend(cfg.State.Backend))
	require.Equal(t, "default", cfg.State.Namespace)
	require.Equal(t, DefaultScannerRuntimeTimeout, cfg.Scanners.Runtime.Timeout)
	require.Equal(t, DefaultScannerRetryMaxAttempts, cfg.Scanners.Runtime.Retry.MaxAttempts)
	require.Equal(t, DefaultScannerRetryInitialBackoff, cfg.Scanners.Runtime.Retry.InitialBackoff)
	require.Equal(t, DefaultScannerRetryMaxBackoff, cfg.Scanners.Runtime.Retry.MaxBackoff)
	require.Equal(t, DefaultScannerRetryBackoffMultiplier, cfg.Scanners.Runtime.Retry.BackoffMultiplier)
	require.Equal(t, DefaultScannerCircuitFailureThreshold, cfg.Scanners.Runtime.CircuitBreaker.FailureThreshold)
	require.Equal(t, DefaultScannerCircuitOpenDuration, cfg.Scanners.Runtime.CircuitBreaker.OpenDuration)
	require.Equal(t, DefaultScannerCircuitHalfOpenMaxRequests, cfg.Scanners.Runtime.CircuitBreaker.HalfOpenMaxRequests)
}

func TestLoadFromBytesInvalidScannerRuntime(t *testing.T) {
	yaml := []byte(`
clusterName: test
workloads:
  kinds:
    - Deployment
scanners:
  runtime:
    timeout: invalid
  scanners:
    - name: trivy
      type: trivy
      enabled: true
komodor:
  baseURL: https://app.komodor.io
`)

	_, err := LoadFromBytes(yaml)

	require.Error(t, err)
	require.Contains(t, err.Error(), "parse scanner runtime config")
}

func TestLoadFromBytesParsesStateBackend(t *testing.T) {
	yaml := []byte(`
clusterName: test
workloads:
  kinds:
    - Deployment
state:
  backend: memory
  ttl: 48h
  namespace: reporter-ns
scanners:
  scanners:
    - name: trivy
      type: trivy
      enabled: true
komodor:
  baseURL: https://app.komodor.io
`)

	cfg, err := LoadFromBytes(yaml)

	require.NoError(t, err)
	require.Equal(t, StateBackendMemory, NormalizeStateBackend(cfg.State.Backend))
	require.Equal(t, 48*time.Hour, cfg.State.TTL)
	require.Equal(t, "reporter-ns", cfg.State.Namespace)
}

func TestLoadFromBytesStateTTL(t *testing.T) {
	yaml := []byte(`
clusterName: test
workloads:
  kinds:
    - Deployment
state:
  ttl: 96h
scanners:
  scanners:
    - name: trivy
      type: trivy
      enabled: true
      command:
        timeout: 10s
komodor:
  baseURL: https://app.komodor.io
`)

	cfg, err := LoadFromBytes(yaml)

	require.NoError(t, err)
	require.Equal(t, 96*time.Hour, cfg.State.TTL)
}

func TestLoadFromBytesInvalidStateTTL(t *testing.T) {
	yaml := []byte(`
clusterName: test
workloads:
  kinds:
    - Deployment
state:
  ttl: not-a-duration
scanners:
  scanners:
    - name: trivy
      type: trivy
      enabled: true
komodor:
  baseURL: https://app.komodor.io
`)

	_, err := LoadFromBytes(yaml)

	require.Error(t, err)
	require.Contains(t, err.Error(), "parse state ttl")
}

func TestLoadFromBytesCustomTimeout(t *testing.T) {
	yaml := []byte(`
clusterName: test
workloads:
  kinds:
    - Deployment
scanners:
  scanners:
    - name: trivy
      type: trivy
      enabled: true
      command:
        binary: /usr/bin/trivy
        timeout: 10s
komodor:
  baseURL: https://app.komodor.io
`)

	cfg, err := LoadFromBytes(yaml)

	require.NoError(t, err)
	require.Equal(t, map[string]any{"binary": "/usr/bin/trivy", "timeout": "10s"}, cfg.Scanners.Scanners[0].Settings["command"])
}

func TestLoadFromBytesInvalidTimeout(t *testing.T) {
	yaml := []byte(`
clusterName: test
workloads:
  kinds:
    - Deployment
scanners:
  scanners:
    - name: trivy
      type: trivy
      enabled: true
      command:
        binary: /usr/bin/trivy
        timeout: invalid
komodor:
  baseURL: https://app.komodor.io
`)

	_, err := LoadFromBytes(yaml)

	require.NoError(t, err)
}

func TestLoadFromBytesAllowsScannerBinaryOverrideToBeOmitted(t *testing.T) {
	yaml := []byte(`
clusterName: test
workloads:
  kinds:
    - Deployment
scanners:
  scanners:
    - name: trivy
      type: trivy
      enabled: true
      command:
        timeout: 10s
komodor:
  baseURL: https://app.komodor.io
`)

	cfg, err := LoadFromBytes(yaml)

	require.NoError(t, err)
	require.Equal(t, map[string]any{"timeout": "10s"}, cfg.Scanners.Scanners[0].Settings["command"])
}

func TestLoadFromBytesParsesScannerResources(t *testing.T) {
	yaml := []byte(`
clusterName: test
workloads:
  kinds:
    - Deployment
scanners:
  scanners:
    - name: trivy-operator
      type: trivy-operator
      enabled: true
      resources:
        - vulnerabilityreports
        - clustervulnerabilityreports
komodor:
  baseURL: https://app.komodor.io
`)

	cfg, err := LoadFromBytes(yaml)

	require.NoError(t, err)
	require.Equal(t, []any{"vulnerabilityreports", "clustervulnerabilityreports"}, cfg.Scanners.Scanners[0].Settings["resources"])
}

func TestLoadFromBytesParsesPublishingMode(t *testing.T) {
	yaml := []byte(`
clusterName: test
workloads:
  kinds:
    - Deployment
scanners:
  scanners:
    - name: trivy
      type: trivy
      enabled: true
publishing:
  mode: events
`)

	cfg, err := LoadFromBytes(yaml)

	require.NoError(t, err)
	require.Equal(t, PublishingModeEvents, cfg.Publishing.Mode)
}
