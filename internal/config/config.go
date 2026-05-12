package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	// DefaultScannerRuntimeTimeout is the per-scan timeout when a scanner does not define a command timeout.
	DefaultScannerRuntimeTimeout = 5 * time.Minute
	// DefaultScannerRetryMaxAttempts is the maximum number of scan attempts (first attempt + retries).
	DefaultScannerRetryMaxAttempts = 3
	// DefaultScannerRetryInitialBackoff is the initial retry delay for transient scanner failures.
	DefaultScannerRetryInitialBackoff = 1 * time.Second
	// DefaultScannerRetryMaxBackoff is the upper bound for retry backoff.
	DefaultScannerRetryMaxBackoff = 10 * time.Second
	// DefaultScannerRetryBackoffMultiplier controls exponential backoff growth.
	DefaultScannerRetryBackoffMultiplier = 2.0
	// DefaultScannerCircuitFailureThreshold is the number of failed scans before opening the scanner circuit.
	DefaultScannerCircuitFailureThreshold = 3
	// DefaultScannerCircuitOpenDuration is how long a scanner circuit stays open before half-open checks.
	DefaultScannerCircuitOpenDuration = 2 * time.Minute
	// DefaultScannerCircuitHalfOpenMaxRequests is the number of probe requests allowed while half-open.
	DefaultScannerCircuitHalfOpenMaxRequests = 1
)

// Supported state backend names.
const (
	StateBackendConfigMap = "configmap"
	StateBackendMemory    = "memory"
	StateBackendRedis     = "redis"
	StateBackendMemcache  = "memcache"
)

// Publishing mode constants control where scan findings are sent.
const (
	PublishingModeKomodor = "komodor"
	PublishingModeEvents  = "events"
	PublishingModeBoth    = "both"
)

// Config represents the watcher configuration.
type Config struct {
	source *viper.Viper

	ClusterName string           `mapstructure:"clusterName"`
	Namespaces  NamespaceConfig  `mapstructure:"namespaces"`
	Workloads   WorkloadsConfig  `mapstructure:"workloads"`
	Registry    RegistryConfig   `mapstructure:"registry"`
	Scanners    ScannersConfig   `mapstructure:"scanners"`
	State       StateConfig      `mapstructure:"state"`
	Publishing  PublishingConfig `mapstructure:"publishing"`
	Komodor     KomodorConfig    `mapstructure:"komodor"`
}

// NamespaceConfig defines namespace filtering.
type NamespaceConfig struct {
	Include []string `mapstructure:"include"`
	Exclude []string `mapstructure:"exclude"`
}

// WorkloadsConfig defines which workload kinds to watch.
type WorkloadsConfig struct {
	Kinds []string `mapstructure:"kinds"` // Deployment, StatefulSet, DaemonSet, Job, CronJob
}

// RegistryConfig defines registry resolution options.
type RegistryConfig struct {
	ResolveDigest bool `mapstructure:"resolveDigest"`
}

// StateConfig defines state storage behaviour.
type StateConfig struct {
	Backend   string         `mapstructure:"backend"`
	TTL       time.Duration  `mapstructure:"ttl"`
	Namespace string         `mapstructure:"namespace"`
	Settings  map[string]any `mapstructure:",remain"`
}

// ScannersConfig defines scanner configurations.
type ScannersConfig struct {
	Concurrency int                  `mapstructure:"concurrency"`
	Runtime     ScannerRuntimeConfig `mapstructure:"runtime"`
	Scanners    []ScannerConfig      `mapstructure:"scanners"`
}

// ScannerRuntimeConfig defines scanner execution resilience behaviour.
type ScannerRuntimeConfig struct {
	Timeout        time.Duration        `mapstructure:"timeout"`
	Retry          ScannerRetryConfig   `mapstructure:"retry"`
	CircuitBreaker ScannerCircuitConfig `mapstructure:"circuitBreaker"`
}

// ScannerRetryConfig defines retry behaviour for transient scanner failures.
type ScannerRetryConfig struct {
	MaxAttempts       int           `mapstructure:"maxAttempts"`
	InitialBackoff    time.Duration `mapstructure:"initialBackoff"`
	MaxBackoff        time.Duration `mapstructure:"maxBackoff"`
	BackoffMultiplier float64       `mapstructure:"backoffMultiplier"`
}

// ScannerCircuitConfig defines circuit breaker behaviour for scanner failures.
type ScannerCircuitConfig struct {
	FailureThreshold    int           `mapstructure:"failureThreshold"`
	OpenDuration        time.Duration `mapstructure:"openDuration"`
	HalfOpenMaxRequests int           `mapstructure:"halfOpenMaxRequests"`
}

// ScannerConfig defines a single scanner configuration.
type ScannerConfig struct {
	Name     string         `mapstructure:"name"`
	Type     string         `mapstructure:"type"` // trivy, trivy-operator, clair, snyk, wiz
	Enabled  bool           `mapstructure:"enabled"`
	Settings map[string]any `mapstructure:",remain"`
}

// PublishingConfig defines event publishing policies.
type PublishingConfig struct {
	Mode               string        `mapstructure:"mode"`
	MinimumSeverity    string        `mapstructure:"minimumSeverity"`
	IncludeTopFindings int           `mapstructure:"includeTopFindings"`
	PublishCleanScans  bool          `mapstructure:"publishCleanScans"`
	DeduplicateTTL     time.Duration `mapstructure:"dedupeTTL"`
}

// KomodorConfig defines Komodor integration settings.
type KomodorConfig struct {
	BaseURL string `mapstructure:"baseURL"`
}

// EnabledScanners returns a human-readable list of enabled scanners.
func (c *Config) EnabledScanners() []string {
	enabled := make([]string, 0, len(c.Scanners.Scanners))

	for _, scanner := range c.Scanners.Scanners {
		if !scanner.Enabled {
			continue
		}

		enabled = append(enabled, fmt.Sprintf("%s (%s)", scanner.Name, scanner.Type))
	}

	return enabled
}

// SubConfig returns a scoped viper instance for the provided path.
func (c *Config) SubConfig(path string) *viper.Viper {
	if c == nil || c.source == nil {
		return nil
	}

	return c.source.Sub(path)
}

// ScannerSubConfig returns a scoped viper instance for scanners.scanners[index].
func (c *Config) ScannerSubConfig(index int) *viper.Viper {
	if index < 0 {
		return nil
	}

	return c.SubConfig(fmt.Sprintf("scanners.scanners.%d", index))
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.ClusterName == "" {
		return fmt.Errorf("clusterName is required")
	}

	if err := validateWorkloadKinds(c.Workloads.Kinds); err != nil {
		return err
	}

	if err := validateScanners(c.Scanners); err != nil {
		return err
	}

	if c.State.TTL <= 0 {
		return fmt.Errorf("state.ttl must be greater than 0")
	}

	if err := validateState(c.State); err != nil {
		return err
	}

	if err := validatePublishing(c.Publishing); err != nil {
		return err
	}

	if PublishToKomodor(c.Publishing.Mode) {
		if err := validateKomodor(c.Komodor); err != nil {
			return err
		}
	}

	if !PublishToKomodor(c.Publishing.Mode) && !PublishToEvents(c.Publishing.Mode) {
		return fmt.Errorf("publishing.mode must enable at least one publisher")
	}

	return nil
}

func validateState(state StateConfig) error {
	switch NormalizeStateBackend(state.Backend) {
	case StateBackendConfigMap, StateBackendMemory, StateBackendRedis, StateBackendMemcache:
		return nil
	default:
		return fmt.Errorf("state.backend must be one of: %s, %s, %s, %s", StateBackendConfigMap, StateBackendMemory, StateBackendRedis, StateBackendMemcache)
	}
}

func validatePublishing(publishing PublishingConfig) error {
	if !isValidPublishingMode(publishing.Mode) {
		return fmt.Errorf("publishing.mode must be one of: %s, %s, %s", PublishingModeKomodor, PublishingModeEvents, PublishingModeBoth)
	}

	return nil
}

func isValidPublishingMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", PublishingModeKomodor, PublishingModeEvents, PublishingModeBoth:
		return true
	default:
		return false
	}
}

// PublishToKomodor returns true when Komodor API publishing is enabled for the mode.
func PublishToKomodor(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", PublishingModeKomodor, PublishingModeBoth:
		return true
	default:
		return false
	}
}

// PublishToEvents returns true when Kubernetes Event publishing is enabled for the mode.
func PublishToEvents(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case PublishingModeEvents, PublishingModeBoth:
		return true
	default:
		return false
	}
}

func validateWorkloadKinds(kinds []string) error {
	if len(kinds) == 0 {
		return fmt.Errorf("at least one workload kind is required")
	}

	for _, kind := range kinds {
		switch kind {
		case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
			// OK
		default:
			return fmt.Errorf("unsupported workload kind: %s", kind)
		}
	}

	return nil
}

func validateScanners(scanners ScannersConfig) error {
	if len(scanners.Scanners) == 0 {
		return fmt.Errorf("at least one scanner configuration is required")
	}

	if scanners.Concurrency <= 0 {
		return fmt.Errorf("scanner concurrency must be greater than 0")
	}

	runtime := EffectiveScannerRuntimeConfig(scanners.Runtime)

	if runtime.Timeout <= 0 {
		return fmt.Errorf("scanners.runtime.timeout must be greater than 0")
	}

	if runtime.Retry.MaxAttempts <= 0 {
		return fmt.Errorf("scanners.runtime.retry.maxAttempts must be greater than 0")
	}

	if runtime.Retry.InitialBackoff <= 0 {
		return fmt.Errorf("scanners.runtime.retry.initialBackoff must be greater than 0")
	}

	if runtime.Retry.MaxBackoff <= 0 {
		return fmt.Errorf("scanners.runtime.retry.maxBackoff must be greater than 0")
	}

	if runtime.Retry.BackoffMultiplier < 1 {
		return fmt.Errorf("scanners.runtime.retry.backoffMultiplier must be greater than or equal to 1")
	}

	if runtime.CircuitBreaker.FailureThreshold <= 0 {
		return fmt.Errorf("scanners.runtime.circuitBreaker.failureThreshold must be greater than 0")
	}

	if runtime.CircuitBreaker.OpenDuration <= 0 {
		return fmt.Errorf("scanners.runtime.circuitBreaker.openDuration must be greater than 0")
	}

	if runtime.CircuitBreaker.HalfOpenMaxRequests <= 0 {
		return fmt.Errorf("scanners.runtime.circuitBreaker.halfOpenMaxRequests must be greater than 0")
	}

	for _, s := range scanners.Scanners {
		if s.Name == "" {
			return fmt.Errorf("scanner name is required")
		}

		if s.Type == "" {
			return fmt.Errorf("scanner type is required")
		}
	}

	return nil
}

// EffectiveScannerRuntimeConfig applies defaults to scanner runtime settings.
func EffectiveScannerRuntimeConfig(runtime ScannerRuntimeConfig) ScannerRuntimeConfig {
	if runtime.Timeout == 0 {
		runtime.Timeout = DefaultScannerRuntimeTimeout
	}

	if runtime.Retry.MaxAttempts == 0 {
		runtime.Retry.MaxAttempts = DefaultScannerRetryMaxAttempts
	}

	if runtime.Retry.InitialBackoff == 0 {
		runtime.Retry.InitialBackoff = DefaultScannerRetryInitialBackoff
	}

	if runtime.Retry.MaxBackoff == 0 {
		runtime.Retry.MaxBackoff = DefaultScannerRetryMaxBackoff
	}

	if runtime.Retry.BackoffMultiplier == 0 {
		runtime.Retry.BackoffMultiplier = DefaultScannerRetryBackoffMultiplier
	}

	if runtime.CircuitBreaker.FailureThreshold == 0 {
		runtime.CircuitBreaker.FailureThreshold = DefaultScannerCircuitFailureThreshold
	}

	if runtime.CircuitBreaker.OpenDuration == 0 {
		runtime.CircuitBreaker.OpenDuration = DefaultScannerCircuitOpenDuration
	}

	if runtime.CircuitBreaker.HalfOpenMaxRequests == 0 {
		runtime.CircuitBreaker.HalfOpenMaxRequests = DefaultScannerCircuitHalfOpenMaxRequests
	}

	return runtime
}

func validateKomodor(komodor KomodorConfig) error {
	if komodor.BaseURL == "" {
		return fmt.Errorf("komodor.baseURL is required")
	}

	return nil
}

// NormalizeStateBackend returns a validated backend value with defaults applied.
func NormalizeStateBackend(backend string) string {
	if strings.TrimSpace(backend) == "" {
		return StateBackendConfigMap
	}

	normalized := strings.ToLower(strings.TrimSpace(backend))
	if normalized == "external" {
		return StateBackendRedis
	}

	return normalized
}
