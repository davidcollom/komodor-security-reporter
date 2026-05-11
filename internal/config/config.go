package config

import (
	"fmt"
	"strings"
	"time"
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
	Memory    MemoryConfig   `mapstructure:"memory"`
	Redis     RedisConfig    `mapstructure:"redis"`
	Memcache  MemcacheConfig `mapstructure:"memcache"`
}

// MemoryConfig defines in-process memory backend settings.
type MemoryConfig struct {
	// MaxEntries caps the number of live dedupe entries. 0 means unlimited.
	MaxEntries int `mapstructure:"maxEntries"`
}

// RedisConfig defines Redis-backed state backend settings.
type RedisConfig struct {
	// Address is the Redis server address in host:port form (required for redis backend).
	Address    string `mapstructure:"address"`
	Password   string `mapstructure:"password"`
	DB         int    `mapstructure:"db"`
	TLSEnabled bool   `mapstructure:"tlsEnabled"`
	// KeyPrefix is prepended to all Redis keys. Defaults to "komodor-security-reporter".
	KeyPrefix    string        `mapstructure:"keyPrefix"`
	DialTimeout  time.Duration `mapstructure:"dialTimeout"`
	ReadTimeout  time.Duration `mapstructure:"readTimeout"`
	WriteTimeout time.Duration `mapstructure:"writeTimeout"`
}

// MemcacheConfig defines Memcache-backed state backend settings.
type MemcacheConfig struct {
	// Address is the Memcache server address in host:port form (required for memcache backend).
	Address      string        `mapstructure:"address"`
	KeyPrefix    string        `mapstructure:"keyPrefix"`
	Timeout      time.Duration `mapstructure:"timeout"`
	MaxIdleConns int           `mapstructure:"maxIdleConns"`
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
	Name      string        `mapstructure:"name"`
	Type      string        `mapstructure:"type"` // trivy, trivy-operator, clair, snyk, wiz
	Enabled   bool          `mapstructure:"enabled"`
	Resources []string      `mapstructure:"resources"`
	Command   CommandConfig `mapstructure:"command"`
}

// CommandConfig defines CLI-based scanner configuration.
type CommandConfig struct {
	Binary  string        `mapstructure:"binary"`
	Timeout time.Duration `mapstructure:"timeout"`
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
	case StateBackendConfigMap, StateBackendMemory:
		return nil
	case StateBackendRedis:
		if strings.TrimSpace(state.Redis.Address) == "" {
			return fmt.Errorf("state.redis.address is required when using the redis backend")
		}

		return nil
	case StateBackendMemcache:
		if strings.TrimSpace(state.Memcache.Address) == "" {
			return fmt.Errorf("state.memcache.address is required when using the memcache backend")
		}

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

		if s.Type == "trivy-operator" {
			for _, resource := range s.Resources {
				if resource == "" {
					return fmt.Errorf("trivy-operator scanner resources entries must be non-empty")
				}
			}
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
