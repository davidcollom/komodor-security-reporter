package config

import (
	"fmt"
	"strings"
	"time"
)

// Supported state backend names.
const (
	StateBackendConfigMap = "configmap"
	StateBackendMemory    = "memory"
	StateBackendExternal  = "external"
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
	Backend   string        `mapstructure:"backend"`
	TTL       time.Duration `mapstructure:"ttl"`
	Namespace string        `mapstructure:"namespace"`
}

// ScannersConfig defines scanner configurations.
type ScannersConfig struct {
	Concurrency int             `mapstructure:"concurrency"`
	Scanners    []ScannerConfig `mapstructure:"scanners"`
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
	case StateBackendConfigMap, StateBackendMemory, StateBackendExternal:
		return nil
	default:
		return fmt.Errorf("state.backend must be one of: %s, %s, %s", StateBackendConfigMap, StateBackendMemory, StateBackendExternal)
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

	return strings.ToLower(strings.TrimSpace(backend))
}
