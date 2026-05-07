package config

import (
	"fmt"
	"time"
)

// Config represents the watcher configuration.
type Config struct {
	ClusterName string
	Namespaces  NamespaceConfig
	Workloads   WorkloadsConfig
	Registry    RegistryConfig
	Scanners    ScannersConfig
	State       StateConfig
	Publishing  PublishingConfig
	Komodor     KomodorConfig
}

// NamespaceConfig defines namespace filtering.
type NamespaceConfig struct {
	Include []string
	Exclude []string
}

// WorkloadsConfig defines which workload kinds to watch.
type WorkloadsConfig struct {
	Kinds []string // Deployment, StatefulSet, DaemonSet, Job, CronJob
}

// RegistryConfig defines registry resolution options.
type RegistryConfig struct {
	ResolveDigest bool
}

// StateConfig defines state storage behavior.
type StateConfig struct {
	TTL time.Duration
}

// ScannersConfig defines scanner configurations.
type ScannersConfig struct {
	Concurrency int
	Scanners    []ScannerConfig
}

// ScannerConfig defines a single scanner configuration.
type ScannerConfig struct {
	Name      string
	Type      string // trivy, trivy-operator, clair, snyk, wiz
	Enabled   bool
	Resources []string
	Command   CommandConfig
}

// CommandConfig defines CLI-based scanner configuration.
type CommandConfig struct {
	Binary  string
	Timeout time.Duration
}

// PublishingConfig defines event publishing policies.
type PublishingConfig struct {
	MinimumSeverity    string
	IncludeTopFindings int
	PublishCleanScans  bool
	DeduplicateTTL     time.Duration
}

// KomodorConfig defines Komodor integration settings.
type KomodorConfig struct {
	Enabled bool
	BaseURL string
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

	if err := validateKomodor(c.Komodor); err != nil {
		return err
	}

	return nil
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
	if !komodor.Enabled {
		return fmt.Errorf("komodor.enabled must be true")
	}

	if komodor.BaseURL == "" {
		return fmt.Errorf("komodor.baseURL is required")
	}

	return nil
}
