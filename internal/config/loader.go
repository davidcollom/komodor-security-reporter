package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// rawConfig is the YAML structure for configuration.
type rawConfig struct {
	ClusterName string `yaml:"clusterName"`
	Namespaces  struct {
		Include []string `yaml:"include"`
		Exclude []string `yaml:"exclude"`
	} `yaml:"namespaces"`
	Workloads struct {
		Kinds []string `yaml:"kinds"`
	} `yaml:"workloads"`
	Registry struct {
		ResolveDigest bool `yaml:"resolveDigest"`
	} `yaml:"registry"`
	State struct {
		TTL string `yaml:"ttl"`
	} `yaml:"state"`
	Scanners struct {
		Concurrency int `yaml:"concurrency"`
		Scanners    []struct {
			Name    string `yaml:"name"`
			Type    string `yaml:"type"`
			Enabled bool   `yaml:"enabled"`
			Command struct {
				Binary  string `yaml:"binary"`
				Timeout string `yaml:"timeout"`
			} `yaml:"command"`
		} `yaml:"scanners"`
	} `yaml:"scanners"`
	Publishing struct {
		MinimumSeverity    string `yaml:"minimumSeverity"`
		IncludeTopFindings int    `yaml:"includeTopFindings"`
		PublishCleanScans  bool   `yaml:"publishCleanScans"`
		DeduplicateTTL     string `yaml:"dedupeTTL"`
	} `yaml:"publishing"`
	Komodor struct {
		Enabled bool   `yaml:"enabled"`
		BaseURL string `yaml:"baseURL"`
	} `yaml:"komodor"`
}

// LoadFromFile loads configuration from a YAML file.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	return LoadFromBytes(data)
}

// LoadFromBytes loads configuration from YAML bytes.
func LoadFromBytes(data []byte) (*Config, error) {
	var raw rawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal yaml: %w", err)
	}

	return convertToConfig(raw)
}

func convertToConfig(raw rawConfig) (*Config, error) {
	cfg := &Config{
		ClusterName: raw.ClusterName,
		Namespaces: NamespaceConfig{
			Include: raw.Namespaces.Include,
			Exclude: raw.Namespaces.Exclude,
		},
		Workloads: WorkloadsConfig{
			Kinds: raw.Workloads.Kinds,
		},
		Registry: RegistryConfig{
			ResolveDigest: raw.Registry.ResolveDigest,
		},
		State: StateConfig{},
		Komodor: KomodorConfig{
			Enabled: raw.Komodor.Enabled,
			BaseURL: raw.Komodor.BaseURL,
		},
	}

	stateTTL := 72 * time.Hour // default

	if raw.State.TTL != "" {
		d, err := time.ParseDuration(raw.State.TTL)
		if err != nil {
			return nil, fmt.Errorf("parse state ttl: %w", err)
		}

		stateTTL = d
	}

	cfg.State = StateConfig{TTL: stateTTL}

	if raw.Scanners.Concurrency > 0 {
		cfg.Scanners.Concurrency = raw.Scanners.Concurrency
	} else {
		cfg.Scanners.Concurrency = 4
	}

	// Parse scanners
	cfg.Scanners.Scanners = make([]ScannerConfig, len(raw.Scanners.Scanners))
	for i, s := range raw.Scanners.Scanners {
		timeout := 5 * time.Minute // default

		if s.Command.Timeout != "" {
			d, err := time.ParseDuration(s.Command.Timeout)
			if err != nil {
				return nil, fmt.Errorf("parse scanner timeout: %w", err)
			}

			timeout = d
		}

		cfg.Scanners.Scanners[i] = ScannerConfig{
			Name:    s.Name,
			Type:    s.Type,
			Enabled: s.Enabled,
			Command: CommandConfig{
				Binary:  s.Command.Binary,
				Timeout: timeout,
			},
		}
	}

	// Parse publishing config
	deduplicateTTL := 24 * time.Hour // default

	if raw.Publishing.DeduplicateTTL != "" {
		d, err := time.ParseDuration(raw.Publishing.DeduplicateTTL)
		if err != nil {
			return nil, fmt.Errorf("parse deduplicate TTL: %w", err)
		}

		deduplicateTTL = d
	}

	cfg.Publishing = PublishingConfig{
		MinimumSeverity:    raw.Publishing.MinimumSeverity,
		IncludeTopFindings: raw.Publishing.IncludeTopFindings,
		PublishCleanScans:  raw.Publishing.PublishCleanScans,
		DeduplicateTTL:     deduplicateTTL,
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}
