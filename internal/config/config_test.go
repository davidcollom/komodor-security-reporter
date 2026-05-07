package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadFromBytes(t *testing.T) {
	yaml := []byte(`
clusterName: prod-eks-01

namespaces:
  include:
    - production
    - platform
  exclude:
    - kube-system

workloads:
  kinds:
    - Deployment
    - StatefulSet

registry:
  resolveDigest: true

scanners:
  concurrency: 3
  scanners:
    - name: trivy
      type: trivy
      enabled: true
      command:
        binary: /usr/local/bin/trivy
        timeout: 5m

publishing:
  minimumSeverity: high
  includeTopFindings: 5
  publishCleanScans: false
  dedupeTTL: 24h

komodor:
  enabled: true
  baseURL: https://app.komodor.io
`)

	cfg, err := LoadFromBytes(yaml)

	require.NoError(t, err)
	require.Equal(t, "prod-eks-01", cfg.ClusterName)
	require.Equal(t, 2, len(cfg.Namespaces.Include))
	require.Equal(t, 1, len(cfg.Namespaces.Exclude))
	require.Equal(t, 2, len(cfg.Workloads.Kinds))
	require.True(t, cfg.Registry.ResolveDigest)
	require.Equal(t, 3, cfg.Scanners.Concurrency)
	require.Equal(t, 1, len(cfg.Scanners.Scanners))
	require.Equal(t, "/usr/local/bin/trivy", cfg.Scanners.Scanners[0].Command.Binary)
	require.Equal(t, 5*time.Minute, cfg.Scanners.Scanners[0].Command.Timeout)
	require.Equal(t, 72*time.Hour, cfg.State.TTL)
	require.Equal(t, "high", cfg.Publishing.MinimumSeverity)
	require.Equal(t, 5, cfg.Publishing.IncludeTopFindings)
	require.Equal(t, 24*time.Hour, cfg.Publishing.DeduplicateTTL)
	require.True(t, cfg.Komodor.Enabled)
	require.Equal(t, "https://app.komodor.io", cfg.Komodor.BaseURL)
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		wantError bool
	}{
		{
			name: "valid config",
			config: &Config{
				ClusterName: "test",
				Workloads: WorkloadsConfig{
					Kinds: []string{"Deployment"},
				},
				Scanners: ScannersConfig{
					Concurrency: 2,
					Scanners: []ScannerConfig{
						{
							Name:    "trivy",
							Type:    "trivy",
							Enabled: true,
							Command: CommandConfig{
								Binary: "/usr/bin/trivy",
							},
						},
					},
				},
				State: StateConfig{TTL: 72 * time.Hour},
				Komodor: KomodorConfig{
					Enabled: true,
					BaseURL: "https://app.komodor.io",
				},
			},
			wantError: false,
		},
		{
			name: "valid config without scanner binary override",
			config: &Config{
				ClusterName: "test",
				Workloads: WorkloadsConfig{
					Kinds: []string{"Deployment"},
				},
				Scanners: ScannersConfig{
					Concurrency: 2,
					Scanners: []ScannerConfig{
						{
							Name:    "trivy",
							Type:    "trivy",
							Enabled: true,
						},
					},
				},
				State: StateConfig{TTL: 72 * time.Hour},
				Komodor: KomodorConfig{
					Enabled: true,
					BaseURL: "https://app.komodor.io",
				},
			},
			wantError: false,
		},
		{
			name: "invalid scanner concurrency",
			config: &Config{
				ClusterName: "test",
				Workloads: WorkloadsConfig{
					Kinds: []string{"Deployment"},
				},
				Scanners: ScannersConfig{
					Concurrency: 0,
					Scanners: []ScannerConfig{{
						Name:    "trivy",
						Type:    "trivy",
						Enabled: true,
						Command: CommandConfig{Binary: "/usr/bin/trivy"},
					}},
				},
				State: StateConfig{TTL: 72 * time.Hour},
				Komodor: KomodorConfig{
					Enabled: true,
					BaseURL: "https://app.komodor.io",
				},
			},
			wantError: true,
		},
		{
			name: "komodor must be enabled",
			config: &Config{
				ClusterName: "test",
				Workloads: WorkloadsConfig{
					Kinds: []string{"Deployment"},
				},
				Scanners: ScannersConfig{
					Concurrency: 1,
					Scanners: []ScannerConfig{{
						Name:    "trivy",
						Type:    "trivy",
						Enabled: true,
						Command: CommandConfig{Binary: "/usr/bin/trivy"},
					}},
				},
				State: StateConfig{TTL: 72 * time.Hour},
				Komodor: KomodorConfig{
					Enabled: false,
					BaseURL: "https://app.komodor.io",
				},
			},
			wantError: true,
		},
		{
			name: "komodor base url required",
			config: &Config{
				ClusterName: "test",
				Workloads: WorkloadsConfig{
					Kinds: []string{"Deployment"},
				},
				Scanners: ScannersConfig{
					Concurrency: 1,
					Scanners: []ScannerConfig{{
						Name:    "trivy",
						Type:    "trivy",
						Enabled: true,
						Command: CommandConfig{Binary: "/usr/bin/trivy"},
					}},
				},
				State: StateConfig{TTL: 72 * time.Hour},
				Komodor: KomodorConfig{
					Enabled: true,
				},
			},
			wantError: true,
		},
		{
			name: "missing cluster name",
			config: &Config{
				Workloads: WorkloadsConfig{
					Kinds: []string{"Deployment"},
				},
				State: StateConfig{TTL: 72 * time.Hour},
			},
			wantError: true,
		},
		{
			name: "missing workload kinds",
			config: &Config{
				ClusterName: "test",
				State:       StateConfig{TTL: 72 * time.Hour},
			},
			wantError: true,
		},
		{
			name: "invalid workload kind",
			config: &Config{
				ClusterName: "test",
				Workloads: WorkloadsConfig{
					Kinds: []string{"InvalidKind"},
				},
				State: StateConfig{TTL: 72 * time.Hour},
			},
			wantError: true,
		},
		{
			name: "invalid state ttl",
			config: &Config{
				ClusterName: "test",
				Workloads:   WorkloadsConfig{Kinds: []string{"Deployment"}},
				Scanners: ScannersConfig{Concurrency: 1, Scanners: []ScannerConfig{{
					Name:    "trivy",
					Type:    "trivy",
					Enabled: true,
				}}},
				State: StateConfig{TTL: 0},
				Komodor: KomodorConfig{
					Enabled: true,
					BaseURL: "https://app.komodor.io",
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
