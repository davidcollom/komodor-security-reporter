package config

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// LoadFromFile loads configuration from a YAML file.
func LoadFromFile(path string) (*Config, error) {
	v := newLoader()
	v.SetConfigFile(path)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg, err := unmarshalConfig(v)
	if err != nil {
		return nil, err
	}

	return validateLoadedConfig(cfg)
}

// LoadFromBytes loads configuration from YAML bytes.
func LoadFromBytes(data []byte) (*Config, error) {
	v := newLoader()
	v.SetConfigType("yaml")

	if err := v.ReadConfig(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("unmarshal yaml: %w", err)
	}

	cfg, err := unmarshalConfig(v)
	if err != nil {
		return nil, err
	}

	return validateLoadedConfig(cfg)
}

func newLoader() *viper.Viper {
	v := viper.New()
	v.SetDefault("state.backend", StateBackendConfigMap)
	v.SetDefault("state.ttl", "72h")
	v.SetDefault("state.namespace", "default")
	v.SetDefault("state.memory.maxEntries", 1000)
	v.SetDefault("state.redis.keyPrefix", "komodor-security-reporter")
	v.SetDefault("state.redis.dialTimeout", "5s")
	v.SetDefault("state.redis.readTimeout", "3s")
	v.SetDefault("state.redis.writeTimeout", "3s")
	v.SetDefault("state.memcache.keyPrefix", "komodor-security-reporter")
	v.SetDefault("state.memcache.timeout", "500ms")
	v.SetDefault("state.memcache.maxIdleConns", 2)
	v.SetDefault("scanners.concurrency", 4)
	v.SetDefault("scanners.runtime.timeout", DefaultScannerRuntimeTimeout.String())
	v.SetDefault("scanners.runtime.retry.maxAttempts", DefaultScannerRetryMaxAttempts)
	v.SetDefault("scanners.runtime.retry.initialBackoff", DefaultScannerRetryInitialBackoff.String())
	v.SetDefault("scanners.runtime.retry.maxBackoff", DefaultScannerRetryMaxBackoff.String())
	v.SetDefault("scanners.runtime.retry.backoffMultiplier", DefaultScannerRetryBackoffMultiplier)
	v.SetDefault("scanners.runtime.circuitBreaker.failureThreshold", DefaultScannerCircuitFailureThreshold)
	v.SetDefault("scanners.runtime.circuitBreaker.openDuration", DefaultScannerCircuitOpenDuration.String())
	v.SetDefault("scanners.runtime.circuitBreaker.halfOpenMaxRequests", DefaultScannerCircuitHalfOpenMaxRequests)
	v.SetDefault("publishing.mode", PublishingModeKomodor)
	v.SetDefault("publishing.dedupeTTL", "24h")
	v.SetDefault("scanners.scanners", []map[string]any{})

	return v
}

func unmarshalConfig(v *viper.Viper) (*Config, error) {
	var cfg Config

	err := v.Unmarshal(&cfg, func(dc *mapstructure.DecoderConfig) {
		dc.TagName = "mapstructure"
		dc.DecodeHook = mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
		)
	})
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "state.ttl") {
			return nil, fmt.Errorf("parse state ttl: %w", err)
		}

		if strings.Contains(errMsg, ".command.timeout") {
			return nil, fmt.Errorf("parse scanner timeout: %w", err)
		}

		if strings.Contains(errMsg, "scanners.runtime") {
			return nil, fmt.Errorf("parse scanner runtime config: %w", err)
		}

		return nil, fmt.Errorf("decode config: %w", err)
	}

	for i := range cfg.Scanners.Scanners {
		if cfg.Scanners.Scanners[i].Command.Timeout == 0 {
			// Only apply the default when the field is absent from configuration.
			// An explicit timeout: 0s is preserved (treated as no timeout).
			key := fmt.Sprintf("scanners.scanners.%d.command.timeout", i)
			if !v.IsSet(key) {
				cfg.Scanners.Scanners[i].Command.Timeout = 5 * time.Minute
			}
		}
	}

	return &cfg, nil
}

func validateLoadedConfig(cfg *Config) (*Config, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}
