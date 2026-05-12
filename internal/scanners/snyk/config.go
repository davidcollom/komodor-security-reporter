package snyk

import (
	"fmt"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

const defaultCommandTimeout = 5 * time.Minute

type scannerConfig struct {
	Command commandConfig `mapstructure:"command"`
}

type commandConfig struct {
	Binary  string        `mapstructure:"binary"`
	Timeout time.Duration `mapstructure:"timeout"`
}

func parseConfig(scopedConfig *viper.Viper) (scannerConfig, time.Duration, error) {
	var cfg scannerConfig

	if scopedConfig != nil {
		err := scopedConfig.Unmarshal(&cfg, func(dc *mapstructure.DecoderConfig) {
			dc.TagName = "mapstructure"
			dc.DecodeHook = mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
			)
		})
		if err != nil {
			return scannerConfig{}, 0, fmt.Errorf("decode snyk config: %w", err)
		}
	}

	if cfg.Command.Binary == "" {
		cfg.Command.Binary = "snyk"
	}

	timeout := cfg.Command.Timeout
	if scopedConfig == nil || !scopedConfig.IsSet("command.timeout") {
		timeout = defaultCommandTimeout
	}

	return cfg, timeout, nil
}
