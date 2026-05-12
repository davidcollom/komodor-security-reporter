package trivyoperator

import (
	"fmt"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

type scannerConfig struct {
	Resources []string `mapstructure:"resources"`
}

func parseConfig(scopedConfig *viper.Viper) (scannerConfig, error) {
	var cfg scannerConfig

	if scopedConfig != nil {
		err := scopedConfig.Unmarshal(&cfg, func(dc *mapstructure.DecoderConfig) {
			dc.TagName = "mapstructure"
			dc.DecodeHook = mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
			)
		})
		if err != nil {
			return scannerConfig{}, fmt.Errorf("decode trivy-operator config: %w", err)
		}
	}

	for i := range cfg.Resources {
		if strings.TrimSpace(cfg.Resources[i]) == "" {
			return scannerConfig{}, fmt.Errorf("trivy-operator scanner resources entries must be non-empty")
		}
	}

	return cfg, nil
}
