package configmap

import (
	"fmt"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

const defaultConfigMapName = "komodor-security-reporter-state"

// Config defines ConfigMap backend-specific state settings.
type Config struct {
	ConfigMapName string `mapstructure:"configMapName"`
}

// ParseConfig decodes ConfigMap backend settings from a scoped state viper config.
func ParseConfig(scopedConfig *viper.Viper) (Config, error) {
	cfg := Config{}

	if scopedConfig != nil {
		err := scopedConfig.Unmarshal(&cfg, func(dc *mapstructure.DecoderConfig) {
			dc.TagName = "mapstructure"
			dc.DecodeHook = mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
			)
		})
		if err != nil {
			return Config{}, fmt.Errorf("decode configmap state config: %w", err)
		}
	}

	if cfg.ConfigMapName == "" {
		if scopedConfig != nil {
			cfg.ConfigMapName = scopedConfig.GetString("configmap.configMapName")
		}
	}

	if cfg.ConfigMapName == "" {
		cfg.ConfigMapName = defaultConfigMapName
	}

	return cfg, nil
}
