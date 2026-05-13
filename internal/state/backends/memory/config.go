package memory

import (
	"fmt"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// Config defines memory backend-specific state settings.
// MaxEntries caps live dedupe entries; 0 means unlimited.
type Config struct {
	MaxEntries int `mapstructure:"maxEntries"`
}

// ParseConfig decodes memory backend settings from a scoped state viper config.
func ParseConfig(scopedConfig *viper.Viper) (Config, error) {
	cfg := Config{}

	decodeScope := scopedConfig
	if scopedConfig != nil {
		if sub := scopedConfig.Sub("memory"); sub != nil {
			decodeScope = sub
		}
	}

	if decodeScope != nil {
		err := decodeScope.Unmarshal(&cfg, func(dc *mapstructure.DecoderConfig) {
			dc.TagName = "mapstructure"
			dc.DecodeHook = mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
			)
		})
		if err != nil {
			return Config{}, fmt.Errorf("decode memory state config: %w", err)
		}
	}

	return cfg, nil
}
