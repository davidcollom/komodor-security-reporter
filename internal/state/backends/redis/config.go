package redis

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// Config defines Redis backend-specific state settings.
type Config struct {
	Address      string        `mapstructure:"address"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	TLSEnabled   bool          `mapstructure:"tlsEnabled"`
	KeyPrefix    string        `mapstructure:"keyPrefix"`
	DialTimeout  time.Duration `mapstructure:"dialTimeout"`
	ReadTimeout  time.Duration `mapstructure:"readTimeout"`
	WriteTimeout time.Duration `mapstructure:"writeTimeout"`
}

// ParseConfig decodes Redis backend settings from a scoped state viper config.
func ParseConfig(scopedConfig *viper.Viper) (Config, error) {
	cfg := Config{}

	decodeScope := scopedConfig
	if scopedConfig != nil {
		if sub := scopedConfig.Sub("redis"); sub != nil {
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
			return Config{}, fmt.Errorf("decode redis state config: %w", err)
		}
	}

	if strings.TrimSpace(cfg.Address) == "" {
		return Config{}, fmt.Errorf("state.redis.address is required")
	}

	return cfg, nil
}
