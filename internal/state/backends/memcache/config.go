package memcache

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// Config defines Memcache backend-specific state settings.
type Config struct {
	Address      string        `mapstructure:"address"`
	KeyPrefix    string        `mapstructure:"keyPrefix"`
	Timeout      time.Duration `mapstructure:"timeout"`
	MaxIdleConns int           `mapstructure:"maxIdleConns"`
}

// ParseConfig decodes Memcache backend settings from a scoped state viper config.
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
			return Config{}, fmt.Errorf("decode memcache state config: %w", err)
		}
	}

	if cfg.Address == "" && scopedConfig != nil {
		cfg.Address = scopedConfig.GetString("memcache.address")
	}

	if strings.TrimSpace(cfg.Address) == "" {
		return Config{}, fmt.Errorf("state.memcache.address is required")
	}

	return cfg, nil
}
