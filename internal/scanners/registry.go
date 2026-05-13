package scanners

import (
	"fmt"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// ScannerFactory creates a scanner from configuration.
type ScannerFactory func(scannerCfg config.ScannerConfig, scopedConfig *viper.Viper, log logrus.FieldLogger) (Scanner, *time.Duration, error)

var scannerFactories = make(map[string]ScannerFactory)

// RegisterScanner registers a scanner factory.
func RegisterScanner(scannerType string, factory ScannerFactory) {
	scannerFactories[scannerType] = factory
}

// CreateScannerRegistry creates a scanner registry from configuration.
func CreateScannerRegistry(scannerConfigs []config.ScannerConfig, scannerScopes []*viper.Viper, log logrus.FieldLogger) (map[string]Scanner, map[string]time.Duration, error) {
	registry := make(map[string]Scanner)
	timeoutOverrides := make(map[string]time.Duration)

	for i := range scannerConfigs {
		scannerCfg := scannerConfigs[i]
		if !scannerCfg.Enabled {
			continue
		}

		factory, ok := scannerFactories[scannerCfg.Type]
		if !ok {
			log.Warnf("scanner type not registered: %s", scannerCfg.Type)
			continue
		}

		var scope *viper.Viper
		if i < len(scannerScopes) {
			scope = scannerScopes[i]
		}

		scanner, timeoutOverride, err := factory(scannerCfg, scope, log)
		if err != nil {
			return nil, nil, fmt.Errorf("create scanner %s (%s): %w", scannerCfg.Name, scannerCfg.Type, err)
		}

		registry[scannerCfg.Name] = scanner
		if timeoutOverride != nil {
			timeoutOverrides[scannerCfg.Name] = *timeoutOverride
		}
	}

	return registry, timeoutOverrides, nil
}
