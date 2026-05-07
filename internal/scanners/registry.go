package scanners

import (
	"fmt"

	"github.com/davidcollom/komodor-security-reporter/internal/config"
	"github.com/sirupsen/logrus"
)

// ScannerFactory creates a scanner from configuration.
type ScannerFactory func(name string, binaryPath string, log logrus.FieldLogger) (Scanner, error)

var scannerFactories = make(map[string]ScannerFactory)

// RegisterScanner registers a scanner factory.
func RegisterScanner(scannerType string, factory ScannerFactory) {
	scannerFactories[scannerType] = factory
}

// CreateScannerRegistry creates a scanner registry from configuration.
func CreateScannerRegistry(scannerConfigs []config.ScannerConfig, log logrus.FieldLogger) (map[string]Scanner, error) {
	registry := make(map[string]Scanner)

	for _, scannerCfg := range scannerConfigs {
		if !scannerCfg.Enabled {
			continue
		}

		factory, ok := scannerFactories[scannerCfg.Type]
		if !ok {
			log.Warnf("scanner type not registered: %s", scannerCfg.Type)
			continue
		}

		binaryPath := scannerCfg.Command.Binary
		if binaryPath == "" {
			binaryPath = scannerCfg.Type
		}

		scanner, err := factory(scannerCfg.Name, binaryPath, log)
		if err != nil {
			return nil, fmt.Errorf("create scanner %s (%s): %w", scannerCfg.Name, scannerCfg.Type, err)
		}

		registry[scannerCfg.Name] = scanner
	}

	return registry, nil
}
