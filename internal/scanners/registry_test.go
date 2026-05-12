package scanners

import (
	"context"
	"testing"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

type testScanner struct{}

func (s *testScanner) Name() string { return "test" }

func (s *testScanner) Scan(_ context.Context, _ ImageRef) (*ScanResult, error) { return nil, nil }

func TestCreateScannerRegistryIncludesTimeoutOverrides(t *testing.T) {
	const scannerType = "test-path-fallback"

	override := 42 * time.Second

	RegisterScanner(scannerType, func(scannerCfg config.ScannerConfig, scopedConfig *viper.Viper, log logrus.FieldLogger) (Scanner, *time.Duration, error) {
		return &testScanner{}, &override, nil
	})

	registry, timeouts, err := CreateScannerRegistry([]config.ScannerConfig{{
		Name:    "test",
		Type:    scannerType,
		Enabled: true,
	}}, nil, logrus.New())

	require.NoError(t, err)
	require.Len(t, registry, 1)
	require.Equal(t, override, timeouts["test"])
}
