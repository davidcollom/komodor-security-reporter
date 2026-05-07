package scanners

import (
	"context"
	"testing"

	"github.com/davidcollom/komodor-security-reporter/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type testScanner struct{}

func (s *testScanner) Name() string { return "test" }

func (s *testScanner) Scan(_ context.Context, _ ImageRef) (*ScanResult, error) { return nil, nil }

func TestCreateScannerRegistryDefaultsBinaryToScannerType(t *testing.T) {
	const scannerType = "test-path-fallback"

	var gotBinary string

	RegisterScanner(scannerType, func(scannerCfg config.ScannerConfig, binaryPath string, log logrus.FieldLogger) (Scanner, error) {
		gotBinary = binaryPath
		return &testScanner{}, nil
	})

	registry, err := CreateScannerRegistry([]config.ScannerConfig{{
		Name:    "test",
		Type:    scannerType,
		Enabled: true,
	}}, logrus.New())

	require.NoError(t, err)
	require.Len(t, registry, 1)
	require.Equal(t, scannerType, gotBinary)
}
