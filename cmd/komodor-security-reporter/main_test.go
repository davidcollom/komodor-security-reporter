package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewRootCommandDefaults(t *testing.T) {
	configFile = ""
	metricsAddr = ""
	logLevel = ""

	cmd := newRootCommand()

	require.Equal(t, "komodor-security-reporter", cmd.Use)
	require.Equal(t, "/etc/komodor-security-reporter/config.yaml", cmd.Flag("config").DefValue)
	require.Equal(t, ":8081", cmd.Flag("metrics-bind-address").DefValue)
	require.Equal(t, "info", cmd.Flag("log-level").DefValue)
}

func TestNewRootCommandParsesFlags(t *testing.T) {
	oldConfigFile := configFile
	oldMetricsAddr := metricsAddr
	oldLogLevel := logLevel

	defer func() {
		configFile = oldConfigFile
		metricsAddr = oldMetricsAddr
		logLevel = oldLogLevel
	}()

	cmd := newRootCommand()
	err := cmd.ParseFlags([]string{
		"--config", "/tmp/config.yaml",
		"--metrics-bind-address", ":9090",
		"--log-level", "debug",
	})

	require.NoError(t, err)
	require.Equal(t, "/tmp/config.yaml", configFile)
	require.Equal(t, ":9090", metricsAddr)
	require.Equal(t, "debug", logLevel)
}

func TestStateStoreNamespaceFromEnv(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "komodor-security-reporter")

	require.Equal(t, "komodor-security-reporter", stateStoreNamespace())
}

func TestStateStoreNamespaceDefaultsToDefault(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "")

	require.Equal(t, "default", stateStoreNamespace())
}
