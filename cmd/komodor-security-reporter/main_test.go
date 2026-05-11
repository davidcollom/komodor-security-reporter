package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/config"
	appversion "github.com/davidcollom/komodor-security-reporter/internal/version"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"
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
	versionCmd, _, err := cmd.Find([]string{"version"})
	require.NoError(t, err)
	require.NotNil(t, versionCmd)
	require.Equal(t, "version", versionCmd.Name())
}

func TestVersionCommandOutput(t *testing.T) {
	oldVersion := appversion.Version
	oldCommit := appversion.Commit
	oldDate := appversion.Date

	t.Cleanup(func() {
		appversion.Version = oldVersion
		appversion.Commit = oldCommit
		appversion.Date = oldDate
	})

	appversion.Version = "1.2.3"
	appversion.Commit = "abcdef0"
	appversion.Date = "2026-05-11"

	cmd := newRootCommand()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"version"})

	err := cmd.Execute()
	require.NoError(t, err)
	require.Equal(t, "version=1.2.3 commit=abcdef0 date=2026-05-11\n", buf.String())
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

func TestStateStoreNamespacePrefersEnvVar(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "from-env")

	ns := stateStoreNamespace("from-config")

	require.Equal(t, "from-env", ns)
}

func TestStateStoreNamespaceFallsBackToConfig(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "")

	ns := stateStoreNamespace("from-config")

	require.Equal(t, "from-config", ns)
}

func TestStateStoreNamespaceDefaultsToDefault(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "")

	ns := stateStoreNamespace("")

	require.Equal(t, "default", ns)
}

func TestBuildStateStoreConfigMapBackend(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	cfg := &config.Config{
		State: config.StateConfig{
			Backend: config.StateBackendConfigMap,
			TTL:     72 * time.Hour,
		},
	}

	store, err := buildStateStore(cfg, clientset, "default")

	require.NoError(t, err)
	require.NotNil(t, store)
}

func TestBuildStateStoreMemoryBackend(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	cfg := &config.Config{
		State: config.StateConfig{
			Backend: config.StateBackendMemory,
			TTL:     72 * time.Hour,
		},
	}

	store, err := buildStateStore(cfg, clientset, "default")

	require.Error(t, err)
	require.Nil(t, store)
	require.Contains(t, err.Error(), "use gocache's native memory store")
}

func TestBuildStateStoreExternalBackendNotImplemented(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	cfg := &config.Config{
		State: config.StateConfig{
			Backend: config.StateBackendExternal,
			TTL:     72 * time.Hour,
		},
	}

	_, err := buildStateStore(cfg, clientset, "default")

	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}
