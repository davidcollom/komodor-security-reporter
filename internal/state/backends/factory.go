package backends

import (
	"fmt"

	"github.com/davidcollom/komodor-security-reporter/internal/config"
	"github.com/davidcollom/komodor-security-reporter/internal/state"
	stateconfigmap "github.com/davidcollom/komodor-security-reporter/internal/state/backends/configmap"
	statememcache "github.com/davidcollom/komodor-security-reporter/internal/state/backends/memcache"
	statememory "github.com/davidcollom/komodor-security-reporter/internal/state/backends/memory"
	stateredis "github.com/davidcollom/komodor-security-reporter/internal/state/backends/redis"
	"github.com/spf13/viper"
	"k8s.io/client-go/kubernetes"
)

// New creates a state backend from the given StateConfig.
// resolvedNamespace is the Kubernetes namespace used for the ConfigMap backend; it
// may be derived from the POD_NAMESPACE environment variable or the config value.
func New(cfg config.StateConfig, scopedConfig *viper.Viper, resolvedNamespace string, clientset kubernetes.Interface) (state.Backend, error) {
	switch config.NormalizeStateBackend(cfg.Backend) {
	case config.StateBackendConfigMap:
		backendCfg, err := stateconfigmap.ParseConfig(scopedConfig)
		if err != nil {
			return nil, err
		}

		return stateconfigmap.NewBackend(clientset, resolvedNamespace, backendCfg.ConfigMapName, cfg.TTL), nil
	case config.StateBackendMemory:
		backendCfg, err := statememory.ParseConfig(scopedConfig)
		if err != nil {
			return nil, err
		}

		return statememory.NewBackend(cfg.TTL, backendCfg.MaxEntries), nil
	case config.StateBackendRedis:
		backendCfg, err := stateredis.ParseConfig(scopedConfig)
		if err != nil {
			return nil, err
		}

		return stateredis.NewBackend(backendCfg, cfg.TTL)
	case config.StateBackendMemcache:
		backendCfg, err := statememcache.ParseConfig(scopedConfig)
		if err != nil {
			return nil, err
		}

		return statememcache.NewBackend(backendCfg, cfg.TTL)
	default:
		return nil, fmt.Errorf("unsupported state backend: %s", cfg.Backend)
	}
}
