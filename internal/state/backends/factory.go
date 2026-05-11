package backends

import (
	"fmt"

	"github.com/davidcollom/komodor-security-reporter/internal/config"
	"github.com/davidcollom/komodor-security-reporter/internal/state"
	stateconfigmap "github.com/davidcollom/komodor-security-reporter/internal/state/backends/configmap"
	statememcache "github.com/davidcollom/komodor-security-reporter/internal/state/backends/memcache"
	statememory "github.com/davidcollom/komodor-security-reporter/internal/state/backends/memory"
	stateredis "github.com/davidcollom/komodor-security-reporter/internal/state/backends/redis"
	"k8s.io/client-go/kubernetes"
)

// defaultConfigMapName is the Kubernetes ConfigMap used for durable state storage.
const defaultConfigMapName = "komodor-security-reporter-state"

// New creates a state backend from the given StateConfig.
// resolvedNamespace is the Kubernetes namespace used for the ConfigMap backend; it
// may be derived from the POD_NAMESPACE environment variable or the config value.
func New(cfg config.StateConfig, resolvedNamespace string, clientset kubernetes.Interface) (state.Backend, error) {
	switch config.NormalizeStateBackend(cfg.Backend) {
	case config.StateBackendConfigMap:
		return stateconfigmap.NewBackend(clientset, resolvedNamespace, defaultConfigMapName, cfg.TTL), nil
	case config.StateBackendMemory:
		return statememory.NewBackend(cfg.TTL, cfg.Memory.MaxEntries), nil
	case config.StateBackendRedis:
		return stateredis.NewBackend(cfg.Redis, cfg.TTL)
	case config.StateBackendMemcache:
		return statememcache.NewBackend(cfg.Memcache, cfg.TTL)
	default:
		return nil, fmt.Errorf("unsupported state backend: %s", cfg.Backend)
	}
}
