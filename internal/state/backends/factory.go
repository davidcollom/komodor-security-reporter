package backends

import (
	"fmt"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/state"
	stateconfigmap "github.com/davidcollom/komodor-security-reporter/internal/state/backends/configmap"
	"k8s.io/client-go/kubernetes"
)

const (
	backendConfigMap = "configmap"
	backendMemory    = "memory"
	backendExternal  = "external"
)

// New creates a state backend from a backend name and common backend settings.
func New(backend string, clientset kubernetes.Interface, namespace, configMapName string, ttl time.Duration) (state.Backend, error) {
	switch backend {
	case backendConfigMap:
		return stateconfigmap.NewBackend(clientset, namespace, configMapName, ttl), nil
	case backendMemory:
		return nil, fmt.Errorf("state backend %q: use gocache's native memory store (Redis, etc.) when ready", backendMemory)
	case backendExternal:
		return nil, fmt.Errorf("state backend %q is not implemented yet", backendExternal)
	default:
		return nil, fmt.Errorf("unsupported state backend: %s", backend)
	}
}
