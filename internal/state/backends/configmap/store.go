package configmap

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/state"
	gocache "github.com/eko/gocache/lib/v4/cache"
	gocachestore "github.com/eko/gocache/lib/v4/store"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
)

// Store implements gocachestore.StoreInterface for ConfigMap-backed persistence.
// This is a pure gocache store that persists state entries to Kubernetes ConfigMaps.
type Store struct {
	client    kubernetes.Interface
	namespace string
	configMap string
	ttl       time.Duration
}

// NewStore creates a new ConfigMap-backed gocache store.
func NewStore(client kubernetes.Interface, namespace, configMapName string, ttl time.Duration) *Store {
	return &Store{
		client:    client,
		namespace: namespace,
		configMap: configMapName,
		ttl:       ttl,
	}
}

// Get retrieves a state entry from ConfigMap.
func (s *Store) Get(ctx context.Context, key interface{}) (interface{}, error) {
	keyStr, ok := key.(string)
	if !ok {
		return nil, &gocachestore.NotFound{}
	}

	storageKey := configMapDataKey(keyStr)

	cm, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.configMap, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, &gocachestore.NotFound{}
		}

		return nil, fmt.Errorf("get configmap: %w", err)
	}

	data, ok := cm.Data[storageKey]
	if !ok {
		return nil, &gocachestore.NotFound{}
	}

	entry := &state.Entry{}

	err = entry.Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("parse state entry for key %s: %w", keyStr, err)
	}

	if s.isExpired(entry, time.Now()) {
		_ = s.Delete(ctx, key)
		return nil, &gocachestore.NotFound{}
	}

	return entry, nil
}

// GetWithTTL retrieves a state entry and its TTL from ConfigMap.
func (s *Store) GetWithTTL(ctx context.Context, key interface{}) (interface{}, time.Duration, error) {
	entry, err := s.Get(ctx, key)
	if err != nil {
		return nil, 0, err
	}

	// ConfigMap doesn't track individual entry TTLs, so return the configured TTL
	return entry, s.ttl, nil
}

// Set stores a state entry in ConfigMap.
// Note: the options parameter (including per-entry expiration) is not supported by
// the ConfigMap backend; the TTL configured at construction is always used for expiry.
func (s *Store) Set(ctx context.Context, key interface{}, object interface{}, options ...gocachestore.Option) error {
	keyStr, ok := key.(string)
	if !ok {
		return fmt.Errorf("expected string key, got %T", key)
	}

	entry, ok := object.(*state.Entry)
	if !ok {
		return fmt.Errorf("expected *state.Entry, got %T", object)
	}

	storageKey := configMapDataKey(keyStr)

	value, err := entry.Marshal()
	if err != nil {
		return fmt.Errorf("serialise state entry: %w", err)
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cm, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.configMap, metav1.GetOptions{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("get configmap: %w", err)
			}
			// ConfigMap does not exist yet — create it with the entry already set so
			// we do not need a subsequent Update (which would fail without resourceVersion).
			cm = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      s.configMap,
					Namespace: s.namespace,
				},
				Data: map[string]string{storageKey: value},
			}
			if _, err := s.client.CoreV1().ConfigMaps(s.namespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
				return fmt.Errorf("create configmap: %w", err)
			}

			return nil
		}

		if cm.Data == nil {
			cm.Data = make(map[string]string)
		}

		cm.Data[storageKey] = value

		if _, err = s.client.CoreV1().ConfigMaps(s.namespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update configmap: %w", err)
		}

		return nil
	})
}

// Delete removes a state entry from ConfigMap.
func (s *Store) Delete(ctx context.Context, key interface{}) error {
	keyStr, ok := key.(string)
	if !ok {
		return fmt.Errorf("expected string key, got %T", key)
	}

	storageKey := configMapDataKey(keyStr)

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cm, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.configMap, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}

			return fmt.Errorf("get configmap: %w", err)
		}

		if cm.Data == nil {
			return nil
		}

		if _, ok := cm.Data[storageKey]; !ok {
			return nil
		}

		delete(cm.Data, storageKey)

		if _, err := s.client.CoreV1().ConfigMaps(s.namespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update configmap: %w", err)
		}

		return nil
	})
}

// Clear removes all entries from ConfigMap (not safely supported).
func (s *Store) Clear(ctx context.Context) error {
	return fmt.Errorf("Clear not supported for ConfigMap backend")
}

// Invalidate removes entries by tag (not supported for ConfigMap).
func (s *Store) Invalidate(ctx context.Context, options ...gocachestore.InvalidateOption) error {
	return fmt.Errorf("Invalidate not supported for ConfigMap backend")
}

// GetType returns the store type.
func (s *Store) GetType() string {
	return "configmap"
}

func configMapDataKey(key string) string {
	return "state_" + base64.RawURLEncoding.EncodeToString([]byte(key))
}

func (s *Store) isExpired(entry *state.Entry, now time.Time) bool {
	if entry == nil || s.ttl <= 0 || entry.LastScannedTime.IsZero() {
		return false
	}

	return now.After(entry.LastScannedTime.Add(s.ttl))
}

// Backend wraps a gocache cache backed by ConfigMap into the state.Backend interface.
type Backend struct {
	cache gocache.CacheInterface[*state.Entry]
	ttl   time.Duration
}

// NewBackend creates a state.Backend using ConfigMap as the persistent gocache store.
// This consolidates Store (StoreInterface) → gocache.New → state.Backend in one factory.
func NewBackend(client kubernetes.Interface, namespace, configMapName string, ttl time.Duration) *Backend {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	// ConfigMap store implements gocachestore.StoreInterface directly
	store := NewStore(client, namespace, configMapName, ttl)

	// Wrap in gocache cache with type-safe interface
	cache := gocache.New[*state.Entry](store)

	// Return wrapped in state.Backend interface
	return &Backend{cache: cache, ttl: ttl}
}

// GetEntry retrieves an entry from the cache.
func (b *Backend) GetEntry(ctx context.Context, key string) (*state.Entry, error) {
	entry, err := b.cache.Get(ctx, key)
	if err != nil {
		if state.IsCacheNotFound(err) {
			return nil, nil
		}

		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	return entry, nil
}

// SetEntry stores an entry in the cache.
func (b *Backend) SetEntry(ctx context.Context, key string, entry *state.Entry) error {
	if entry == nil {
		return nil
	}

	options := []gocachestore.Option{gocachestore.WithCost(1)}
	if b.ttl > 0 {
		options = append(options, gocachestore.WithExpiration(b.ttl))
	}

	return b.cache.Set(ctx, key, entry, options...)
}

// DeleteEntry removes an entry from the cache.
func (b *Backend) DeleteEntry(ctx context.Context, key string) error {
	return b.cache.Delete(ctx, key)
}
