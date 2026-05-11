package configmap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/state"
	gocache "github.com/eko/gocache/lib/v4/cache"
	gocachestore "github.com/eko/gocache/lib/v4/store"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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

	entry, err := parseStateEntry(data)
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

	cm, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.configMap, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			cm = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      s.configMap,
					Namespace: s.namespace,
				},
				Data: make(map[string]string),
			}

			_, err := s.client.CoreV1().ConfigMaps(s.namespace).Create(ctx, cm, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("create configmap: %w", err)
			}
		} else {
			return fmt.Errorf("get configmap: %w", err)
		}
	}

	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}

	cm.Data[storageKey] = formatStateEntry(entry)

	_, err = s.client.CoreV1().ConfigMaps(s.namespace).Update(ctx, cm, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("update configmap: %w", err)
	}

	return nil
}

// Delete removes a state entry from ConfigMap.
func (s *Store) Delete(ctx context.Context, key interface{}) error {
	keyStr, ok := key.(string)
	if !ok {
		return fmt.Errorf("expected string key, got %T", key)
	}

	storageKey := configMapDataKey(keyStr)

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

type serializedStateEntry struct {
	Fingerprint       string `json:"fingerprint"`
	LastScannedTime   int64  `json:"lastScannedTime"`
	LastPublishedTime int64  `json:"lastPublishedTime"`
	Summary           string `json:"summary"`
}

func parseStateEntry(data string) (*state.Entry, error) {
	var serialized serializedStateEntry
	if err := json.Unmarshal([]byte(data), &serialized); err == nil {
		entry := &state.Entry{Fingerprint: serialized.Fingerprint, Summary: serialized.Summary}
		if serialized.LastScannedTime > 0 {
			entry.LastScannedTime = time.Unix(serialized.LastScannedTime, 0).UTC()
		}

		if serialized.LastPublishedTime > 0 {
			entry.LastPublishedTime = time.Unix(serialized.LastPublishedTime, 0).UTC()
		}

		return entry, nil
	}

	parts := strings.SplitN(data, "|", 4)
	if len(parts) == 4 {
		entry := &state.Entry{Fingerprint: parts[0], Summary: parts[3]}

		scanned, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse scanned unix timestamp: %w", err)
		}

		published, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse published unix timestamp: %w", err)
		}

		if scanned > 0 {
			entry.LastScannedTime = time.Unix(scanned, 0).UTC()
		}

		if published > 0 {
			entry.LastPublishedTime = time.Unix(published, 0).UTC()
		}

		return entry, nil
	}

	return &state.Entry{Fingerprint: data}, nil
}

func formatStateEntry(entry *state.Entry) string {
	payload := serializedStateEntry{
		Fingerprint: entry.Fingerprint,
		Summary:     entry.Summary,
	}
	if !entry.LastScannedTime.IsZero() {
		payload.LastScannedTime = entry.LastScannedTime.Unix()
	}

	if !entry.LastPublishedTime.IsZero() {
		payload.LastPublishedTime = entry.LastPublishedTime.Unix()
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf("%s|%d|%d|%s",
			entry.Fingerprint,
			entry.LastScannedTime.Unix(),
			entry.LastPublishedTime.Unix(),
			entry.Summary,
		)
	}

	return string(data)
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
		if isCacheNotFound(err) {
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

func isCacheNotFound(err error) bool {
	if err == nil {
		return false
	}

	_, ok := err.(*gocachestore.NotFound)

	return ok
}
