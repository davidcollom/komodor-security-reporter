package memcache

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/davidcollom/komodor-security-reporter/internal/state"
	gocache "github.com/eko/gocache/lib/v4/cache"
	gocachestore "github.com/eko/gocache/lib/v4/store"
)

const storeType = "memcache"

type memcacheClient interface {
	Get(key string) (*memcache.Item, error)
	Set(item *memcache.Item) error
	Delete(key string) error
}

// Store implements gocachestore.StoreInterface for Memcache-backed persistence.
type Store struct {
	client    memcacheClient
	keyPrefix string
	ttl       time.Duration
}

// NewStore creates a Memcache-backed gocache store.
func NewStore(client memcacheClient, keyPrefix string, ttl time.Duration) *Store {
	return &Store{client: client, keyPrefix: keyPrefix, ttl: ttl}
}

func (s *Store) memcacheKey(key string) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(key))
	return fmt.Sprintf("%s:state:%s", s.keyPrefix, encoded)
}

// Get retrieves a state entry by key.
func (s *Store) Get(ctx context.Context, key interface{}) (interface{}, error) {
	keyStr, ok := key.(string)
	if !ok {
		return nil, &gocachestore.NotFound{}
	}

	item, err := s.client.Get(s.memcacheKey(keyStr))
	if err != nil {
		if err == memcache.ErrCacheMiss {
			return nil, &gocachestore.NotFound{}
		}

		return nil, fmt.Errorf("memcache get: %w", err)
	}

	entry := &state.Entry{}

	err = entry.Unmarshal(string(item.Value))
	if err != nil {
		return nil, fmt.Errorf("parse state entry: %w", err)
	}

	return entry, nil
}

// GetWithTTL retrieves a state entry and the configured store TTL.
func (s *Store) GetWithTTL(ctx context.Context, key interface{}) (interface{}, time.Duration, error) {
	entry, err := s.Get(ctx, key)
	if err != nil {
		return nil, 0, err
	}

	// Memcache does not provide remaining TTL on reads.
	return entry, s.ttl, nil
}

// Set stores a state entry. Per-entry expiration from options is respected;
// if not provided, the store-level TTL applies.
func (s *Store) Set(ctx context.Context, key interface{}, object interface{}, options ...gocachestore.Option) error {
	keyStr, ok := key.(string)
	if !ok {
		return fmt.Errorf("expected string key, got %T", key)
	}

	entry, ok := object.(*state.Entry)
	if !ok {
		return fmt.Errorf("expected *state.Entry, got %T", object)
	}

	applied := gocachestore.ApplyOptions(options...)

	expiry := s.ttl
	if applied.Expiration > 0 {
		expiry = applied.Expiration
	}

	data, err := entry.Marshal()
	if err != nil {
		return fmt.Errorf("serialise state entry: %w", err)
	}

	item := &memcache.Item{
		Key:        s.memcacheKey(keyStr),
		Value:      []byte(data),
		Expiration: durationToMemcacheExpiration(expiry),
	}

	if err := s.client.Set(item); err != nil {
		return fmt.Errorf("memcache set: %w", err)
	}

	return nil
}

// Delete removes a state entry by key.
func (s *Store) Delete(ctx context.Context, key interface{}) error {
	keyStr, ok := key.(string)
	if !ok {
		return fmt.Errorf("expected string key, got %T", key)
	}

	if err := s.client.Delete(s.memcacheKey(keyStr)); err != nil && err != memcache.ErrCacheMiss {
		return fmt.Errorf("memcache delete: %w", err)
	}

	return nil
}

// Invalidate is not supported by the Memcache backend.
func (s *Store) Invalidate(ctx context.Context, options ...gocachestore.InvalidateOption) error {
	return fmt.Errorf("Invalidate not supported for Memcache backend")
}

// Clear is not supported by the Memcache backend.
func (s *Store) Clear(ctx context.Context) error {
	return fmt.Errorf("Clear not supported for Memcache backend")
}

// GetType returns the backend store type.
func (s *Store) GetType() string {
	return storeType
}

func durationToMemcacheExpiration(d time.Duration) int32 {
	if d <= 0 {
		return 0
	}

	seconds := d / time.Second
	if seconds <= 0 {
		return 1
	}

	if seconds > time.Duration(math.MaxInt32) {
		return math.MaxInt32
	}

	return int32(seconds)
}

// Backend wraps the Memcache store in the state.Backend interface.
type Backend struct {
	cache gocache.CacheInterface[*state.Entry]
	ttl   time.Duration
}

// NewBackend creates a Memcache-backed state.Backend from the given config.
func NewBackend(cfg Config, ttl time.Duration) (*Backend, error) {
	client := memcache.New(cfg.Address)
	if cfg.Timeout > 0 {
		client.Timeout = cfg.Timeout
	}

	if cfg.MaxIdleConns > 0 {
		client.MaxIdleConns = cfg.MaxIdleConns
	}

	store := NewStore(client, cfg.KeyPrefix, ttl)
	cache := gocache.New[*state.Entry](store)

	return &Backend{cache: cache, ttl: ttl}, nil
}

// NewBackendWithClient creates a Memcache-backed state.Backend using a pre-built client.
func NewBackendWithClient(client memcacheClient, keyPrefix string, ttl time.Duration) *Backend {
	store := NewStore(client, keyPrefix, ttl)
	cache := gocache.New[*state.Entry](store)

	return &Backend{cache: cache, ttl: ttl}
}

// GetEntry retrieves an entry from the backend.
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

// SetEntry stores an entry in the backend.
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

// DeleteEntry removes an entry from the backend.
func (b *Backend) DeleteEntry(ctx context.Context, key string) error {
	return b.cache.Delete(ctx, key)
}
