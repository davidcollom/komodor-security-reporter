package memory

import (
	"context"
	"fmt"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/state"
	gocache "github.com/eko/gocache/lib/v4/cache"
	gocachestore "github.com/eko/gocache/lib/v4/store"
	gocachegostore "github.com/eko/gocache/store/go_cache/v4"
	gocacheclient "github.com/patrickmn/go-cache"
)

const storeType = "memory"

// Store implements gocachestore.StoreInterface with an in-process bounded cache.
// State is not durable — it is lost on process restart. This backend is intended
// for readonly deployments that cannot write to the Kubernetes API.
type Store struct {
	delegate   *gocachegostore.GoCacheStore
	ttl        time.Duration
	maxEntries int // currently advisory only for the go-cache adapter
}

// NewStore creates a new in-process memory store.
func NewStore(ttl time.Duration, maxEntries int) *Store {
	cleanupInterval := time.Minute
	if ttl > 0 {
		cleanupInterval = ttl / 2
		if cleanupInterval <= 0 {
			cleanupInterval = time.Second
		}
	}

	client := gocacheclient.New(ttl, cleanupInterval)

	return &Store{
		delegate:   gocachegostore.NewGoCache(client, gocachestore.WithExpiration(ttl)),
		ttl:        ttl,
		maxEntries: maxEntries,
	}
}

// Get retrieves a state entry by key.
func (s *Store) Get(ctx context.Context, key interface{}) (interface{}, error) {
	return s.delegate.Get(ctx, key)
}

// GetWithTTL retrieves a state entry and the remaining TTL.
func (s *Store) GetWithTTL(ctx context.Context, key interface{}) (interface{}, time.Duration, error) {
	return s.delegate.GetWithTTL(ctx, key)
}

// Set stores a state entry. Per-entry expiration from options is respected;
// if not provided, the store-level TTL applies.
func (s *Store) Set(ctx context.Context, key interface{}, object interface{}, options ...gocachestore.Option) error {
	if _, ok := object.(*state.Entry); !ok {
		return fmt.Errorf("expected *state.Entry, got %T", object)
	}

	return s.delegate.Set(ctx, key, object, options...)
}

// Delete removes a state entry by key.
func (s *Store) Delete(ctx context.Context, key interface{}) error {
	return s.delegate.Delete(ctx, key)
}

// Invalidate is not supported by the memory backend.
func (s *Store) Invalidate(ctx context.Context, options ...gocachestore.InvalidateOption) error {
	return s.delegate.Invalidate(ctx, options...)
}

// Clear removes all entries from the in-process memory store.
func (s *Store) Clear(ctx context.Context) error {
	return s.delegate.Clear(ctx)
}

// GetType returns the backend store type.
func (s *Store) GetType() string {
	return storeType
}

// Backend wraps the in-process memory store in the state.Backend interface.
// State is not durable and will be lost on process restart.
type Backend struct {
	cache gocache.CacheInterface[*state.Entry]
	ttl   time.Duration
}

// NewBackend creates an in-process state.Backend.
// maxEntries caps the number of live entries; 0 means unlimited.
func NewBackend(ttl time.Duration, maxEntries int) *Backend {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	store := NewStore(ttl, maxEntries)
	cache := gocache.New[*state.Entry](store)

	return &Backend{cache: cache, ttl: ttl}
}

// GetEntry retrieves an entry from the backend.
func (b *Backend) GetEntry(ctx context.Context, key string) (*state.Entry, error) {
	entry, err := b.cache.Get(ctx, key)
	if err != nil {
		if _, ok := err.(*gocachestore.NotFound); ok {
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
