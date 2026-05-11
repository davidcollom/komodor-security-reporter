package memcache

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/davidcollom/komodor-security-reporter/internal/config"
	"github.com/davidcollom/komodor-security-reporter/internal/state"
	gocachestore "github.com/eko/gocache/lib/v4/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeItem struct {
	value     []byte
	expiresAt time.Time
}

type fakeMemcacheClient struct {
	mu    sync.Mutex
	items map[string]fakeItem
}

func newFakeMemcacheClient() *fakeMemcacheClient {
	return &fakeMemcacheClient{items: make(map[string]fakeItem)}
}

func (f *fakeMemcacheClient) Get(key string) (*memcache.Item, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	item, ok := f.items[key]
	if !ok {
		return nil, memcache.ErrCacheMiss
	}

	if !item.expiresAt.IsZero() && time.Now().After(item.expiresAt) {
		delete(f.items, key)
		return nil, memcache.ErrCacheMiss
	}

	return &memcache.Item{Key: key, Value: append([]byte(nil), item.value...)}, nil
}

func (f *fakeMemcacheClient) Set(item *memcache.Item) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	var expiresAt time.Time
	if item.Expiration > 0 {
		expiresAt = time.Now().Add(time.Duration(item.Expiration) * time.Second)
	}

	f.items[item.Key] = fakeItem{value: append([]byte(nil), item.Value...), expiresAt: expiresAt}

	return nil
}

func (f *fakeMemcacheClient) Delete(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.items[key]; !ok {
		return memcache.ErrCacheMiss
	}

	delete(f.items, key)

	return nil
}

func newEntry(fingerprint string) *state.Entry {
	return &state.Entry{
		Fingerprint:     fingerprint,
		LastScannedTime: time.Now().UTC(),
		Summary:         "test finding",
	}
}

func TestStoreSetAndGet(t *testing.T) {
	t.Parallel()

	client := newFakeMemcacheClient()
	s := NewStore(client, "test", time.Hour)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "key1", newEntry("fp-1")))

	got, err := s.Get(ctx, "key1")
	require.NoError(t, err)
	require.NotNil(t, got)

	payload, err := json.Marshal(got)
	require.NoError(t, err)

	entry := &state.Entry{}
	require.NoError(t, json.Unmarshal(payload, entry))
	assert.Equal(t, "fp-1", entry.Fingerprint)
}

func TestStoreGetNotFound(t *testing.T) {
	t.Parallel()

	s := NewStore(newFakeMemcacheClient(), "test", time.Hour)

	_, err := s.Get(context.Background(), "missing")
	require.Error(t, err)

	var notFound *gocachestore.NotFound
	require.ErrorAs(t, err, &notFound)
}

func TestStoreDelete(t *testing.T) {
	t.Parallel()

	client := newFakeMemcacheClient()
	s := NewStore(client, "test", time.Hour)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "key1", newEntry("fp-1")))
	require.NoError(t, s.Delete(ctx, "key1"))

	_, err := s.Get(ctx, "key1")
	require.Error(t, err)
}

func TestStorePerEntryExpiry(t *testing.T) {
	t.Parallel()

	client := newFakeMemcacheClient()
	s := NewStore(client, "test", time.Hour)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "key1", newEntry("fp-1"), gocachestore.WithExpiration(time.Second)))
	time.Sleep(1100 * time.Millisecond)

	_, err := s.Get(ctx, "key1")
	require.Error(t, err)
}

func TestStoreGetType(t *testing.T) {
	t.Parallel()

	s := NewStore(newFakeMemcacheClient(), "test", time.Hour)
	assert.Equal(t, storeType, s.GetType())
}

func TestStoreKeyEncoding(t *testing.T) {
	t.Parallel()

	s := NewStore(newFakeMemcacheClient(), "prefix", time.Hour)
	key := s.memcacheKey("myimage/sha256:abcd")

	assert.True(t, strings.HasPrefix(key, "prefix:state:"))
	assert.NotContains(t, key, "myimage/sha256:abcd")
}

func TestStoreClearNotSupported(t *testing.T) {
	t.Parallel()

	s := NewStore(newFakeMemcacheClient(), "test", time.Hour)
	err := s.Clear(context.Background())
	require.Error(t, err)
}

func TestDurationToMemcacheExpiration(t *testing.T) {
	t.Parallel()

	assert.Equal(t, int32(0), durationToMemcacheExpiration(0))
	assert.Equal(t, int32(1), durationToMemcacheExpiration(500*time.Millisecond))
	assert.Equal(t, int32(5), durationToMemcacheExpiration(5*time.Second))
}

func TestBackendSetGetDelete(t *testing.T) {
	t.Parallel()

	client := newFakeMemcacheClient()
	backend := NewBackendWithClient(client, "test", time.Hour)
	ctx := context.Background()

	require.NoError(t, backend.SetEntry(ctx, "k1", newEntry("fp-1")))
	got, err := backend.GetEntry(ctx, "k1")
	require.NoError(t, err)
	require.NotNil(t, got)

	require.NoError(t, backend.DeleteEntry(ctx, "k1"))
	got, err = backend.GetEntry(ctx, "k1")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestNewBackendRequiresAddress(t *testing.T) {
	t.Parallel()

	_, err := NewBackend(config.MemcacheConfig{}, time.Hour)
	require.Error(t, err)
	require.Contains(t, err.Error(), "state.memcache.address is required")
}

func TestBackendGetEntryPropagatesErrors(t *testing.T) {
	t.Parallel()

	client := &errorMemcacheClient{}
	backend := NewBackendWithClient(client, "test", time.Hour)

	_, err := backend.GetEntry(context.Background(), "k1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "memcache get")
}

type errorMemcacheClient struct{}

func (e *errorMemcacheClient) Get(key string) (*memcache.Item, error) {
	return nil, fmt.Errorf("boom")
}

func (e *errorMemcacheClient) Set(item *memcache.Item) error {
	return fmt.Errorf("boom")
}

func (e *errorMemcacheClient) Delete(key string) error {
	return fmt.Errorf("boom")
}
