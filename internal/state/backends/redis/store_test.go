package redis

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/davidcollom/komodor-security-reporter/internal/state"
	gocachestore "github.com/eko/gocache/lib/v4/store"
	redisclient "github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPrefix = "test"

func newTestStore(t *testing.T, ttl time.Duration) (*Store, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)
	client := redisclient.NewClient(&redisclient.Options{Addr: mr.Addr()})

	return NewStore(client, testPrefix, ttl), mr
}

func newEntry(fingerprint string) *state.Entry {
	return &state.Entry{
		Fingerprint:     fingerprint,
		LastScannedTime: time.Now().UTC(),
		Summary:         "test finding",
	}
}

func TestStoreGetNotFound(t *testing.T) {
	t.Parallel()

	s, _ := newTestStore(t, time.Hour)

	_, err := s.Get(context.Background(), "missing")
	require.Error(t, err)

	var notFound *gocachestore.NotFound
	require.ErrorAs(t, err, &notFound)
}

func TestStoreSetAndGet(t *testing.T) {
	t.Parallel()

	s, _ := newTestStore(t, time.Hour)
	ctx := context.Background()
	entry := newEntry("fp-1")

	require.NoError(t, s.Set(ctx, "key1", entry))

	got, err := s.Get(ctx, "key1")
	require.NoError(t, err)
	require.NotNil(t, got)

	payload, err := json.Marshal(got)
	require.NoError(t, err)

	decoded := &state.Entry{}
	require.NoError(t, json.Unmarshal(payload, decoded))
	assert.Equal(t, entry.Fingerprint, decoded.Fingerprint)
	assert.Equal(t, entry.Summary, decoded.Summary)
}

func TestStoreDelete(t *testing.T) {
	t.Parallel()

	s, _ := newTestStore(t, time.Hour)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "key1", newEntry("fp-1")))
	require.NoError(t, s.Delete(ctx, "key1"))

	_, err := s.Get(ctx, "key1")
	require.Error(t, err)
}

func TestStoreExpiry(t *testing.T) {
	t.Parallel()

	s, mr := newTestStore(t, 100*time.Millisecond)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "key1", newEntry("fp-1")))

	mr.FastForward(200 * time.Millisecond)

	_, err := s.Get(ctx, "key1")
	require.Error(t, err)

	var notFound *gocachestore.NotFound
	require.ErrorAs(t, err, &notFound)
}

func TestStorePerEntryExpiry(t *testing.T) {
	t.Parallel()

	s, mr := newTestStore(t, time.Hour)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "key1", newEntry("fp-1"), gocachestore.WithExpiration(50*time.Millisecond)))

	mr.FastForward(100 * time.Millisecond)

	_, err := s.Get(ctx, "key1")
	require.Error(t, err)
}

func TestStoreClear(t *testing.T) {
	t.Parallel()

	s, _ := newTestStore(t, time.Hour)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "key1", newEntry("fp-1")))
	require.NoError(t, s.Set(ctx, "key2", newEntry("fp-2")))
	require.NoError(t, s.Clear(ctx))

	_, err := s.Get(ctx, "key1")
	require.Error(t, err)

	_, err = s.Get(ctx, "key2")
	require.Error(t, err)
}

func TestStoreGetWithTTL(t *testing.T) {
	t.Parallel()

	s, _ := newTestStore(t, time.Hour)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "key1", newEntry("fp-1")))

	_, remaining, err := s.GetWithTTL(ctx, "key1")
	require.NoError(t, err)
	assert.Greater(t, remaining, time.Duration(0))
	assert.LessOrEqual(t, remaining, time.Hour)
}

func TestStoreRedisKeyNamespaced(t *testing.T) {
	t.Parallel()

	s, mr := newTestStore(t, time.Hour)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "myimage/sha256:abc123", newEntry("fp-1")))

	keys := mr.Keys()
	require.Len(t, keys, 1)
	assert.Contains(t, keys[0], testPrefix+":state:")
	parts := strings.SplitN(keys[0], ":", 3)
	require.Len(t, parts, 3, "expected prefix:state:<encoded> format")
	assert.NotContains(t, parts[2], "/")
	assert.NotContains(t, parts[2], ":")
}

func TestStoreGetType(t *testing.T) {
	t.Parallel()

	s, _ := newTestStore(t, time.Hour)
	assert.Equal(t, storeType, s.GetType())
}

func TestBackendSetAndGetEntry(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redisclient.NewClient(&redisclient.Options{Addr: mr.Addr()})
	b := NewBackendWithClient(client, testPrefix, time.Hour)
	ctx := context.Background()

	entry := newEntry("fp-backend")
	require.NoError(t, b.SetEntry(ctx, "image/sha:trivy", entry))

	got, err := b.GetEntry(ctx, "image/sha:trivy")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, entry.Fingerprint, got.Fingerprint)
}

func TestBackendGetEntryMissing(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redisclient.NewClient(&redisclient.Options{Addr: mr.Addr()})
	b := NewBackendWithClient(client, testPrefix, time.Hour)

	got, err := b.GetEntry(context.Background(), "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestBackendDeleteEntry(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redisclient.NewClient(&redisclient.Options{Addr: mr.Addr()})
	b := NewBackendWithClient(client, testPrefix, time.Hour)
	ctx := context.Background()

	require.NoError(t, b.SetEntry(ctx, "key", newEntry("fp-del")))
	require.NoError(t, b.DeleteEntry(ctx, "key"))

	got, err := b.GetEntry(ctx, "key")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestNewBackendRequiresAddress(t *testing.T) {
	t.Parallel()

	_, err := ParseConfig(viper.New())
	require.Error(t, err)
	require.Contains(t, err.Error(), "state.redis.address is required")
}
