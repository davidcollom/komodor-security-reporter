package memory

import (
	"context"
	"testing"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/state"
	gocachestore "github.com/eko/gocache/lib/v4/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newEntry(fingerprint string) *state.Entry {
	return &state.Entry{
		Fingerprint:     fingerprint,
		LastScannedTime: time.Now().UTC(),
		Summary:         "test",
	}
}

func TestStoreGetNotFound(t *testing.T) {
	t.Parallel()

	s := NewStore(time.Hour, 0)

	_, err := s.Get(context.Background(), "missing")
	require.Error(t, err)

	var notFound *gocachestore.NotFound
	require.ErrorAs(t, err, &notFound)
}

func TestStoreSetAndGet(t *testing.T) {
	t.Parallel()

	s := NewStore(time.Hour, 0)
	ctx := context.Background()
	entry := newEntry("fp-1")

	require.NoError(t, s.Set(ctx, "key1", entry))

	got, err := s.Get(ctx, "key1")
	require.NoError(t, err)
	require.Equal(t, entry, got)
}

func TestStoreDelete(t *testing.T) {
	t.Parallel()

	s := NewStore(time.Hour, 0)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "key1", newEntry("fp-1")))
	require.NoError(t, s.Delete(ctx, "key1"))

	_, err := s.Get(ctx, "key1")
	require.Error(t, err)
}

func TestStoreExpiry(t *testing.T) {
	t.Parallel()

	s := NewStore(10*time.Millisecond, 0)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "key1", newEntry("fp-1")))

	time.Sleep(20 * time.Millisecond)

	_, err := s.Get(ctx, "key1")
	require.Error(t, err)

	var notFound *gocachestore.NotFound
	require.ErrorAs(t, err, &notFound)
}

func TestStorePerEntryExpiry(t *testing.T) {
	t.Parallel()

	s := NewStore(time.Hour, 0) // store TTL is 1h
	ctx := context.Background()

	// Override with a short per-entry expiry via options.
	require.NoError(t, s.Set(ctx, "key1", newEntry("fp-1"), gocachestore.WithExpiration(10*time.Millisecond)))

	time.Sleep(20 * time.Millisecond)

	_, err := s.Get(ctx, "key1")
	require.Error(t, err)
}

func TestStoreClear(t *testing.T) {
	t.Parallel()

	s := NewStore(time.Hour, 0)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "key1", newEntry("fp-1")))
	require.NoError(t, s.Set(ctx, "key2", newEntry("fp-2")))
	require.NoError(t, s.Clear(ctx))

	_, err := s.Get(ctx, "key1")
	require.Error(t, err)

	_, err = s.Get(ctx, "key2")
	require.Error(t, err)
}

func TestStoreMaxEntriesParameterIsAccepted(t *testing.T) {
	t.Parallel()

	s := NewStore(time.Hour, 2)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "k1", newEntry("fp-1")))
	require.NoError(t, s.Set(ctx, "k2", newEntry("fp-2")))
	require.NoError(t, s.Set(ctx, "k3", newEntry("fp-3")))

	_, err := s.Get(ctx, "k1")
	assert.NoError(t, err)
	_, err = s.Get(ctx, "k2")
	assert.NoError(t, err)
	_, err = s.Get(ctx, "k3")
	assert.NoError(t, err)
}

func TestStoreGetWithTTL(t *testing.T) {
	t.Parallel()

	s := NewStore(time.Hour, 0)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "key1", newEntry("fp-1")))

	_, remaining, err := s.GetWithTTL(ctx, "key1")
	require.NoError(t, err)
	assert.Greater(t, remaining, time.Duration(0))
	assert.LessOrEqual(t, remaining, time.Hour)
}

func TestStoreGetType(t *testing.T) {
	t.Parallel()

	s := NewStore(time.Hour, 0)
	assert.Equal(t, storeType, s.GetType())
}

func TestBackendSetAndGetEntry(t *testing.T) {
	t.Parallel()

	b := NewBackend(time.Hour, 0)
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

	b := NewBackend(time.Hour, 0)

	got, err := b.GetEntry(context.Background(), "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestBackendDeleteEntry(t *testing.T) {
	t.Parallel()

	b := NewBackend(time.Hour, 0)
	ctx := context.Background()

	require.NoError(t, b.SetEntry(ctx, "key", newEntry("fp-del")))
	require.NoError(t, b.DeleteEntry(ctx, "key"))

	got, err := b.GetEntry(ctx, "key")
	require.NoError(t, err)
	assert.Nil(t, got)
}
