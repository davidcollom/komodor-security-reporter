package configmap

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/state"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestStoreEncodesUnsafeConfigMapKeys(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	client := fake.NewSimpleClientset()
	store := NewBackend(client, "default", "komodor-security-reporter-state", 100*365*24*time.Hour)

	logicalKey := "sha256:e02287f003226f1aad693766e1eecd50272ce6285481906fc9a715cc4f7a5ba9/trivy"
	entry := &state.Entry{
		Fingerprint:       "fp-123",
		LastScannedTime:   time.Unix(1700000000, 0).UTC(),
		LastPublishedTime: time.Unix(1700000100, 0).UTC(),
		Summary:           "3 findings",
	}

	require.NoError(t, store.SetEntry(ctx, logicalKey, entry))

	cm, err := client.CoreV1().ConfigMaps("default").Get(ctx, "komodor-security-reporter-state", metav1.GetOptions{})
	require.NoError(t, err)
	require.Len(t, cm.Data, 1)

	storageKey := configMapDataKey(logicalKey)
	storedValue, ok := cm.Data[storageKey]
	require.True(t, ok)
	require.NotContains(t, storageKey, "/")
	require.NotContains(t, storageKey, ":")
	require.True(t, strings.HasPrefix(storageKey, "state_"))
	require.Contains(t, storedValue, "fp-123")

	got, err := store.GetEntry(ctx, logicalKey)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, entry.Fingerprint, got.Fingerprint)
}

func TestStoreExpiresEntriesByTTL(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	client := fake.NewSimpleClientset()
	store := NewBackend(client, "default", "komodor-security-reporter-state", time.Hour)

	logicalKey := "sha256:old/trivy"
	expired := &state.Entry{
		Fingerprint:       "old-fingerprint",
		LastScannedTime:   time.Now().Add(-2 * time.Hour).UTC(),
		LastPublishedTime: time.Now().Add(-2 * time.Hour).UTC(),
		Summary:           "expired",
	}

	require.NoError(t, store.SetEntry(ctx, logicalKey, expired))

	got, err := store.GetEntry(ctx, logicalKey)
	require.NoError(t, err)
	require.Nil(t, got)

	cm, err := client.CoreV1().ConfigMaps("default").Get(ctx, "komodor-security-reporter-state", metav1.GetOptions{})
	require.NoError(t, err)

	_, exists := cm.Data[configMapDataKey(logicalKey)]
	require.False(t, exists)
}

func TestStoreDeleteEntry(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	client := fake.NewSimpleClientset()
	store := NewBackend(client, "default", "komodor-security-reporter-state", 72*time.Hour)

	logicalKey := "sha256:to-delete/trivy"
	entry := &state.Entry{
		Fingerprint:       "fp-delete",
		LastScannedTime:   time.Now().UTC(),
		LastPublishedTime: time.Now().UTC(),
		Summary:           "delete me",
	}

	require.NoError(t, store.SetEntry(ctx, logicalKey, entry))
	require.NoError(t, store.DeleteEntry(ctx, logicalKey))

	got, err := store.GetEntry(ctx, logicalKey)
	require.NoError(t, err)
	require.Nil(t, got)
}
