package state

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEntryMarshalAndParseStorageRoundTrip(t *testing.T) {
	t.Parallel()

	entry := &Entry{
		Fingerprint:       "fp-123",
		LastScannedTime:   time.Unix(1700000000, 0).UTC(),
		LastPublishedTime: time.Unix(1700000100, 0).UTC(),
		Summary:           "3 findings",
	}

	data, err := entry.Marshal()
	require.NoError(t, err)

	got := &Entry{}
	err = got.Unmarshal(data)
	require.NoError(t, err)
	require.Equal(t, entry, got)
}

func TestParseStorageEntryLegacyPipeFormat(t *testing.T) {
	t.Parallel()

	got := &Entry{}
	err := got.Unmarshal("fp|1700000000|1700000100|summary")
	require.NoError(t, err)
	require.Equal(t, "fp", got.Fingerprint)
	require.Equal(t, "summary", got.Summary)
	require.Equal(t, time.Unix(1700000000, 0).UTC(), got.LastScannedTime)
	require.Equal(t, time.Unix(1700000100, 0).UTC(), got.LastPublishedTime)
}

func TestParseStorageEntryLegacyPlainFingerprint(t *testing.T) {
	t.Parallel()

	got := &Entry{}
	err := got.Unmarshal("fingerprint-only")
	require.NoError(t, err)
	require.Equal(t, "fingerprint-only", got.Fingerprint)
	require.True(t, got.LastScannedTime.IsZero())
	require.True(t, got.LastPublishedTime.IsZero())
	require.Equal(t, "", got.Summary)
}

func TestMarshalStorageNilEntry(t *testing.T) {
	t.Parallel()

	var entry *Entry

	_, err := entry.Marshal()
	require.Error(t, err)
}

func TestParseStorageEntryCompatibility(t *testing.T) {
	t.Parallel()

	entry := &Entry{}
	err := entry.Unmarshal("fp|1700000000|1700000100|summary")
	require.NoError(t, err)
	require.Equal(t, "fp", entry.Fingerprint)
}
