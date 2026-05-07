package policy

import (
	"strings"
	"testing"

	"github.com/davidcollom/komodor-security-reporter/internal/scanners"
	"github.com/stretchr/testify/require"
)

func TestFingerprint(t *testing.T) {
	result := &scanners.ScanResult{
		Scanner: "trivy",
		Image: scanners.ImageRef{
			Digest: "sha256:abc123",
		},
		Summary: scanners.VulnerabilitySummary{
			Critical: 2,
			High:     5,
		},
		Findings: []scanners.Finding{
			{CVE: "CVE-2022-1234"},
			{CVE: "CVE-2022-5678"},
		},
	}

	fp1 := Fingerprint(result)

	// Same result should produce same fingerprint
	fp2 := Fingerprint(result)
	require.Equal(t, fp1, fp2)

	// Different counts should produce different fingerprint
	result.Summary.Critical = 3
	fp3 := Fingerprint(result)
	require.NotEqual(t, fp1, fp3)

	// Check format
	require.True(t, strings.HasPrefix(fp1, "sha256:"), "fingerprint should start with sha256:")
}

func TestEvaluatePublish(t *testing.T) {
	result := &scanners.ScanResult{
		Scanner: "trivy",
		Image: scanners.ImageRef{
			Digest: "sha256:abc123",
		},
		Summary: scanners.VulnerabilitySummary{
			Critical: 2,
		},
	}

	tests := []struct {
		name            string
		lastFingerprint string
		onlyOnChange    bool
		shouldPublish   bool
	}{
		{
			name:            "first scan",
			lastFingerprint: "",
			shouldPublish:   true,
		},
		{
			name:            "unchanged, publish anyway",
			lastFingerprint: Fingerprint(result),
			onlyOnChange:    false,
			shouldPublish:   true,
		},
		{
			name:            "unchanged, only on change",
			lastFingerprint: Fingerprint(result),
			onlyOnChange:    true,
			shouldPublish:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publish := EvaluatePublish(result, tt.lastFingerprint, tt.onlyOnChange)
			require.Equal(t, tt.shouldPublish, publish)
		})
	}
}
