package scanners

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantSev   Severity
		wantError bool
	}{
		{"critical lowercase", "critical", SeverityCritical, false},
		{"critical uppercase", "CRITICAL", SeverityCritical, false},
		{"high lowercase", "high", SeverityHigh, false},
		{"high uppercase", "HIGH", SeverityHigh, false},
		{"medium lowercase", "medium", SeverityMedium, false},
		{"medium uppercase", "MEDIUM", SeverityMedium, false},
		{"low lowercase", "low", SeverityLow, false},
		{"low uppercase", "LOW", SeverityLow, false},
		{"unknown lowercase", "unknown", SeverityUnknown, false},
		{"unknown uppercase", "UNKNOWN", SeverityUnknown, false},
		{"invalid", "invalid", SeverityUnknown, true},
		{"empty", "", SeverityUnknown, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sev, err := ParseSeverity(tt.input)
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantSev, sev)
			}
		})
	}
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		sev  Severity
		rank int
	}{
		{SeverityCritical, 4},
		{SeverityHigh, 3},
		{SeverityMedium, 2},
		{SeverityLow, 1},
		{SeverityUnknown, 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.sev), func(t *testing.T) {
			require.Equal(t, tt.rank, tt.sev.Rank())
		})
	}
}
