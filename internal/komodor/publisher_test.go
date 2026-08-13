package komodor

import (
	"testing"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/scanners"
	"github.com/stretchr/testify/require"
)

func TestEventFromScanResult(t *testing.T) {
	result := &scanners.ScanResult{
		Scanner: "trivy",
		Image: scanners.ImageRef{
			Resolved: "ghcr.io/acme/checkout-api@sha256:abc123",
			Digest:   "sha256:abc123",
		},
		ScannedAt: time.Now(),
		Summary: scanners.VulnerabilitySummary{
			Critical: 2,
			High:     7,
			Medium:   14,
			Low:      3,
		},
		Findings: []scanners.Finding{
			{
				CVE:      "CVE-2026-1234",
				Severity: scanners.SeverityCritical,
			},
			{
				CVE:      "CVE-2025-5678",
				Severity: scanners.SeverityHigh,
			},
		},
		ReportURL: "https://scanner.example/report/123",
	}

	workload := WorkloadContext{
		ClusterName: "prod-eks-01",
		Namespace:   "production",
		Kind:        "Deployment",
		Name:        "checkout-api",
		Container:   "checkout-api",
	}

	opts := EventOptions{
		MinimumSeverity:    "high",
		IncludeTopFindings: 5,
	}

	event := EventFromScanResult(result, workload, opts)

	require.Equal(t, "vulnerability-scan", event.EventType)
	require.Equal(t, "26 vulnerability findings in production/checkout-api", event.Summary)
	require.Equal(t, "error", event.Severity)
	require.Equal(t, []string{"checkout-api"}, event.Scope.ServicesNames)
	require.Equal(t, []string{"production"}, event.Scope.Namespaces)
	require.Equal(t, []string{"prod-eks-01"}, event.Scope.Clusters)
	require.Equal(t, 2, event.Details["critical"])
	require.Equal(t, 7, event.Details["high"])
}

func TestShouldPublish(t *testing.T) {
	tests := []struct {
		name          string
		result        *scanners.ScanResult
		opts          EventOptions
		shouldPublish bool
	}{
		{
			name: "clean scan, no publish",
			result: &scanners.ScanResult{
				Summary: scanners.VulnerabilitySummary{},
			},
			opts: EventOptions{
				PublishCleanScans: false,
			},
			shouldPublish: false,
		},
		{
			name: "clean scan, publish enabled",
			result: &scanners.ScanResult{
				Summary: scanners.VulnerabilitySummary{},
			},
			opts: EventOptions{
				PublishCleanScans: true,
			},
			shouldPublish: true,
		},
		{
			name: "high severity below threshold",
			result: &scanners.ScanResult{
				Summary: scanners.VulnerabilitySummary{
					Medium: 5,
				},
			},
			opts: EventOptions{
				MinimumSeverity: "high",
			},
			shouldPublish: false,
		},
		{
			name: "high severity meets threshold",
			result: &scanners.ScanResult{
				Summary: scanners.VulnerabilitySummary{
					High: 1,
				},
			},
			opts: EventOptions{
				MinimumSeverity: "high",
			},
			shouldPublish: true,
		},
		{
			name: "critical severity",
			result: &scanners.ScanResult{
				Summary: scanners.VulnerabilitySummary{
					Critical: 1,
				},
			},
			opts: EventOptions{
				MinimumSeverity: "high",
			},
			shouldPublish: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ShouldPublish(tt.result, tt.opts)
			require.Equal(t, tt.shouldPublish, result)
		})
	}
}

func TestTopFindingsList(t *testing.T) {
	findings := []scanners.Finding{
		{CVE: "CVE-2022-1234", Severity: scanners.SeverityHigh},
		{CVE: "CVE-2022-5678", Severity: scanners.SeverityCritical},
		{CVE: "CVE-2022-9999", Severity: scanners.SeverityMedium},
	}

	top := topFindingsList(findings, 2)

	require.Equal(t, 2, len(top))
	require.Equal(t, "CVE-2022-5678", top[0]) // Critical first
	require.Equal(t, "CVE-2022-1234", top[1]) // Then High
}

func TestTopFindingsListExploitableFirst(t *testing.T) {
	findings := []scanners.Finding{
		{CVE: "CVE-2022-CRIT", Severity: scanners.SeverityCritical, Exploitable: false, FixAvailable: false},
		{CVE: "CVE-2022-HIGH-EXPLOIT", Severity: scanners.SeverityHigh, Exploitable: true, FixAvailable: true},
	}

	top := topFindingsList(findings, 2)

	require.Equal(t, 2, len(top))
	// Exploitable ranks above critical-but-not-exploitable
	require.Equal(t, "CVE-2022-HIGH-EXPLOIT", top[0])
	require.Equal(t, "CVE-2022-CRIT", top[1])
}

func TestTopFindingsListFixableBeforeUnfixable(t *testing.T) {
	// Within the same severity tier, fixable ranks above unfixable.
	// Across severity tiers, severity wins: an unfixable critical ranks above a fixable high.
	findings := []scanners.Finding{
		{CVE: "CVE-2022-CRIT-NOFIX", Severity: scanners.SeverityCritical, FixAvailable: false},
		{CVE: "CVE-2022-HIGH-FIX", Severity: scanners.SeverityHigh, FixAvailable: true},
		{CVE: "CVE-2022-CRIT-FIX", Severity: scanners.SeverityCritical, FixAvailable: true},
	}

	top := topFindingsList(findings, 3)

	require.Equal(t, 3, len(top))
	// Fixable critical first
	require.Equal(t, "CVE-2022-CRIT-FIX", top[0])
	// Unfixable critical still above fixable high (severity wins across tiers)
	require.Equal(t, "CVE-2022-CRIT-NOFIX", top[1])
	require.Equal(t, "CVE-2022-HIGH-FIX", top[2])
}

func TestTopFindingsListDeterministicTiebreaker(t *testing.T) {
	findings := []scanners.Finding{
		{CVE: "CVE-2022-ZZZZ", Severity: scanners.SeverityCritical, FixAvailable: true},
		{CVE: "CVE-2022-AAAA", Severity: scanners.SeverityCritical, FixAvailable: true},
	}

	top := topFindingsList(findings, 2)

	require.Equal(t, 2, len(top))
	require.Equal(t, "CVE-2022-AAAA", top[0])
	require.Equal(t, "CVE-2022-ZZZZ", top[1])
}

func TestEventFromScanResultEnrichedFields(t *testing.T) {
	result := &scanners.ScanResult{
		Scanner: "trivy",
		Image: scanners.ImageRef{
			Resolved: "ghcr.io/acme/app@sha256:abc123",
			Digest:   "sha256:abc123",
		},
		Summary: scanners.VulnerabilitySummary{
			Critical: 1,
			High:     1,
		},
		Findings: []scanners.Finding{
			{CVE: "CVE-2026-0001", Severity: scanners.SeverityCritical, FixAvailable: true, Exploitable: false, ScannerAttribution: "trivy"},
			{CVE: "CVE-2026-0002", Severity: scanners.SeverityHigh, FixAvailable: false, Exploitable: true, ScannerAttribution: "trivy"},
		},
	}

	workload := WorkloadContext{
		ClusterName: "prod",
		Namespace:   "default",
		Kind:        "Deployment",
		Name:        "app",
	}

	event := EventFromScanResult(result, workload, EventOptions{IncludeTopFindings: 5})

	require.Equal(t, 1, event.Details["fixableFindings"])
	require.Equal(t, 1, event.Details["exploitableFindings"])
}
