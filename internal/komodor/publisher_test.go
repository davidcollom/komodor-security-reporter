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
