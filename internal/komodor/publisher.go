package komodor

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/davidcollom/komodor-security-reporter/internal/scanners"
)

// Publisher converts scan results to Komodor events.
type Publisher struct {
	client *Client
}

// NewPublisher creates a new Komodor event publisher.
func NewPublisher(client *Client) *Publisher {
	return &Publisher{
		client: client,
	}
}

// Publish publishes an event to Komodor via the client.
func (p *Publisher) Publish(ctx context.Context, event *Event) error {
	return p.client.PublishEvent(ctx, event)
}

// WorkloadContext provides context about the affected workload.
type WorkloadContext struct {
	ClusterName string
	Namespace   string
	Kind        string
	Name        string
	UID         string
	APIVersion  string
	Container   string
}

// EventOptions configures event publishing.
type EventOptions struct {
	MinimumSeverity    string
	IncludeTopFindings int
	PublishCleanScans  bool
}

// ShouldPublish determines if an event should be published based on options.
func ShouldPublish(result *scanners.ScanResult, opts EventOptions) bool {
	if result.Summary.Total() == 0 {
		return opts.PublishCleanScans
	}

	minRank := severityRank(opts.MinimumSeverity)

	return hasRiskAtLevel(result, minRank)
}

// EventFromScanResult converts a scan result to a Komodor event.
func EventFromScanResult(result *scanners.ScanResult, workload WorkloadContext, opts EventOptions) *Event {
	summary := result.Summary
	topFindings := topFindingsList(result.Findings, opts.IncludeTopFindings)

	severity := mapSeverityToEvent(summary)

	eventType := "vulnerability-scan"
	eventSummary := fmt.Sprintf("%d vulnerability findings in %s/%s", summary.Total(), workload.Namespace, workload.Name)

	var detailsSummary string

	switch {
	case summary.Critical > 0:
		detailsSummary = fmt.Sprintf("%d CRITICAL, %d HIGH, %d MEDIUM, %d LOW", summary.Critical, summary.High, summary.Medium, summary.Low)
	case summary.High > 0:
		detailsSummary = fmt.Sprintf("%d HIGH, %d MEDIUM, %d LOW", summary.High, summary.Medium, summary.Low)
	default:
		detailsSummary = fmt.Sprintf("%d MEDIUM, %d LOW", summary.Medium, summary.Low)
	}

	fixableCount, exploitableCount := countRiskContext(result.Findings)

	event := &Event{
		EventType: eventType,
		Summary:   eventSummary,
		Severity:  severity,
		Scope: Scope{
			Clusters:      []string{workload.ClusterName},
			Namespaces:    []string{workload.Namespace},
			ServicesNames: []string{workload.Name},
		},
		Details: map[string]interface{}{
			"cluster":             workload.ClusterName,
			"namespace":           workload.Namespace,
			"kind":                workload.Kind,
			"serviceName":         workload.Name,
			"container":           workload.Container,
			"scanner":             result.Scanner,
			"image":               result.Image.Resolved,
			"digest":              result.Image.Digest,
			"summary":             detailsSummary,
			"critical":            summary.Critical,
			"high":                summary.High,
			"medium":              summary.Medium,
			"low":                 summary.Low,
			"topFindings":         topFindings,
			"reportURL":           result.ReportURL,
			"scannedAt":           result.ScannedAt,
			"totalFindings":       summary.Total(),
			"minimumSeverity":     opts.MinimumSeverity,
			"fixableFindings":     fixableCount,
			"exploitableFindings": exploitableCount,
		},
	}

	return event
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func hasRiskAtLevel(result *scanners.ScanResult, minRank int) bool {
	// Check if the maximum severity in the result meets or exceeds the minimum rank
	if result.Summary.Critical > 0 && 4 >= minRank {
		return true
	}

	if result.Summary.High > 0 && 3 >= minRank {
		return true
	}

	if result.Summary.Medium > 0 && 2 >= minRank {
		return true
	}

	if result.Summary.Low > 0 && 1 >= minRank {
		return true
	}

	return false
}

// topFindingsList returns the top CVE identifiers from findings ranked by actionability.
//
// Ranking strategy (deterministic, applied in order):
//  1. Exploitable findings rank highest – they represent active risk.
//  2. Higher severity ranks above lower severity.
//  3. Findings with a fix available rank above those without – more immediately actionable.
//  4. CVE ID ascending is used as a tiebreaker for reproducible output.
func topFindingsList(findings []scanners.Finding, limit int) []string {
	if limit <= 0 || len(findings) == 0 {
		return nil
	}

	sorted := make([]scanners.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		fi, fj := &sorted[i], &sorted[j]

		// 1. Exploitable first
		if fi.Exploitable != fj.Exploitable {
			return fi.Exploitable
		}

		// 2. Higher severity rank first
		if fi.Severity.Rank() != fj.Severity.Rank() {
			return fi.Severity.Rank() > fj.Severity.Rank()
		}

		// 3. Fix available (actionable) before no fix, within the same severity tier
		if fi.FixAvailable != fj.FixAvailable {
			return fi.FixAvailable
		}

		// 4. Alphabetical CVE for deterministic ordering
		return fi.CVE < fj.CVE
	})

	var result []string

	for i := 0; i < len(sorted) && i < limit; i++ {
		if sorted[i].CVE != "" {
			result = append(result, sorted[i].CVE)
		}
	}

	return result
}

// countRiskContext returns the number of fixable and exploitable findings.
func countRiskContext(findings []scanners.Finding) (fixable, exploitable int) {
	for i := range findings {
		if findings[i].FixAvailable {
			fixable++
		}

		if findings[i].Exploitable {
			exploitable++
		}
	}

	return fixable, exploitable
}

func mapSeverityToEvent(summary scanners.VulnerabilitySummary) string {
	if summary.Critical > 0 {
		return "error"
	}

	if summary.High > 0 {
		return "error"
	}

	if summary.Medium > 0 {
		return "warning"
	}

	return "information"
}
