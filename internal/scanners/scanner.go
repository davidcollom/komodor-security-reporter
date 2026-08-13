package scanners

import (
	"context"
	"time"
)

// Scanner defines the interface for image vulnerability scanners.
type Scanner interface {
	// Name returns the scanner name.
	Name() string
	// Scan scans an image and returns normalised findings.
	Scan(ctx context.Context, image ImageRef) (*ScanResult, error)
}

// ImageRef represents a container image reference with resolution state.
type ImageRef struct {
	Original   string // Original image string from workload
	Registry   string // Registry host
	Repository string // Repository path
	Tag        string // Tag or empty if digest
	Digest     string // Digest if resolved
	Resolved   string // Full resolved reference (registry/repo@digest or registry/repo:tag)
}

// ScanResult represents normalised scan findings for an image.
type ScanResult struct {
	Scanner   string
	Image     ImageRef
	ScannedAt time.Time
	Summary   VulnerabilitySummary
	Findings  []Finding
	ReportURL string
	SBOMURL   string
}

// VulnerabilitySummary counts vulnerabilities by severity.
type VulnerabilitySummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

// Total returns the total number of vulnerabilities.
func (vs VulnerabilitySummary) Total() int {
	return vs.Critical + vs.High + vs.Medium + vs.Low + vs.Unknown
}

// RiskHints holds optional risk-scoring metadata for a finding.
// Fields are populated on a best-effort basis depending on scanner output.
type RiskHints struct {
	// EPSSScore is the Exploit Prediction Scoring System score (0.0–1.0), when available.
	EPSSScore float64 `json:"epssScore,omitempty"`
	// KEV indicates whether the CVE appears in CISA's Known Exploited Vulnerabilities catalogue.
	KEV bool `json:"kev,omitempty"`
}

// Finding represents a single vulnerability finding.
type Finding struct {
	ID                 string
	CVE                string
	Package            string
	Installed          string
	Fixed              string
	Severity           Severity
	Title              string
	URL                string
	Exploitable        bool
	FixAvailable       bool      // True when a fixed version has been reported by the scanner.
	ScannerAttribution string    // Scanner that produced this finding (e.g. "trivy", "snyk").
	RiskHints          RiskHints // Optional risk-scoring hints.
}
