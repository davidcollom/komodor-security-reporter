package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/scanners"
	"github.com/davidcollom/komodor-security-reporter/internal/scanners/command"
	"github.com/sirupsen/logrus"
)

func init() {
	scanners.RegisterScanner("trivy", newScannerFactory)
}

// newScannerFactory creates a Trivy scanner from configuration.
// Trivy is a native Go application, so no separate binary installation is strictly required.
// If binary path is omitted, defaults to "trivy" on system PATH.
func newScannerFactory(name string, binary string, log logrus.FieldLogger) (scanners.Scanner, error) {
	// Default to "trivy" if no binary path specified; relies on PATH
	if binary == "" {
		binary = "trivy"
	}

	return NewScanner(binary, log), nil
}

// Scanner implements the scanners.Scanner interface for Trivy.
// Trivy is written in Go and provides excellent JSON output for parsing.
type Scanner struct {
	binary string
	runner *command.Runner
	log    logrus.FieldLogger
}

// NewScanner creates a new Trivy scanner.
func NewScanner(binary string, log logrus.FieldLogger) *Scanner {
	return &Scanner{
		binary: binary,
		runner: command.NewRunner(),
		log:    log,
	}
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "trivy"
}

// Scan scans an image using Trivy and returns normalised results.
func (s *Scanner) Scan(ctx context.Context, image scanners.ImageRef) (*scanners.ScanResult, error) {
	// Run Trivy with JSON output
	stdout, stderr, err := s.runner.Run(ctx, s.binary, "image", "--format", "json", image.Resolved)
	if err != nil {
		return nil, fmt.Errorf("trivy scan: %w (stderr: %s)", err, string(stderr))
	}

	// Parse Trivy JSON output
	result, err := parseResult(stdout, image)
	if err != nil {
		return nil, fmt.Errorf("parse trivy output: %w", err)
	}

	result.Scanner = s.Name()
	result.ScannedAt = time.Now()

	return result, nil
}

// trivyReport represents the Trivy JSON report structure.
type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string               `json:"Target"`
	Type            string               `json:"Type"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
}

type trivyVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
	PrimaryURL       string `json:"PrimaryURL"`
}

// parseResult parses Trivy JSON output and normalises it.
func parseResult(data []byte, image scanners.ImageRef) (*scanners.ScanResult, error) {
	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("unmarshal json: %w", err)
	}

	result := &scanners.ScanResult{
		Image:    image,
		Findings: make([]scanners.Finding, 0),
		Summary:  scanners.VulnerabilitySummary{},
	}

	// Process all results
	for _, res := range report.Results {
		for i := range res.Vulnerabilities {
			vuln := &res.Vulnerabilities[i]
			sev := parseSeverityOrUnknown(vuln.Severity)
			incrementSummary(&result.Summary, sev)

			finding := scanners.Finding{
				ID:          vuln.VulnerabilityID,
				CVE:         normalizeCVE(vuln.VulnerabilityID),
				Package:     vuln.PkgName,
				Installed:   vuln.InstalledVersion,
				Fixed:       vuln.FixedVersion,
				Severity:    sev,
				Title:       vuln.Title,
				URL:         vuln.PrimaryURL,
				Exploitable: false, // Trivy doesn't provide exploit status
			}

			result.Findings = append(result.Findings, finding)
		}
	}

	return result, nil
}

func parseSeverityOrUnknown(value string) scanners.Severity {
	sev, err := scanners.ParseSeverity(value)
	if err != nil {
		return scanners.SeverityUnknown
	}

	return sev
}

func incrementSummary(summary *scanners.VulnerabilitySummary, sev scanners.Severity) {
	switch sev {
	case scanners.SeverityCritical:
		summary.Critical++
	case scanners.SeverityHigh:
		summary.High++
	case scanners.SeverityMedium:
		summary.Medium++
	case scanners.SeverityLow:
		summary.Low++
	default:
		summary.Unknown++
	}
}

func normalizeCVE(vulnerabilityID string) string {
	if len(vulnerabilityID) < 4 {
		return ""
	}

	if vulnerabilityID[:4] != "CVE-" {
		return ""
	}

	return vulnerabilityID
}
