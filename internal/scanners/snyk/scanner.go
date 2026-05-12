package snyk

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/config"
	"github.com/davidcollom/komodor-security-reporter/internal/scanners"
	"github.com/davidcollom/komodor-security-reporter/internal/scanners/command"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func init() {
	scanners.RegisterScanner("snyk", newScannerFactory)
}

func newScannerFactory(_ config.ScannerConfig, scopedConfig *viper.Viper, log logrus.FieldLogger) (scanners.Scanner, *time.Duration, error) {
	cfg, timeout, err := parseConfig(scopedConfig)
	if err != nil {
		return nil, nil, err
	}

	return NewScanner(cfg.Command.Binary, log), &timeout, nil
}

// Scanner implements the scanners.Scanner interface for Snyk Container.
type Scanner struct {
	binary string
	runner *command.Runner
	log    logrus.FieldLogger
}

// NewScanner creates a Snyk scanner.
func NewScanner(binary string, log logrus.FieldLogger) *Scanner {
	return &Scanner{
		binary: binary,
		runner: command.NewRunner(),
		log:    log,
	}
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "snyk"
}

// Scan runs a Snyk container scan and normalizes the result.
func (s *Scanner) Scan(ctx context.Context, image scanners.ImageRef) (*scanners.ScanResult, error) {
	stdout, stderr, err := s.runner.RunAllowExitCodes(ctx, []int{1}, s.binary, "container", "test", "--json", image.Resolved)
	if err != nil {
		return nil, fmt.Errorf("snyk scan: %w (stderr: %s)", err, string(stderr))
	}

	result, err := parseResult(stdout, image)
	if err != nil {
		return nil, fmt.Errorf("parse snyk output: %w", err)
	}

	result.Scanner = s.Name()
	result.ScannedAt = time.Now()

	return result, nil
}

type report struct {
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
	Applications    []application   `json:"applications"`
}

type application struct {
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
}

type vulnerability struct {
	ID          string              `json:"id"`
	PackageName string              `json:"packageName"`
	Name        string              `json:"name"`
	Version     string              `json:"version"`
	Severity    string              `json:"severity"`
	Title       string              `json:"title"`
	FixedIn     []string            `json:"fixedIn"`
	Identifiers map[string][]string `json:"identifiers"`
	References  []string            `json:"references"`
	URL         string              `json:"url"`
}

func parseResult(data []byte, image scanners.ImageRef) (*scanners.ScanResult, error) {
	findings, err := parseReports(data)
	if err != nil {
		return nil, err
	}

	result := &scanners.ScanResult{
		Image:    image,
		Findings: make([]scanners.Finding, 0, len(findings)),
		Summary:  scanners.VulnerabilitySummary{},
	}

	for i := range findings {
		vuln := &findings[i]

		sev, err := scanners.ParseSeverity(vuln.Severity)
		if err != nil {
			sev = scanners.SeverityUnknown
		}

		switch sev {
		case scanners.SeverityCritical:
			result.Summary.Critical++
		case scanners.SeverityHigh:
			result.Summary.High++
		case scanners.SeverityMedium:
			result.Summary.Medium++
		case scanners.SeverityLow:
			result.Summary.Low++
		default:
			result.Summary.Unknown++
		}

		packageName := vuln.PackageName
		if packageName == "" {
			packageName = vuln.Name
		}

		result.Findings = append(result.Findings, scanners.Finding{
			ID:          vuln.ID,
			CVE:         firstIdentifier(vuln.Identifiers, "CVE"),
			Package:     packageName,
			Installed:   vuln.Version,
			Fixed:       firstString(vuln.FixedIn),
			Severity:    sev,
			Title:       vuln.Title,
			URL:         firstNonEmpty(vuln.URL, firstString(vuln.References)),
			Exploitable: false,
		})
	}

	return result, nil
}

func parseReports(data []byte) ([]vulnerability, error) {
	var single report
	if err := json.Unmarshal(data, &single); err == nil {
		return collectVulnerabilities([]report{single}), nil
	}

	var multiple []report
	if err := json.Unmarshal(data, &multiple); err == nil {
		return collectVulnerabilities(multiple), nil
	}

	return nil, fmt.Errorf("unmarshal json")
}

func collectVulnerabilities(reports []report) []vulnerability {
	all := make([]vulnerability, 0)
	for _, rep := range reports {
		all = append(all, rep.Vulnerabilities...)
		for _, app := range rep.Applications {
			all = append(all, app.Vulnerabilities...)
		}
	}

	return dedupeVulnerabilities(all)
}

func dedupeVulnerabilities(vulns []vulnerability) []vulnerability {
	seen := make(map[string]struct{}, len(vulns))

	result := make([]vulnerability, 0, len(vulns))
	for i := range vulns {
		vuln := &vulns[i]

		key := strings.Join([]string{vuln.ID, vuln.PackageName, vuln.Name, vuln.Version}, "|")
		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}

		result = append(result, *vuln)
	}

	return result
}

func firstIdentifier(identifiers map[string][]string, key string) string {
	if identifiers == nil {
		return ""
	}

	return firstString(identifiers[key])
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}

	return values[0]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}
