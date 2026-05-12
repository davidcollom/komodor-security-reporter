package clair

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
	scanners.RegisterScanner("clair", newScannerFactory)
}

func newScannerFactory(_ config.ScannerConfig, scopedConfig *viper.Viper, log logrus.FieldLogger) (scanners.Scanner, *time.Duration, error) {
	cfg, timeout, err := parseConfig(scopedConfig)
	if err != nil {
		return nil, nil, err
	}

	return NewScanner(cfg.Command.Binary, log), &timeout, nil
}

// Scanner implements the scanners.Scanner interface for Clair CLI.
type Scanner struct {
	binary string
	runner *command.Runner
	log    logrus.FieldLogger
}

// NewScanner creates a Clair scanner.
func NewScanner(binary string, log logrus.FieldLogger) *Scanner {
	return &Scanner{
		binary: binary,
		runner: command.NewRunner(),
		log:    log,
	}
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "clair"
}

// Scan runs a Clair image report and normalizes the result.
func (s *Scanner) Scan(ctx context.Context, image scanners.ImageRef) (*scanners.ScanResult, error) {
	stdout, stderr, err := s.runner.RunAllowExitCodes(
		ctx,
		[]int{1},
		s.binary,
		"report",
		image.Resolved,
		"-o",
		"json",
	)
	if err != nil {
		return nil, fmt.Errorf("clair scan: %w (stderr: %s)", err, string(stderr))
	}

	result, err := parseResult(stdout, image)
	if err != nil {
		return nil, fmt.Errorf("parse clair output: %w", err)
	}

	result.Scanner = s.Name()
	result.ScannedAt = time.Now()

	return result, nil
}

func parseResult(data []byte, image scanners.ImageRef) (*scanners.ScanResult, error) {
	var payload interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal json: %w", err)
	}

	vulns := collectVulnerabilityObjects(payload)
	result := &scanners.ScanResult{
		Image:    image,
		Findings: make([]scanners.Finding, 0, len(vulns)),
		Summary:  scanners.VulnerabilitySummary{},
	}

	for _, vuln := range vulns {
		sev := parseSeverityOrUnknown(vuln)
		incrementSummary(&result.Summary, sev)

		id := vulnIdentity(vuln)

		cve := firstCVE(vuln)
		if cve == "" && strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			cve = id
		}

		result.Findings = append(result.Findings, scanners.Finding{
			ID:  id,
			CVE: cve,
			Package: firstNonEmpty(
				toString(vuln["package"]),
				toString(vuln["packageName"]),
				toString(vuln["featureName"]),
				toString(vuln["artifact"]),
			),
			Installed: firstNonEmpty(
				toString(vuln["installedVersion"]),
				toString(vuln["version"]),
				toString(vuln["featureVersion"]),
			),
			Fixed: firstNonEmpty(
				toString(vuln["fixedVersion"]),
				toString(vuln["fixedby"]),
				toString(vuln["fixedBy"]),
			),
			Severity: sev,
			Title: firstNonEmpty(
				toString(vuln["title"]),
				toString(vuln["name"]),
				id,
			),
			URL: firstNonEmpty(
				toString(vuln["url"]),
				toString(vuln["link"]),
			),
			Exploitable: toBool(vuln["exploitable"]),
		})
	}

	return result, nil
}

func parseSeverityOrUnknown(v map[string]interface{}) scanners.Severity {
	severity := strings.ToLower(firstNonEmpty(
		toString(v["severity"]),
		toString(v["normalizedSeverity"]),
	))

	sev, err := scanners.ParseSeverity(severity)
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

func collectVulnerabilityObjects(payload interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, 0)

	var walk func(interface{})

	walk = func(node interface{}) {
		switch value := node.(type) {
		case map[string]interface{}:
			if looksLikeVulnerability(value) {
				out = append(out, value)
			}

			for _, child := range value {
				walk(child)
			}
		case []interface{}:
			for _, child := range value {
				walk(child)
			}
		}
	}

	walk(payload)

	return dedupeByFingerprint(out)
}

func looksLikeVulnerability(v map[string]interface{}) bool {
	hasSeverity := firstNonEmpty(
		toString(v["severity"]),
		toString(v["normalizedSeverity"]),
	) != ""
	if !hasSeverity {
		return false
	}

	hasIdentity := vulnIdentity(v) != ""

	return hasIdentity
}

func vulnIdentity(v map[string]interface{}) string {
	return firstNonEmpty(
		toString(v["id"]),
		toString(v["vulnerability"]),
		toString(v["vulnerabilityId"]),
		toString(v["name"]),
		toString(v["title"]),
	)
}

func dedupeByFingerprint(vulns []map[string]interface{}) []map[string]interface{} {
	seen := make(map[string]struct{}, len(vulns))

	out := make([]map[string]interface{}, 0, len(vulns))
	for _, vuln := range vulns {
		key := strings.Join([]string{
			vulnIdentity(vuln),
			firstNonEmpty(
				toString(vuln["package"]),
				toString(vuln["packageName"]),
				toString(vuln["featureName"]),
				toString(vuln["artifact"]),
			),
			firstNonEmpty(
				toString(vuln["installedVersion"]),
				toString(vuln["version"]),
				toString(vuln["featureVersion"]),
			),
			strings.ToLower(firstNonEmpty(toString(vuln["severity"]), toString(vuln["normalizedSeverity"]))),
		}, "|")
		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}

		out = append(out, vuln)
	}

	return out
}

func firstCVE(v map[string]interface{}) string {
	for _, key := range []string{"cve", "CVE"} {
		value := toString(v[key])
		if strings.HasPrefix(strings.ToUpper(value), "CVE-") {
			return value
		}
	}

	return cveFromLinks(v["links"])
}

func cveFromLinks(raw interface{}) string {
	items, ok := raw.([]interface{})
	if !ok {
		return ""
	}

	for _, item := range items {
		value := toString(item)
		upper := strings.ToUpper(value)

		idx := strings.Index(upper, "CVE-")
		if idx < 0 {
			continue
		}

		return value[idx:]
	}

	return ""
}

func toString(v interface{}) string {
	switch value := v.(type) {
	case string:
		return value
	case fmt.Stringer:
		return value.String()
	default:
		return ""
	}
}

func toBool(v interface{}) bool {
	value, ok := v.(bool)
	if !ok {
		return false
	}

	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}
