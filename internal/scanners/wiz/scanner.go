package wiz

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
	scanners.RegisterScanner("wiz", newScannerFactory)
}

func newScannerFactory(_ config.ScannerConfig, scopedConfig *viper.Viper, log logrus.FieldLogger) (scanners.Scanner, *time.Duration, error) {
	cfg, timeout, err := parseConfig(scopedConfig)
	if err != nil {
		return nil, nil, err
	}

	return NewScanner(cfg.Command.Binary, log), &timeout, nil
}

// Scanner implements the scanners.Scanner interface for Wiz CLI.
type Scanner struct {
	binary string
	runner *command.Runner
	log    logrus.FieldLogger
}

// NewScanner creates a Wiz scanner.
func NewScanner(binary string, log logrus.FieldLogger) *Scanner {
	return &Scanner{
		binary: binary,
		runner: command.NewRunner(),
		log:    log,
	}
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "wiz"
}

// Scan runs a Wiz container-image scan and normalizes the result.
func (s *Scanner) Scan(ctx context.Context, image scanners.ImageRef) (*scanners.ScanResult, error) {
	stdout, stderr, err := s.runner.RunAllowExitCodes(
		ctx,
		[]int{1},
		s.binary,
		"scan",
		"container-image",
		image.Resolved,
		"--stdout",
		"json",
		"--no-style",
		"--no-color",
	)
	if err != nil {
		return nil, fmt.Errorf("wiz scan: %w (stderr: %s)", err, string(stderr))
	}

	result, err := parseResult(stdout, image)
	if err != nil {
		return nil, fmt.Errorf("parse wiz output: %w", err)
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
		sev, err := scanners.ParseSeverity(toString(vuln["severity"]))
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

		id := firstNonEmpty(
			toString(vuln["id"]),
			toString(vuln["vulnerabilityId"]),
			toString(vuln["issueId"]),
		)

		cve := firstCVE(vuln)
		if cve == "" && strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			cve = id
		}

		result.Findings = append(result.Findings, scanners.Finding{
			ID:  id,
			CVE: cve,
			Package: firstNonEmpty(
				toString(vuln["packageName"]),
				toString(vuln["package"]),
				toString(vuln["name"]),
			),
			Installed: firstNonEmpty(
				toString(vuln["installedVersion"]),
				toString(vuln["version"]),
			),
			Fixed: firstNonEmpty(
				toString(vuln["fixedVersion"]),
				toString(vuln["fixVersion"]),
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
			Exploitable: false,
		})
	}

	return result, nil
}

func collectVulnerabilityObjects(payload interface{}) []map[string]interface{} {
	result := make([]map[string]interface{}, 0)

	var walk func(interface{})

	walk = func(node interface{}) {
		switch value := node.(type) {
		case map[string]interface{}:
			if looksLikeVulnerability(value) {
				result = append(result, value)
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

	return dedupeByFingerprint(result)
}

func looksLikeVulnerability(v map[string]interface{}) bool {
	severity := strings.ToLower(toString(v["severity"]))
	if severity == "" {
		return false
	}

	hasIdentity := firstNonEmpty(
		toString(v["id"]),
		toString(v["vulnerabilityId"]),
		toString(v["issueId"]),
		toString(v["title"]),
		toString(v["name"]),
	) != ""

	return hasIdentity
}

func dedupeByFingerprint(vulns []map[string]interface{}) []map[string]interface{} {
	seen := make(map[string]struct{}, len(vulns))

	out := make([]map[string]interface{}, 0, len(vulns))
	for _, vuln := range vulns {
		key := strings.Join([]string{
			firstNonEmpty(toString(vuln["id"]), toString(vuln["vulnerabilityId"]), toString(vuln["issueId"])),
			firstNonEmpty(toString(vuln["packageName"]), toString(vuln["package"]), toString(vuln["name"])),
			firstNonEmpty(toString(vuln["installedVersion"]), toString(vuln["version"])),
			strings.ToLower(toString(vuln["severity"])),
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
	for _, key := range []string{"cve", "cveId"} {
		value := toString(v[key])
		if strings.HasPrefix(strings.ToUpper(value), "CVE-") {
			return value
		}
	}

	return cveFromIdentifiers(v["identifiers"])
}

func cveFromIdentifiers(identifiers interface{}) string {
	m, ok := identifiers.(map[string]interface{})
	if !ok {
		return ""
	}

	for key, raw := range m {
		if !strings.EqualFold(key, "CVE") {
			continue
		}

		if value := cveFromIdentifierValue(raw); value != "" {
			return value
		}
	}

	return ""
}

func cveFromIdentifierValue(raw interface{}) string {
	if list, ok := raw.([]interface{}); ok && len(list) > 0 {
		if value := toString(list[0]); strings.HasPrefix(strings.ToUpper(value), "CVE-") {
			return value
		}
	}

	value := toString(raw)
	if strings.HasPrefix(strings.ToUpper(value), "CVE-") {
		return value
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}
