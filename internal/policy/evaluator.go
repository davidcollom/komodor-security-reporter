package policy

import (
	"crypto/sha256"
	"fmt"
	"io"
	"sort"

	"github.com/davidcollom/komodor-security-reporter/internal/scanners"
)

// Fingerprint generates a stable hash of scan results for deduplication.
func Fingerprint(result *scanners.ScanResult) string {
	h := sha256.New()

	// Write stable fields
	_, _ = io.WriteString(h, result.Scanner)
	_, _ = io.WriteString(h, "|")
	_, _ = io.WriteString(h, result.Image.Digest)
	_, _ = io.WriteString(h, "|")

	// Write summary counts
	_, _ = fmt.Fprintf(h, "%d,%d,%d,%d,%d|",
		result.Summary.Critical,
		result.Summary.High,
		result.Summary.Medium,
		result.Summary.Low,
		result.Summary.Unknown,
	)

	// Write top finding IDs sorted for stability
	cves := extractCVEs(result.Findings)
	for _, cve := range cves {
		_, _ = io.WriteString(h, cve)
		_, _ = io.WriteString(h, ",")
	}

	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

func extractCVEs(findings []scanners.Finding) []string {
	var cves []string

	for i := range findings {
		f := &findings[i]
		if f.CVE != "" {
			cves = append(cves, f.CVE)
		}
	}

	sort.Strings(cves)

	return cves
}

// EvaluatePublish determines whether to publish based on policy and state.
func EvaluatePublish(result *scanners.ScanResult, lastFingerprint string, onlyOnChange bool) bool {
	currentFingerprint := Fingerprint(result)

	// Always publish on first scan
	if lastFingerprint == "" {
		return true
	}

	// Publish if significant change detected
	if currentFingerprint != lastFingerprint {
		return true
	}

	// If only publishing on change, skip
	if onlyOnChange {
		return false
	}

	return true
}
