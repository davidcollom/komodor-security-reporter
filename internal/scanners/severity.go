package scanners

import "fmt"

// Severity represents the severity level of a vulnerability.
type Severity string

const (
	// SeverityCritical indicates a critical vulnerability severity.
	SeverityCritical Severity = "critical"
	// SeverityHigh indicates a high vulnerability severity.
	SeverityHigh Severity = "high"
	// SeverityMedium indicates a medium vulnerability severity.
	SeverityMedium Severity = "medium"
	// SeverityLow indicates a low vulnerability severity.
	SeverityLow Severity = "low"
	// SeverityUnknown indicates an unknown vulnerability severity.
	SeverityUnknown Severity = "unknown"
)

// ParseSeverity parses a severity string into a Severity type.
func ParseSeverity(s string) (Severity, error) {
	switch s {
	case "critical", "CRITICAL":
		return SeverityCritical, nil
	case "high", "HIGH":
		return SeverityHigh, nil
	case "medium", "MEDIUM":
		return SeverityMedium, nil
	case "low", "LOW":
		return SeverityLow, nil
	case "unknown", "UNKNOWN":
		return SeverityUnknown, nil
	default:
		return SeverityUnknown, fmt.Errorf("unknown severity: %s", s)
	}
}

// Rank returns a numeric rank for ordering severities (higher = more severe).
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}
