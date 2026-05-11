package state

import "time"

// Entry represents stored state for a scanned image.
type Entry struct {
	Fingerprint       string
	LastScannedTime   time.Time
	LastPublishedTime time.Time
	Summary           string // Human-readable summary
}
