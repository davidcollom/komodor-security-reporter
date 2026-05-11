package state

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Entry represents stored state for a scanned image.
type Entry struct {
	Fingerprint       string    `json:"fingerprint"`
	LastScannedTime   time.Time `json:"lastScannedTime"`
	LastPublishedTime time.Time `json:"lastPublishedTime"`
	Summary           string    `json:"summary"`
}

// MarshalJSON serialises Entry with unix timestamps for storage compatibility.
func (e Entry) MarshalJSON() ([]byte, error) {
	toUnix := func(t time.Time) int64 {
		if t.IsZero() {
			return 0
		}

		return t.Unix()
	}

	return json.Marshal(map[string]any{
		"fingerprint":       e.Fingerprint,
		"lastScannedTime":   toUnix(e.LastScannedTime),
		"lastPublishedTime": toUnix(e.LastPublishedTime),
		"summary":           e.Summary,
	})
}

// UnmarshalJSON deserialises Entry from unix timestamps.
func (e *Entry) UnmarshalJSON(data []byte) error {
	if e == nil {
		return fmt.Errorf("entry is nil")
	}

	if string(data) == "null" {
		*e = Entry{}
		return nil
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	if raw, ok := payload["fingerprint"]; ok {
		if err := json.Unmarshal(raw, &e.Fingerprint); err != nil {
			return fmt.Errorf("decode fingerprint: %w", err)
		}
	}

	if raw, ok := payload["summary"]; ok {
		if err := json.Unmarshal(raw, &e.Summary); err != nil {
			return fmt.Errorf("decode summary: %w", err)
		}
	}

	parseUnixField := func(field string, raw json.RawMessage) (time.Time, error) {
		var unix int64
		if err := json.Unmarshal(raw, &unix); err == nil {
			if unix > 0 {
				return time.Unix(unix, 0).UTC(), nil
			}

			return time.Time{}, nil
		}

		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			s = strings.TrimSpace(s)
			if s == "" {
				return time.Time{}, nil
			}

			if parsed, err := time.Parse(time.RFC3339, s); err == nil {
				return parsed.UTC(), nil
			}

			if parsedUnix, err := strconv.ParseInt(s, 10, 64); err == nil && parsedUnix > 0 {
				return time.Unix(parsedUnix, 0).UTC(), nil
			}

			return time.Time{}, fmt.Errorf("decode %s: unsupported string format", field)
		}

		return time.Time{}, fmt.Errorf("decode %s: unsupported JSON type", field)
	}

	if raw, ok := payload["lastScannedTime"]; ok {
		t, err := parseUnixField("lastScannedTime", raw)
		if err != nil {
			return err
		}

		e.LastScannedTime = t
	}

	if raw, ok := payload["lastPublishedTime"]; ok {
		t, err := parseUnixField("lastPublishedTime", raw)
		if err != nil {
			return err
		}

		e.LastPublishedTime = t
	}

	return nil
}

// Marshal serialises an Entry for persistent storage.
func (e *Entry) Marshal() (string, error) {
	if e == nil {
		return "", fmt.Errorf("entry is nil")
	}

	data, err := json.Marshal(e)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// Unmarshal deserialises Entry from storage payloads.
// It supports the current JSON format and legacy pipe-delimited formats.
func (e *Entry) Unmarshal(data string) error {
	if e == nil {
		return fmt.Errorf("entry is nil")
	}

	if err := json.Unmarshal([]byte(data), e); err == nil {
		return nil
	}

	parts := strings.SplitN(data, "|", 4)
	if len(parts) == 4 {
		e.Fingerprint = parts[0]
		e.Summary = parts[3]
		e.LastScannedTime = time.Time{}
		e.LastPublishedTime = time.Time{}

		scanned, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return fmt.Errorf("parse scanned unix timestamp: %w", err)
		}

		published, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			return fmt.Errorf("parse published unix timestamp: %w", err)
		}

		if scanned > 0 {
			e.LastScannedTime = time.Unix(scanned, 0).UTC()
		}

		if published > 0 {
			e.LastPublishedTime = time.Unix(published, 0).UTC()
		}

		return nil
	}

	e.Fingerprint = data
	e.Summary = ""
	e.LastScannedTime = time.Time{}
	e.LastPublishedTime = time.Time{}

	return nil
}
