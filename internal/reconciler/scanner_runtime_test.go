package reconciler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/config"
	"github.com/davidcollom/komodor-security-reporter/internal/scanners"
	"github.com/stretchr/testify/require"
)

type testTemporaryError struct{}

func (e testTemporaryError) Error() string {
	return "temporary scanner failure"
}

func (e testTemporaryError) Temporary() bool {
	return true
}

type scriptedScanner struct {
	name    string
	errors  []error
	results []*scanners.ScanResult
	calls   int
}

func (s *scriptedScanner) Name() string {
	return s.name
}

func (s *scriptedScanner) Scan(_ context.Context, image scanners.ImageRef) (*scanners.ScanResult, error) {
	idx := s.calls
	s.calls++

	if idx < len(s.errors) && s.errors[idx] != nil {
		return nil, s.errors[idx]
	}

	if idx < len(s.results) && s.results[idx] != nil {
		return s.results[idx], nil
	}

	return &scanners.ScanResult{
		Scanner:   s.name,
		Image:     image,
		ScannedAt: time.Now().UTC(),
	}, nil
}

func TestExecuteScannerWithResilienceRetriesTransientErrors(t *testing.T) {
	runtimePolicy := scannerRuntimePolicy{
		Timeout:             5 * time.Second,
		RetryMaxAttempts:    3,
		RetryInitialBackoff: 1 * time.Millisecond,
		RetryMaxBackoff:     2 * time.Millisecond,
		RetryMultiplier:     2,
		FailureThreshold:    3,
		OpenDuration:        1 * time.Minute,
		HalfOpenMaxRequests: 1,
	}

	r := &Reconciler{
		runtimePolicy:  runtimePolicy,
		circuitBreaker: newScannerCircuitBreaker(runtimePolicy, time.Now),
		sleep:          func(context.Context, time.Duration) error { return nil },
		scannerConfigsByName: map[string]config.ScannerConfig{
			"trivy": {Name: "trivy", Command: config.CommandConfig{Timeout: 2 * time.Second}},
		},
	}

	scanner := &scriptedScanner{
		name:   "trivy",
		errors: []error{testTemporaryError{}, testTemporaryError{}, nil},
	}

	result, _, errClass, err := r.executeScannerWithResilience(context.Background(), scanner, scanners.ImageRef{Resolved: "alpine:3.20"})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, 3, scanner.calls)
	require.Equal(t, scannerErrorClass(""), errClass)
	require.Equal(t, circuitStateClosed, r.circuitBreaker.state("trivy"))
}

func TestExecuteScannerWithResilienceTimeoutClassification(t *testing.T) {
	runtimePolicy := scannerRuntimePolicy{
		Timeout:             5 * time.Second,
		RetryMaxAttempts:    2,
		RetryInitialBackoff: 1 * time.Millisecond,
		RetryMaxBackoff:     2 * time.Millisecond,
		RetryMultiplier:     2,
		FailureThreshold:    2,
		OpenDuration:        1 * time.Minute,
		HalfOpenMaxRequests: 1,
	}

	r := &Reconciler{
		runtimePolicy:  runtimePolicy,
		circuitBreaker: newScannerCircuitBreaker(runtimePolicy, time.Now),
		sleep:          func(context.Context, time.Duration) error { return nil },
		scannerConfigsByName: map[string]config.ScannerConfig{
			"trivy": {Name: "trivy", Command: config.CommandConfig{Timeout: 2 * time.Second}},
		},
	}

	scanner := &scriptedScanner{
		name:   "trivy",
		errors: []error{context.DeadlineExceeded, context.DeadlineExceeded},
	}

	_, _, errClass, err := r.executeScannerWithResilience(context.Background(), scanner, scanners.ImageRef{Resolved: "alpine:3.20"})

	require.Error(t, err)
	require.Equal(t, scannerErrorClassTimeout, errClass)
	require.Equal(t, 2, scanner.calls)
	require.Equal(t, circuitStateClosed, r.circuitBreaker.state("trivy"), "circuit remains closed after first failed scan result")
}

func TestExecuteScannerWithResilienceCircuitOpensAndClosesAfterProbeSuccess(t *testing.T) {
	now := time.Now().UTC()
	runtimePolicy := scannerRuntimePolicy{
		Timeout:             5 * time.Second,
		RetryMaxAttempts:    1,
		RetryInitialBackoff: 1 * time.Millisecond,
		RetryMaxBackoff:     2 * time.Millisecond,
		RetryMultiplier:     2,
		FailureThreshold:    1,
		OpenDuration:        30 * time.Second,
		HalfOpenMaxRequests: 1,
	}

	cb := newScannerCircuitBreaker(runtimePolicy, func() time.Time { return now })
	r := &Reconciler{
		runtimePolicy:  runtimePolicy,
		circuitBreaker: cb,
		sleep:          func(context.Context, time.Duration) error { return nil },
		scannerConfigsByName: map[string]config.ScannerConfig{
			"clair": {Name: "clair", Command: config.CommandConfig{Timeout: 2 * time.Second}},
		},
	}

	scanner := &scriptedScanner{name: "clair", errors: []error{errors.New("scanner down")}}

	_, _, _, err := r.executeScannerWithResilience(context.Background(), scanner, scanners.ImageRef{Resolved: "alpine:3.20"})
	require.Error(t, err)
	require.Equal(t, circuitStateOpen, r.circuitBreaker.state("clair"))
	require.Equal(t, 1, scanner.calls)

	_, _, errClass, err := r.executeScannerWithResilience(context.Background(), scanner, scanners.ImageRef{Resolved: "alpine:3.20"})
	require.Error(t, err)
	require.Equal(t, scannerErrorClassCircuitOpen, errClass)
	require.Equal(t, 1, scanner.calls, "scanner should not run while circuit is open")

	now = now.Add(31 * time.Second)

	scanner.errors = append(scanner.errors, nil)

	result, _, _, err := r.executeScannerWithResilience(context.Background(), scanner, scanners.ImageRef{Resolved: "alpine:3.20"})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, circuitStateClosed, r.circuitBreaker.state("clair"))
	require.Equal(t, 2, scanner.calls)
}
