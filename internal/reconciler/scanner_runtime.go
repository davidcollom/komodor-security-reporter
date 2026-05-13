package reconciler

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/davidcollom/komodor-security-reporter/internal/config"
	"github.com/davidcollom/komodor-security-reporter/internal/scanners"
)

var errScannerCircuitOpen = errors.New("scanner circuit is open")

type scannerErrorClass string

const (
	scannerErrorClassTimeout     scannerErrorClass = "timeout"
	scannerErrorClassTransient   scannerErrorClass = "transient"
	scannerErrorClassPermanent   scannerErrorClass = "permanent"
	scannerErrorClassCircuitOpen scannerErrorClass = "circuit_open"
)

type circuitState int

const (
	circuitStateClosed circuitState = iota
	circuitStateOpen
	circuitStateHalfOpen
)

type scannerRuntimePolicy struct {
	Timeout             time.Duration
	RetryMaxAttempts    int
	RetryInitialBackoff time.Duration
	RetryMaxBackoff     time.Duration
	RetryMultiplier     float64
	FailureThreshold    int
	OpenDuration        time.Duration
	HalfOpenMaxRequests int
}

type scannerCircuit struct {
	state               circuitState
	consecutiveFailures int
	openedAt            time.Time
	halfOpenInFlight    int
}

type scannerCircuitBreaker struct {
	mu       sync.Mutex
	policy   scannerRuntimePolicy
	now      func() time.Time
	scanners map[string]*scannerCircuit
}

func newScannerRuntimePolicy(runtime config.ScannerRuntimeConfig) scannerRuntimePolicy {
	effective := config.EffectiveScannerRuntimeConfig(runtime)

	return scannerRuntimePolicy{
		Timeout:             effective.Timeout,
		RetryMaxAttempts:    effective.Retry.MaxAttempts,
		RetryInitialBackoff: effective.Retry.InitialBackoff,
		RetryMaxBackoff:     effective.Retry.MaxBackoff,
		RetryMultiplier:     effective.Retry.BackoffMultiplier,
		FailureThreshold:    effective.CircuitBreaker.FailureThreshold,
		OpenDuration:        effective.CircuitBreaker.OpenDuration,
		HalfOpenMaxRequests: effective.CircuitBreaker.HalfOpenMaxRequests,
	}
}

func newScannerCircuitBreaker(policy scannerRuntimePolicy, nowFn func() time.Time) *scannerCircuitBreaker {
	if nowFn == nil {
		nowFn = time.Now
	}

	return &scannerCircuitBreaker{
		policy:   policy,
		now:      nowFn,
		scanners: map[string]*scannerCircuit{},
	}
}

func (c *scannerCircuitBreaker) allow(scannerName string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	state := c.getOrCreate(scannerName)

	switch state.state {
	case circuitStateClosed:
		return nil
	case circuitStateOpen:
		if c.now().Sub(state.openedAt) < c.policy.OpenDuration {
			return errScannerCircuitOpen
		}

		state.state = circuitStateHalfOpen
		state.halfOpenInFlight = 0
	case circuitStateHalfOpen:
		// keep current state
	}

	if state.state == circuitStateHalfOpen {
		if state.halfOpenInFlight >= c.policy.HalfOpenMaxRequests {
			return errScannerCircuitOpen
		}

		state.halfOpenInFlight++
	}

	return nil
}

func (c *scannerCircuitBreaker) onSuccess(scannerName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	state := c.getOrCreate(scannerName)

	switch state.state {
	case circuitStateHalfOpen:
		if state.halfOpenInFlight > 0 {
			state.halfOpenInFlight--
		}

		state.state = circuitStateClosed
		state.consecutiveFailures = 0
		state.openedAt = time.Time{}
	case circuitStateClosed:
		state.consecutiveFailures = 0
	}
}

func (c *scannerCircuitBreaker) onFailure(scannerName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	state := c.getOrCreate(scannerName)

	switch state.state {
	case circuitStateHalfOpen:
		if state.halfOpenInFlight > 0 {
			state.halfOpenInFlight--
		}

		state.state = circuitStateOpen
		state.openedAt = c.now()
		state.consecutiveFailures = c.policy.FailureThreshold
	case circuitStateClosed:
		state.consecutiveFailures++
		if state.consecutiveFailures >= c.policy.FailureThreshold {
			state.state = circuitStateOpen
			state.openedAt = c.now()
		}
	}
}

func (c *scannerCircuitBreaker) state(scannerName string) circuitState {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.getOrCreate(scannerName).state
}

func (c *scannerCircuitBreaker) getOrCreate(scannerName string) *scannerCircuit {
	state, ok := c.scanners[scannerName]
	if !ok {
		state = &scannerCircuit{state: circuitStateClosed}
		c.scanners[scannerName] = state
	}

	return state
}

func (r *Reconciler) executeScannerWithResilience(
	ctx context.Context,
	scanner scanners.Scanner,
	scanImageRef scanners.ImageRef,
) (*scanners.ScanResult, float64, scannerErrorClass, error) {
	scannerName := scanner.Name()

	if err := r.circuitBreaker.allow(scannerName); err != nil {
		r.updateCircuitStateMetric(scannerName)
		return nil, 0, scannerErrorClassCircuitOpen, err
	}

	r.updateCircuitStateMetric(scannerName)

	attempts := r.runtimePolicy.RetryMaxAttempts
	if attempts <= 0 {
		attempts = 1
	}

	totalDuration := 0.0

	for attempt := 1; attempt <= attempts; attempt++ {
		scanCtx := ctx
		cancel := func() {}

		timeout := r.timeoutForScanner(scannerName)
		if timeout > 0 {
			scanCtx, cancel = context.WithTimeout(ctx, timeout)
		}

		start := time.Now()
		scanResult, err := scanner.Scan(scanCtx, scanImageRef)
		totalDuration += time.Since(start).Seconds()

		cancel()

		if err == nil {
			r.circuitBreaker.onSuccess(scannerName)
			r.updateCircuitStateMetric(scannerName)

			return scanResult, totalDuration, "", nil
		}

		errClass := classifyScannerError(err)
		if !isRetryableScannerError(errClass) || attempt == attempts {
			r.circuitBreaker.onFailure(scannerName)
			r.updateCircuitStateMetric(scannerName)

			return nil, totalDuration, errClass, fmt.Errorf("scanner %s failed after %d attempt(s): %w", scannerName, attempt, err)
		}

		if err := r.sleep(ctx, r.retryBackoff(attempt)); err != nil {
			return nil, totalDuration, scannerErrorClassTransient, fmt.Errorf("scanner retry backoff interrupted: %w", err)
		}
	}

	return nil, totalDuration, scannerErrorClassPermanent, fmt.Errorf("scanner %s failed unexpectedly", scannerName)
}

func (r *Reconciler) timeoutForScanner(scannerName string) time.Duration {
	if timeout, ok := r.scannerTimeoutsByName[scannerName]; ok {
		return timeout
	}

	return r.runtimePolicy.Timeout
}

func (r *Reconciler) retryBackoff(attempt int) time.Duration {
	if attempt <= 0 {
		attempt = 1
	}

	multiplier := r.runtimePolicy.RetryMultiplier
	if multiplier < 1 {
		multiplier = 1
	}

	backoffFloat := float64(r.runtimePolicy.RetryInitialBackoff) * math.Pow(multiplier, float64(attempt-1))

	backoff := time.Duration(backoffFloat)
	if backoff > r.runtimePolicy.RetryMaxBackoff {
		return r.runtimePolicy.RetryMaxBackoff
	}

	return backoff
}

func classifyScannerError(err error) scannerErrorClass {
	if errors.Is(err, errScannerCircuitOpen) {
		return scannerErrorClassCircuitOpen
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return scannerErrorClassTimeout
	}

	if errors.Is(err, context.Canceled) {
		return scannerErrorClassTransient
	}

	if isTemporaryError(err) {
		return scannerErrorClassTransient
	}

	return scannerErrorClassPermanent
}

func isRetryableScannerError(errClass scannerErrorClass) bool {
	return errClass == scannerErrorClassTransient || errClass == scannerErrorClassTimeout
}

func isTemporaryError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	type temporary interface {
		Temporary() bool
	}

	var temporaryErr temporary
	if errors.As(err, &temporaryErr) {
		return temporaryErr.Temporary()
	}

	return false
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (r *Reconciler) updateCircuitStateMetric(scannerName string) {
	if r.metrics == nil || r.metrics.ScannerCircuitState == nil {
		return
	}

	state := r.circuitBreaker.state(scannerName)
	r.metrics.ScannerCircuitState.WithLabelValues(scannerName).Set(float64(state))
}
