// Package concurrency provides adaptive rate limiting and backpressure controls
// for scanner dispatch under degraded downstream conditions.
package concurrency

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// AdaptiveLimiter is a token-bucket rate limiter whose effective limit scales
// down linearly as the observed scan error rate approaches errorRateThreshold.
// It is safe for concurrent use.
type AdaptiveLimiter struct {
	limiter            *rate.Limiter
	minRPS             float64
	maxRPS             float64
	errorRateThreshold float64

	// mu protects totalScans and errorScans so both are always updated and read
	// as a consistent pair.
	mu         sync.Mutex
	totalScans int64
	errorScans int64
}

// NewAdaptiveLimiter creates a new AdaptiveLimiter.
//
//   - maxRPS is the nominal rate limit (tokens/second) when the system is healthy.
//   - minRPS is the floor rate limit applied when the error rate is at or above errorRateThreshold.
//   - errorRateThreshold is the error fraction [0,1] at which the limiter switches to minRPS.
func NewAdaptiveLimiter(maxRPS, minRPS, errorRateThreshold float64) *AdaptiveLimiter {
	if maxRPS <= 0 {
		maxRPS = 1
	}

	if minRPS < 0 {
		minRPS = 0
	}

	if minRPS > maxRPS {
		minRPS = maxRPS
	}

	if errorRateThreshold <= 0 || errorRateThreshold > 1 {
		errorRateThreshold = 0.5
	}

	return &AdaptiveLimiter{
		limiter:            rate.NewLimiter(rate.Limit(maxRPS), 1),
		minRPS:             minRPS,
		maxRPS:             maxRPS,
		errorRateThreshold: errorRateThreshold,
	}
}

// RecordResult updates the internal error-rate counters and adjusts the
// underlying token-bucket limit accordingly.
//
// Call RecordResult(true) after each failed scan and RecordResult(false) after
// each successful scan to keep the adaptive limit current.
func (a *AdaptiveLimiter) RecordResult(isError bool) {
	a.mu.Lock()
	a.totalScans++

	if isError {
		a.errorScans++
	}

	newRate := a.effectiveRPSLocked()
	a.mu.Unlock()

	a.limiter.SetLimit(rate.Limit(newRate))
}

// Wait blocks until the limiter permits one event or the context is cancelled.
func (a *AdaptiveLimiter) Wait(ctx context.Context) error {
	return a.limiter.Wait(ctx)
}

// ErrorRate returns the current fraction of recorded scans that were errors.
func (a *AdaptiveLimiter) ErrorRate() float64 {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.errorRateLocked()
}

// effectiveRPS computes the current rate limit given the observed error rate.
// The caller must hold a.mu.
func (a *AdaptiveLimiter) effectiveRPSLocked() float64 {
	errRate := a.errorRateLocked()

	if errRate >= a.errorRateThreshold {
		return a.minRPS
	}

	if errRate <= 0 {
		return a.maxRPS
	}

	// Linear interpolation between maxRPS (at errRate=0) and minRPS (at errRate=threshold)
	ratio := errRate / a.errorRateThreshold

	return a.maxRPS - ratio*(a.maxRPS-a.minRPS)
}

// errorRateLocked returns the error fraction. The caller must hold a.mu.
func (a *AdaptiveLimiter) errorRateLocked() float64 {
	if a.totalScans == 0 {
		return 0
	}

	return float64(a.errorScans) / float64(a.totalScans)
}

// effectiveRPS is the exported version for testing.
func (a *AdaptiveLimiter) effectiveRPS() float64 {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.effectiveRPSLocked()
}
