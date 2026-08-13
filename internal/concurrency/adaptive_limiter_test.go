package concurrency

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewAdaptiveLimiter_Defaults(t *testing.T) {
	al := NewAdaptiveLimiter(10, 1, 0.5)

	require.NotNil(t, al)
	require.InDelta(t, 10.0, al.maxRPS, 1e-9)
	require.InDelta(t, 1.0, al.minRPS, 1e-9)
	require.InDelta(t, 0.5, al.errorRateThreshold, 1e-9)
}

func TestNewAdaptiveLimiter_InvalidMaxRPSDefaultsToOne(t *testing.T) {
	al := NewAdaptiveLimiter(0, 0, 0.5)

	require.InDelta(t, 1.0, al.maxRPS, 1e-9)
}

func TestNewAdaptiveLimiter_MinRPSClampedToMaxRPS(t *testing.T) {
	al := NewAdaptiveLimiter(5, 10, 0.5)

	require.InDelta(t, 5.0, al.minRPS, 1e-9)
}

func TestNewAdaptiveLimiter_InvalidThresholdDefaultsToHalf(t *testing.T) {
	al := NewAdaptiveLimiter(10, 1, -1)

	require.InDelta(t, 0.5, al.errorRateThreshold, 1e-9)

	al2 := NewAdaptiveLimiter(10, 1, 0)

	require.InDelta(t, 0.5, al2.errorRateThreshold, 1e-9)
}

func TestAdaptiveLimiter_ErrorRate_ZeroWithNoScans(t *testing.T) {
	al := NewAdaptiveLimiter(10, 1, 0.5)

	require.InDelta(t, 0.0, al.ErrorRate(), 1e-9)
}

func TestAdaptiveLimiter_ErrorRate_Calculation(t *testing.T) {
	al := NewAdaptiveLimiter(10, 1, 0.5)

	al.RecordResult(false)
	al.RecordResult(false)
	al.RecordResult(true)
	al.RecordResult(true)

	// 2 errors out of 4 = 0.5
	require.InDelta(t, 0.5, al.ErrorRate(), 1e-9)
}

func TestAdaptiveLimiter_EffectiveRPS_HealthySystem(t *testing.T) {
	al := NewAdaptiveLimiter(100, 1, 0.5)

	// No errors → should return maxRPS
	require.InDelta(t, 100.0, al.effectiveRPS(), 1e-9)
}

func TestAdaptiveLimiter_EffectiveRPS_AtThreshold(t *testing.T) {
	al := NewAdaptiveLimiter(100, 10, 0.5)

	// Push error rate to exactly 0.5 (threshold)
	for i := 0; i < 5; i++ {
		al.RecordResult(true)
	}

	for i := 0; i < 5; i++ {
		al.RecordResult(false)
	}

	// At threshold → minRPS
	require.InDelta(t, 10.0, al.effectiveRPS(), 1e-9)
}

func TestAdaptiveLimiter_EffectiveRPS_BeyondThreshold(t *testing.T) {
	al := NewAdaptiveLimiter(100, 10, 0.5)

	// All errors (rate = 1.0, above threshold)
	al.RecordResult(true)

	require.InDelta(t, 10.0, al.effectiveRPS(), 1e-9)
}

func TestAdaptiveLimiter_EffectiveRPS_LinearInterpolation(t *testing.T) {
	// maxRPS=100 minRPS=0 threshold=1.0
	// At errorRate=0.5 → ratio=0.5, effective = 100 - 0.5*(100-0) = 50
	al := NewAdaptiveLimiter(100, 0, 1.0)

	for i := 0; i < 5; i++ {
		al.RecordResult(true)
	}

	for i := 0; i < 5; i++ {
		al.RecordResult(false)
	}

	require.InDelta(t, 50.0, al.effectiveRPS(), 1e-9)
}

func TestAdaptiveLimiter_Wait_SucceedsImmediatelyWithHighRate(t *testing.T) {
	al := NewAdaptiveLimiter(1000, 100, 0.5)

	err := al.Wait(context.Background())

	require.NoError(t, err)
}

func TestAdaptiveLimiter_Wait_RespectsContextCancellation(t *testing.T) {
	// Set a very low rate to force blocking
	al := NewAdaptiveLimiter(0.0001, 0.0001, 0.5)

	// Consume the initial token
	_ = al.Wait(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := al.Wait(ctx)

	require.ErrorIs(t, err, context.Canceled)
}

func TestAdaptiveLimiter_RecordResult_UpdatesLimiter(t *testing.T) {
	al := NewAdaptiveLimiter(100, 1, 0.5)

	// Drive error rate above threshold to trigger minRPS
	for i := 0; i < 100; i++ {
		al.RecordResult(true)
	}

	require.InDelta(t, 1.0, al.effectiveRPS(), 1e-9)
}
