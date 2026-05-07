package command

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRunnerSuccess(t *testing.T) {
	r := NewRunner()
	ctx := context.Background()

	stdout, stderr, err := r.Run(ctx, "echo", "hello")

	require.NoError(t, err)
	require.Contains(t, string(stdout), "hello")
	require.Empty(t, stderr)
}

func TestRunnerTimeout(t *testing.T) {
	r := NewRunner()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, _, err := r.Run(ctx, "sleep", "10")

	require.Error(t, err)
	require.Contains(t, err.Error(), "run")
}

func TestRunnerStderrCapture(t *testing.T) {
	r := NewRunner()
	ctx := context.Background()

	// bash -c writes to stderr
	_, stderr, _ := r.Run(ctx, "bash", "-c", "echo error >&2")

	require.Contains(t, string(stderr), "error")
}

func TestRunnerOutputLimit(t *testing.T) {
	r := &Runner{
		StdoutLimitBytes: 10,
		StderrLimitBytes: 10,
	}
	ctx := context.Background()

	// This should produce more than 10 bytes
	stdout, _, _ := r.Run(ctx, "echo", "this is a very long message")

	// We should have received less than the full output
	require.True(t, len(stdout) <= 10, "output should be limited to 10 bytes")
}

func TestRunnerAllowedExitCode(t *testing.T) {
	r := NewRunner()
	ctx := context.Background()

	stdout, stderr, err := r.RunAllowExitCodes(ctx, []int{1}, "bash", "-c", "echo found && exit 1")

	require.NoError(t, err)
	require.Contains(t, string(stdout), "found")
	require.Empty(t, stderr)
}
