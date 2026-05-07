package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
)

const (
	// DefaultStdoutLimit is the default maximum stdout size (100 MB).
	DefaultStdoutLimit int64 = 100 * 1024 * 1024
	// DefaultStderrLimit is the default maximum stderr size (10 MB).
	DefaultStderrLimit int64 = 10 * 1024 * 1024
)

// Runner executes commands with resource limits.
type Runner struct {
	StdoutLimitBytes int64
	StderrLimitBytes int64
}

// NewRunner creates a new command runner with default limits.
func NewRunner() *Runner {
	return &Runner{
		StdoutLimitBytes: DefaultStdoutLimit,
		StderrLimitBytes: DefaultStderrLimit,
	}
}

// Run executes a command and returns stdout and stderr output.
// Output is limited to prevent excessive memory usage.
func (r *Runner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	return r.RunAllowExitCodes(ctx, nil, name, args...)
}

// RunAllowExitCodes executes a command and treats the provided exit codes as successful.
func (r *Runner) RunAllowExitCodes(ctx context.Context, allowedExitCodes []int, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 - The command and args are controlled by the application's config and not user input.

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	cmd.Stdout = &limitedWriter{
		writer: &stdout,
		limit:  r.StdoutLimitBytes,
	}
	cmd.Stderr = &limitedWriter{
		writer: &stderr,
		limit:  r.StderrLimitBytes,
	}

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && containsExitCode(allowedExitCodes, exitErr.ExitCode()) {
			return stdout.Bytes(), stderr.Bytes(), nil
		}

		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("run %q: %w", name, err)
	}

	return stdout.Bytes(), stderr.Bytes(), nil
}

func containsExitCode(allowedExitCodes []int, exitCode int) bool {
	for _, allowed := range allowedExitCodes {
		if allowed == exitCode {
			return true
		}
	}

	return false
}

// limitedWriter writes to an underlying writer but stops after a limit.
type limitedWriter struct {
	writer io.Writer
	limit  int64
	seen   int64
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	remaining := w.limit - w.seen
	if remaining <= 0 {
		// Silently drop excess data
		return len(p), nil
	}

	toWrite := p
	if int64(len(p)) > remaining {
		toWrite = p[:remaining]
	}

	n, err := w.writer.Write(toWrite)
	w.seen += int64(n)

	return len(p), err
}
