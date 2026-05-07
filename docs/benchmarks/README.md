# Benchmark Suite

This directory contains reproducible benchmark guidance and baseline outputs for large-cluster scenarios.

## Scope

The current benchmark harness exercises the reconciler hot path with:

- workload-count scaling
- scanner-mix variation
- scanner failure modes

Benchmarks are implemented in `internal/reconciler/reconcile_benchmark_test.go`.

## Run Locally

Run all benchmark functions across the repository without running normal tests:

```bash
make bench
```

Run the current reconciler-focused benchmark directly:

```bash
make bench-reconcile
```

Generate a repo-wide baseline report output (three runs, benchtime=1x):

```bash
make bench-report
```

The latest raw output is written to `docs/benchmarks/results/latest.txt`.

## Reproducibility Notes

- Prefer a quiet machine (close heavy apps/processes).
- Capture `go version`, CPU model, and memory in the baseline report.
- Use the same command flags (`-run '^$' -bench . -benchmem -benchtime=1x -count=3`) for version-to-version comparison.
- `-run '^$'` disables normal tests, so benchmark runs do not execute unit tests.

## CI

`.github/workflows/benchmarks.yml` runs `go test -run '^$' -bench . -benchmem -benchtime=1x ./...` on pushes to `main`, pull requests, scheduled runs, and manual dispatch.

That command picks up any future benchmark added under packages such as state, scanners, or reconciler while still skipping normal unit tests.
