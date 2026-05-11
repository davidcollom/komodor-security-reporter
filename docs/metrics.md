# Metrics Reference

All metrics are exposed on the controller-runtime metrics endpoint (default `:8080/metrics`) under the `image_vuln_watcher_` prefix.

---

## Scanning

### `image_vuln_watcher_scans_total` · Counter

Total vulnerability scans attempted.

```promql
# Scan throughput (scans per second, 5-minute window)
rate(image_vuln_watcher_scans_total[5m])
```

---

### `image_vuln_watcher_scan_errors_total` · Counter

Total scan failures (all error classes).

```promql
# Scan error rate as a fraction of total scans
rate(image_vuln_watcher_scan_errors_total[5m])
  / rate(image_vuln_watcher_scans_total[5m])

# Alert: error rate above 10% over 10 minutes
rate(image_vuln_watcher_scan_errors_total[10m])
  / rate(image_vuln_watcher_scans_total[10m]) > 0.1
```

---

### `image_vuln_watcher_scan_duration_seconds` · Histogram

Per-scan wall-clock duration including retries.

```promql
# p50 / p95 / p99 scan latency
histogram_quantile(0.50, rate(image_vuln_watcher_scan_duration_seconds_bucket[5m]))
histogram_quantile(0.95, rate(image_vuln_watcher_scan_duration_seconds_bucket[5m]))
histogram_quantile(0.99, rate(image_vuln_watcher_scan_duration_seconds_bucket[5m]))

# Alert: p99 scan latency above 5 minutes
histogram_quantile(0.99, rate(image_vuln_watcher_scan_duration_seconds_bucket[5m])) > 300
```

---

### `image_vuln_watcher_scans_in_flight` · Gauge

Number of scans currently executing.

```promql
# Current concurrency — compare against scanners.concurrency config
image_vuln_watcher_scans_in_flight
```

---

### `image_vuln_watcher_scan_queue_depth` · Gauge

Number of scans waiting for a concurrency slot.

```promql
# Alert: queue backing up (scans waiting for slots)
image_vuln_watcher_scan_queue_depth > 10
```

---

## Scanner resilience

### `image_vuln_watcher_scanner_error_class_total` · CounterVec · labels: `scanner`, `class`

Error counts broken down by scanner name and class (`timeout`, `transient`, `permanent`, `circuit_open`).

```promql
# Error rate per scanner/class over 5 minutes
rate(image_vuln_watcher_scanner_error_class_total[5m])

# Top 5 scanner/class combinations by error rate
topk(5, rate(image_vuln_watcher_scanner_error_class_total[5m]))

# Permanent error rate per scanner (these will not be retried)
rate(image_vuln_watcher_scanner_error_class_total{class="permanent"}[5m])

# Alert: any scanner accumulating permanent errors
rate(image_vuln_watcher_scanner_error_class_total{class="permanent"}[10m]) > 0
```

---

### `image_vuln_watcher_scanner_circuit_state` · GaugeVec · label: `scanner`

Circuit breaker state per scanner: `0` = closed (healthy), `1` = open (failing), `2` = half-open (recovering).

```promql
# Show all scanners with an open circuit
image_vuln_watcher_scanner_circuit_state == 1

# Alert: any scanner circuit open for more than 2 minutes
image_vuln_watcher_scanner_circuit_state == 1

# Track half-open probes
image_vuln_watcher_scanner_circuit_state == 2
```

---

### `image_vuln_watcher_scanner_skipped_total` · CounterVec · labels: `scanner`, `reason`

Scans skipped without being attempted. `reason` values include `circuit_open`, `deduped`.

```promql
# Skipped scan rate per scanner and reason
rate(image_vuln_watcher_scanner_skipped_total[5m])

# Alert: scans being skipped because circuit is open
rate(image_vuln_watcher_scanner_skipped_total{reason="circuit_open"}[5m]) > 0
```

---

## Images

### `image_vuln_watcher_images_observed_total` · Counter

Images seen from Kubernetes workloads.

```promql
rate(image_vuln_watcher_images_observed_total[5m])
```

---

### `image_vuln_watcher_images_resolved_total` · Counter

Images successfully resolved to digest.

```promql
# Digest resolution success rate
rate(image_vuln_watcher_images_resolved_total[5m])
  / rate(image_vuln_watcher_images_observed_total[5m])
```

---

### `image_vuln_watcher_image_resolution_errors_total` · Counter

Failed digest resolution attempts.

```promql
rate(image_vuln_watcher_image_resolution_errors_total[5m])
```

---

## Publishing

### `image_vuln_watcher_events_published_total` · Counter

Events successfully sent to Komodor.

```promql
rate(image_vuln_watcher_events_published_total[5m])
```

---

### `image_vuln_watcher_event_publish_errors_total` · Counter

Failed publish attempts.

```promql
# Alert: publish errors
rate(image_vuln_watcher_event_publish_errors_total[5m]) > 0
```

---

### `image_vuln_watcher_dedupe_hits_total` · Counter

Events suppressed by the deduplication window.

```promql
# Deduplication effectiveness (fraction of findings suppressed)
rate(image_vuln_watcher_dedupe_hits_total[5m])
  / (rate(image_vuln_watcher_events_published_total[5m]) + rate(image_vuln_watcher_dedupe_hits_total[5m]))
```

---

### `image_vuln_watcher_event_skips_total` · CounterVec · label: `reason`

Events skipped before publishing. `reason` values include `below_severity`, `clean_scan`, `deduped`.

```promql
rate(image_vuln_watcher_event_skips_total[5m])

# Break down by reason
topk(5, rate(image_vuln_watcher_event_skips_total[5m]))
```

---

## Reconciliation

### `image_vuln_watcher_reconcile_runs_total` · CounterVec · label: `result`

Full reconciliation loop executions. `result` values: `success`, `error`.

```promql
rate(image_vuln_watcher_reconcile_runs_total[5m])

# Alert: reconcile error rate
rate(image_vuln_watcher_reconcile_runs_total{result="error"}[5m]) > 0
```

---

### `image_vuln_watcher_workloads_reconciled_total` · CounterVec · label: `result`

Individual workload reconciliations.

```promql
# Workload reconciliation throughput
rate(image_vuln_watcher_workloads_reconciled_total[5m])

# Error fraction
rate(image_vuln_watcher_workloads_reconciled_total{result="error"}[5m])
  / rate(image_vuln_watcher_workloads_reconciled_total[5m])
```

---

## State store

### `image_vuln_watcher_state_lookups_total` · CounterVec · label: `result`

State store read attempts. `result`: `hit`, `miss`, `error`.

```promql
# State cache hit rate
rate(image_vuln_watcher_state_lookups_total{result="hit"}[5m])
  / rate(image_vuln_watcher_state_lookups_total[5m])

# Alert: state lookup errors
rate(image_vuln_watcher_state_lookups_total{result="error"}[5m]) > 0
```

---

### `image_vuln_watcher_state_updates_total` · CounterVec · label: `result`

State store write attempts. `result`: `success`, `error`.

```promql
rate(image_vuln_watcher_state_updates_total[5m])

# Alert: state write errors
rate(image_vuln_watcher_state_updates_total{result="error"}[5m]) > 0
```

---

## gocache layer

These metrics reflect the in-process gocache layer sitting in front of the durable state backend.

### `image_vuln_watcher_cache_hits_total` · CounterVec · label: `backend`
### `image_vuln_watcher_cache_misses_total` · CounterVec · label: `backend`
### `image_vuln_watcher_cache_evictions_total` · CounterVec · label: `backend`

```promql
# Cache hit rate per backend
rate(image_vuln_watcher_cache_hits_total[5m])
  / (rate(image_vuln_watcher_cache_hits_total[5m]) + rate(image_vuln_watcher_cache_misses_total[5m]))

# Eviction rate — a rising eviction rate with memory backend suggests maxEntries is too low
rate(image_vuln_watcher_cache_evictions_total[5m])

# Alert: cache evictions accelerating (may indicate memory backend cap too tight)
rate(image_vuln_watcher_cache_evictions_total[5m]) > 5
```
