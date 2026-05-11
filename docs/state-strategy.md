# State Strategy for Scale (Issue #11)

## Problem

The current dedupe/state store uses a single ConfigMap. This is simple for MVP, but it has scale risks:

- ConfigMap object size limits can be hit in high-churn clusters.
- Frequent update traffic can create API server pressure.
- A single object creates write contention and retry churn.
- Current behavior requires write RBAC for ConfigMaps.

## Hard Constraint

For security and platform compatibility, the reporter should support a strict readonly runtime mode:

- No workload annotations or workload updates.
- No write operations to workload resources.
- Kubernetes API writes are limited to creating Events only.

This means state strategy must not depend on mutating workloads and should avoid requiring Kubernetes state writes in readonly deployments.

## Goals

- Keep default deployment simple.
- Bound state growth and make usage observable.
- Provide a migration path from ConfigMap state.
- Support strict readonly mode (except Event creation).

## Non-goals

- Introduce CRDs as the primary state backend.
- Add admission-webhook or mutating behavior.
- Persist dedupe state in workload metadata.

## Proposed Backend Modes

### 1. `configmap` (default)

Use ConfigMap-backed durable state as the source of truth, with an in-process hardened cache in front of it.

Data flow:

- Read path: memory cache first, ConfigMap fallback.
- Write path: write-through to ConfigMap, then update cache.
- Reconcile loop: periodic cache cleanup and bounded size enforcement.

Hardening expectations for cache:

- TTL-based expiration.
- Max-entry cap with LRU eviction.
- Per-key lock or singleflight to reduce duplicate concurrent writes.
- Metrics for hit rate, evictions, stale reads, and fallback rate.

Why this is the default:

- Preserves dedupe state across restarts/rollouts.
- Keeps operational model simple for most clusters.
- Reduces API pressure versus ConfigMap-only reads by absorbing hot keys in memory.

### 2. `memory` (strict readonly profile)

Use an in-process bounded cache (TTL + max entries) keyed by scanner/image identity.

- Pros:
  - Zero Kubernetes write permissions required.
  - No API server state pressure.
  - Works with strict readonly RBAC.
- Cons:
  - State is lost on restart/rollout.
  - Deduplication window is best-effort, not durable.

### 3. `external` (optional durable readonly mode)

Use an external key-value store (for example Redis or managed KV) for durable dedupe without Kubernetes writes.

- Pros:
  - Durable and horizontally scalable.
  - Keeps Kubernetes API access readonly.
- Cons:
  - Adds operational dependency and network policy needs.
  - Requires credentials and rotation model.

Recommended initial contract:

- `Get(key)` / `Set(key, ttl)` / `Delete(key)`
- Optional compare-and-set for race-safe dedupe.

## Size and Sharding Constraints

Kubernetes object limits are a hard design input for scale readiness:

- ConfigMaps and Secrets have size limits (commonly enforced around 1 MiB object payload).
- A single state object will not scale safely in high-churn clusters.

Required strategy for ConfigMap mode:

- Shard state across multiple ConfigMaps (`state-0..N`) using deterministic hashing.
- Keep shard count configurable and documented with sizing guidance.
- Track per-shard entry count and approximate bytes.
- Trigger bounded pruning/compaction when shard thresholds are crossed.

## Decision

Adopt a multi-backend state interface with explicit `state.backend` configuration:

- `configmap` + hardened memory cache as default for durable, scalable baseline.
- `memory` for strict readonly operation.
- `external` as an opt-in scalable durable option.

Default behavior should remain persistent and operationally simple, while still providing a strict readonly profile and an external durable readonly option.

## Configuration Shape

Suggested config additions:

```yaml
state:
  backend: configmap # configmap | memory | external
  ttl: 72h
  memory:
    maxEntries: 100000
    enableReadThroughCache: true
  configmap:
    namespace: security
    namePrefix: komodor-security-reporter-state
    shards: 16
    maxEntriesPerShard: 20000
    maxBytesPerShard: 800Ki
  external:
    driver: redis
    address: redis.security.svc:6379
    tls: true
```

## Metrics and Observability

Add backend-agnostic state metrics:

- `image_vuln_watcher_state_entries` (gauge)
- `image_vuln_watcher_state_bytes` (gauge, when measurable)
- `image_vuln_watcher_state_evictions_total` (counter)
- `image_vuln_watcher_state_prunes_total` (counter)
- `image_vuln_watcher_state_backend_operations_total{backend,op,result}` (counter)

Keep existing hit/miss/update metrics and add `backend` labels where useful.

## RBAC Profiles

Define two supported RBAC profiles:

- `readonly-events`:
  - read namespaces/workloads
  - create events
  - no ConfigMap write permissions
- `stateful-configmap`:
  - same as above
  - plus ConfigMap get/list/create/update/patch for state backend

Default Helm profile should map to `stateful-configmap` with sharded ConfigMap state + in-memory cache.

This allows secure-by-default operation in environments with strict platform controls.

## Migration Plan

1. Introduce state interface and default `configmap` backend with cache.
2. Add deterministic sharding and per-shard thresholds.
3. Add telemetry and documented SLO thresholds for state size/churn.
4. Add strict readonly `memory` profile.
5. Add optional `external` backend driver (Redis first).
6. Update Helm chart to expose backend selection, shard sizing, and RBAC profile switch.
7. Publish migration guides: single ConfigMap -> sharded ConfigMap, configmap -> memory, and configmap -> external.

## Testing Plan

- Unit tests:
  - backend contract behavior (`Get/Set/Delete`) for all backends.
  - TTL expiry and pruning behavior.
  - LRU cap behavior and eviction metrics for `memory`.
- Race/concurrency tests:
  - concurrent scanner writes for same image/scanner key.
- Load tests:
  - high-churn synthetic workloads measuring state growth, API write rate, and shard balance.
  - object-size pressure tests validating rollover/sharding before per-object limits are reached.
- Integration tests:
  - readonly profile validates no ConfigMap mutations are attempted.
  - events still publish successfully under readonly RBAC.

## Rollout Plan

- Phase 1: Implement backend abstraction + default ConfigMap backend + hardened memory cache.
- Phase 2: Add ConfigMap sharding/pruning + size guardrails + telemetry.
- Phase 3: Add strict readonly memory profile and RBAC profile switch.
- Phase 4: Add external durable backend (Redis).

## Success Criteria

- State growth remains bounded under churn.
- State behavior is observable through metrics.
- Users can run with strict readonly permissions (except Event creation).
- Migration paths are documented and test-backed.
