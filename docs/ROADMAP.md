# Roadmap

This roadmap is formatted for direct use in GitHub Milestones and Issues.

## Planning Conventions

- Milestone naming:
  - `v0.next.0 - Production Baseline`
  - `v0.next1.0 - Actionable Signal`
  - `v0.next2.0 - Scale Readiness`
- Issue title format: `[v0.next.0] Area - Outcome`
- Suggested labels:
  - `area/security`
  - `area/scanner-runtime`
  - `area/policy`
  - `area/registry`
  - `area/events`
  - `area/operations`
  - `area/performance`
  - `area/state`
  - `kind/feature`
  - `kind/refactor`
  - `kind/docs`
  - `kind/testing`
  - `priority/p0`
  - `priority/p1`
  - `priority/p2`

## Milestones

| Milestone | Goal | Exit Criteria |
| --- | --- | --- |
| v0.next.0 - Production Baseline | Harden release security and scanner reliability while reducing alert noise | Signed releases, SBOMs, scanner resilience controls, dry-run policy support |
| v0.next1.0 - Actionable Signal | Improve coverage and event quality for remediation teams | Better workload coverage, stronger resolver diagnostics, richer event payloads |
| v0.next2.0 - Scale Readiness | Prepare for large-cluster and enterprise-scale operations | State strategy, performance controls, benchmark evidence |

## Release Train (SemVer-Aligned, Not Fixed)

Milestones map to minor releases, but exact minor version numbers are intentionally flexible.

- `Production Baseline` ships as the next available `v0.x.0` minor when its exit criteria are met.
- `Actionable Signal` ships as the next available `v0.x.0` minor when its exit criteria are met.
- `Scale Readiness` ships as the next available `v0.x.0` minor when its exit criteria are met.
- Patch releases (`v0.x.y`) are for bug fixes and non-breaking hardening only.

Example sequence (illustrative only): `Production Baseline -> v0.7.0`, `Actionable Signal -> v0.8.0`, `Scale Readiness -> v0.9.0`.

### v1.0.0 Readiness Gate

Release `v1.0.0` after all milestone exit criteria are complete and the following checks pass:

- All `priority/p0` and `priority/p1` roadmap issues are closed or explicitly deferred with rationale.
- Compatibility matrix is green for supported Kubernetes/scanner versions.
- Security policy and vulnerability reporting process are finalized and tested.
- Upgrade and migration notes are documented for users moving from `v0.x`.
- Benchmarks and SLO targets are published and reviewed.

## Issue Backlog

### v0.next.0 - Production Baseline

#### [v0.next.0] Security - Expand threat model and disclosure workflow docs

- Type: `kind/docs`
- Priority: `priority/p1`
- Labels: `area/security`, `kind/docs`, `priority/p1`
- Scope:
  - Add threat model section covering trust boundaries and abuse cases.
  - Ensure security reporting path and response ownership are explicit.
- Acceptance Criteria:
  - Threat model updated in docs.
  - Security reporting flow is clear for external researchers.
- Dependencies: none

#### [v0.next.0] Scanner Runtime - Add retries, timeout policy, and circuit-breaker behavior

- Type: `kind/feature`
- Priority: `priority/p0`
- Labels: `area/scanner-runtime`, `kind/feature`, `priority/p0`
- Scope:
  - Per-scanner retry policy and timeout defaults.
  - Circuit-breaker behavior for repeated scanner failure.
  - Failure-class metrics and backlog visibility metrics.
- Acceptance Criteria:
  - Repeated failures in one scanner do not stall global scan progress.
  - Metrics expose scanner error class and timeout rates.
- Dependencies: none

#### [v0.next.0] Policy - Add dry-run and delta-only publish modes

- Type: `kind/feature`
- Priority: `priority/p0`
- Labels: `area/policy`, `kind/feature`, `priority/p0`
- Scope:
  - Dry-run mode for publish decision logging only.
  - Delta-only policy mode (new criticals, severity increase, new exploitable findings).
  - Baseline suppression window for onboarding.
- Acceptance Criteria:
  - Policy behavior can be validated without event emission.
  - Duplicate/no-op event volume is reduced in production.
- Dependencies: scanner runtime telemetry preferred

### v0.next1.0 - Actionable Signal

#### [v0.next1.0] Coverage - Add optional support for additional workload kinds

- Type: `kind/feature`
- Priority: `priority/p1`
- Labels: `area/registry`, `kind/feature`, `priority/p1`
- Scope:
  - Add optional support for additional workload kinds (for example Argo Rollouts).
- Acceptance Criteria:
  - New workload kind support is config-gated and documented.
  - Integration tests cover extraction and reconciliation path.
- Dependencies: none

#### [v0.next1.0] Registry - Improve digest resolver failure taxonomy and fallback behavior

- Type: `kind/feature`
- Priority: `priority/p0`
- Labels: `area/registry`, `kind/feature`, `priority/p0`
- Scope:
  - Improve resolver errors into actionable classes (auth, network, not found, throttling).
  - Add optional tag-based fallback scan mode when digest resolution fails.
- Acceptance Criteria:
  - Resolver failures are categorized in logs/metrics.
  - Operators can distinguish auth failures from transient errors quickly.
- Dependencies: none

#### [v0.next1.0] Events - Enrich findings with risk and remediation context

- Type: `kind/feature`
- Priority: `priority/p1`
- Labels: `area/events`, `kind/feature`, `priority/p1`
- Scope:
  - Normalize fix availability and source attribution across scanners.
  - Add optional EPSS/CISA KEV-style hints when available.
  - Improve top findings ranking strategy.
- Acceptance Criteria:
  - Event payloads are consistent across scanners.
  - Findings in events are demonstrably more actionable.
- Dependencies: resolver taxonomy issue

#### [v0.next1.0] Operations - Add config validation command and runbook docs

- Type: `kind/feature`
- Priority: `priority/p1`
- Labels: `area/operations`, `kind/feature`, `kind/docs`, `priority/p1`
- Scope:
  - Add config lint/validate command for CI and local use.
  - Publish runbook sections for scanner down, auth drift, and dedupe growth.
  - Add example config profiles for Trivy-only, Trivy+Snyk, Trivy+Wiz, Trivy+Clair.
- Acceptance Criteria:
  - Invalid config fails fast with actionable errors.
  - Runbook steps exist for top operational failure modes.
- Dependencies: none

### v0.next2.0 - Scale Readiness

#### [v0.next2.0] State - Define scalable state backend strategy

- Type: `kind/feature`
- Priority: `priority/p1`
- Labels: `area/state`, `kind/feature`, `priority/p1`
- Scope:
  - Evaluate ConfigMap viability at scale.
  - Default to persistent sharded ConfigMap state with a hardened in-memory cache layer.
  - Support strict readonly operation (no workload mutation, no state writes; Event creation only).
  - Define optional backend strategy (for example SQLite/PVC or external KV) while keeping no-CRD default.
  - Add compaction/pruning and state size telemetry.
- Acceptance Criteria:
  - State growth is bounded and observable.
  - Strategy decision and migration path documented.
- Plan: see [state-strategy.md](state-strategy.md)
- Dependencies: none

#### [v0.next2.0] Performance - Add concurrency controls and adaptive backpressure

- Type: `kind/feature`
- Priority: `priority/p1`
- Labels: `area/performance`, `kind/feature`, `priority/p1`
- Scope:
  - Namespace-level and scanner-level concurrency controls.
  - Adaptive rate limiting when scanners or APIs degrade.
  - Queue and latency telemetry improvements.
- Acceptance Criteria:
  - Stable processing latency under sustained churn.
  - Throughput remains predictable during downstream degradation.
- Dependencies: scanner runtime telemetry

#### [v0.next2.0] Performance - Add benchmark suite for large cluster scenarios

- Type: `kind/testing`
- Priority: `priority/p2`
- Labels: `area/performance`, `kind/testing`, `priority/p2`
- Scope:
  - Add benchmark scenarios for high workload count and scanner mix.
  - Capture baseline throughput and latency targets.
- Acceptance Criteria:
  - Benchmarks are reproducible in CI or a documented local harness.
  - Performance targets are version-tracked.
- Dependencies: concurrency controls

## Cross-Cutting Issues

### [Cross] Testing - Expand e2e and parser golden tests

- Type: `kind/testing`
- Priority: `priority/p1`
- Labels: `kind/testing`, `priority/p1`
- Scope:
  - Expand e2e coverage including failure injection.
  - Add parser golden tests for scanner normalization.
- Acceptance Criteria:
  - New regressions in parsing and scan/publish flow are caught in CI.
- Dependencies: none

### [Cross] Compatibility - Add supported Kubernetes and scanner version matrix in CI

- Type: `kind/testing`
- Priority: `priority/p2`
- Labels: `kind/testing`, `priority/p2`
- Scope:
  - Define and test support matrix for Kubernetes and scanner versions.
- Acceptance Criteria:
  - CI reports matrix status clearly for each supported lane.
- Dependencies: none

## Out of Scope (Unless Requirements Change)

- Admission control or deployment blocking behavior.
- Host runtime socket or hostPath-based scanning.
- Kubernetes Secret read RBAC for application credentials.
- Privileged scanner execution model.

## Suggested GitHub Setup

1. Create milestones: `v0.next.0 - Production Baseline`, `v0.next1.0 - Actionable Signal`, `v0.next2.0 - Scale Readiness`.
2. Create labels listed in Planning Conventions.
3. Create one issue per backlog entry and assign the matching milestone.
4. Start with all `priority/p0` items in `v0.next.0`, then schedule `priority/p1`.
