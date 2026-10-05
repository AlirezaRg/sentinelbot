# Detection engine

This document summarizes the detection engine and its review. Each rule's full specification (problem, input, algorithm, threshold, window, output, severity, risk contribution, false positives, false negatives and test case) is in `docs/detection-rules.md`.

## Design

- **Input:** normalized `Event` objects from the agent, processed in arrival order.
- **Rules:** five classes that each keep their own state through the `StateStore` interface (in memory or Redis).
- **Output:** events with `event_type` ending in `_DETECTED`, metadata that records the threshold and window, and a rule identifier.
- **Placement:** the API runs the engine in `Container.ingest()`. The CLI `sentinelbot-detect` runs the same engine on a file.

## Rules

| Rule | Detects | Source events | Threshold | Window | Cooldown | Severity |
| --- | --- | --- | --- | --- | --- | --- |
| `ssh_bruteforce` | Repeated failed SSH logins from one address | `ssh_login_failed` | 5 | 300 s | 900 s per address | high |
| `root_login` | Direct root login over SSH | `ssh_root_login` | every occurrence | none | 900 s per (address, user) | high |
| `auth_burst` | Many authentication attempts on one host | auth events | 30 | 300 s | 900 s per host | medium |
| `privileged_process` | New root-owned process compared with a baseline | `process_snapshot` | new (name, executable) | baseline | none | medium |
| `unexpected_port` | Listening port not on the allowlist or new since the baseline | `network_snapshot` | allowlist or baseline | baseline | 900 s per (protocol, port) | medium |

## Review

### What is good

- Each rule is short and states its threshold in one place.
- Cooldowns keep one attack from producing hundreds of detections.
- The root-login rule is deterministic and trivially testable.
- Baseline learning is explicit and bounded (the first snapshot is the baseline, and the process list is capped by CPU).
- Unit tests feed events with controlled timestamps and check outputs, including cooldown edges.

### What is weak

1. **Suppressed attempts are invisible.** After the first brute-force detection, later failures from the same source are counted in the window but produce nothing. Incidents therefore show one detection for many attempts. The lab `bruteforce` scenario demonstrates this (8 failures, 1 detection).
2. **`auth_burst` mixes successful and failed attempts** in one count. A busy but legitimate host can trigger it. The failed count is in the output, but the rule does not use it.
3. **`root_login` cannot tell authorized from unauthorized.** This is inherent to the signal, not a bug. It is correctly documented as a false-positive source.
4. **The baseline is shared across nodes** in a deployment, so a process that exists on one node looks new on another. This was observed in the Kubernetes test. Per-host baselines are the fix.
5. **Process and port rules depend on snapshots.** A process that starts and stops between snapshots is not seen. This is a false-negative source that depends on the collection interval.
6. **No rule covers Docker.** The lab plan's Docker scenario is not implemented, and it must not be presented as a feature.

### What should not be changed

- The five rules themselves. They cover the most common host authentication patterns and each has a clear meaning.
- The decision to keep detection on the server. Changing it would remove the cross-host view.

### What should be added only if justified

- A rule for successful logins from a source that had failures (an outcome rule). It needs the scorer change described in `risk-scoring.md` before it is useful, and it needs labeled data to justify its threshold.

## Testing approach

| Level | What | Where |
| --- | --- | --- |
| Unit | Each rule with controlled events | `detection/tests/test_rules.py` |
| Unit | Window and cooldown | `detection/tests/test_windows.py` |
| Integration | Redis-backed state | `detection/tests/test_redis_state.py` (needs Redis; runs in CI) |
| End to end, offline | Synthetic logs through the three CLIs | `scripts/lab/run_scenario.py` |
| Measurement | Throughput and resources | `scripts/lab/benchmark.py` |
