# Simplification report

This report lists the parts of SentinelBot that add complexity beyond what the academic goals need. For each one it says what it costs, what it gives, and what I recommend.

No code was removed in this round. Removing working code without a way to re-test the whole system risks breaking the deployment that was verified. The items below are recommendations. Each one needs its own change and its own test run.

## Recommended simplifications

### 1. Two state backends behind one interface

- **Where:** `detection/src/sentinelbot_detection/state.py` has `MemoryState` and `RedisState`, plus `RedisWindow` and `RedisCooldown`.
- **Cost:** a protocol, two implementations, and a test file that needs a real Redis to run the Redis half.
- **Gain:** several API workers can share windows and cooldowns. The Redis version is also the one that makes the Kubernetes deployment correct.
- **Recommendation:** keep it. It is a real requirement of the multi-worker deployment, and it is small.
- **Explain it as:** an interface with two backends, so the rules do not know where their state lives.

### 2. Two incident stores

- **Where:** `IncidentStore` writes a JSON file for the CLI. `SqlIncidentStore` writes PostgreSQL for the API.
- **Cost:** two implementations of persistence for the same object. The CLI has to be kept in sync with the API.
- **Gain:** the CLI runs without a database, which makes the lab and the detection tests possible.
- **Recommendation:** keep the CLI store for the lab, but state clearly that the API uses PostgreSQL. Do not describe the JSON store as production storage. Its own docstring says PostgreSQL replaces it, which is out of date and should be corrected.

### 3. Two rate limiters

- **Where:** `MemoryRateLimiter` and `RedisRateLimiter` in `backend/src/sentinelbot_backend/ratelimit.py`.
- **Cost:** small, but it is one more thing to test.
- **Recommendation:** keep. The duplication is about thirty lines.

### 4. Kubernetes, Prometheus and Grafana in addition to Compose

- **Where:** `k8s/`, `monitoring/`.
- **Cost:** a large amount of YAML that has to be explained, and it duplicates the Compose setup.
- **Gain:** shows a DaemonSet agent on several nodes, which is the scale story of the project.
- **Recommendation:** keep Kubernetes, because it was tested on a real cluster and it supports the deployment chapter. Explain it as the same components in another packaging, not as a second system.

### 5. Email alert escalation and cooldown

- **Where:** `alerts/src/sentinelbot_alerts/policy.py`.
- **Cost:** a second cooldown in addition to the rule cooldown.
- **Gain:** the rule cooldown limits detections, and the alert cooldown limits emails for one incident. They protect different resources.
- **Recommendation:** keep, and explain the difference.

### 6. CI image scanning with Trivy

- **Where:** `.github/workflows/ci.yml`.
- **Cost:** it caused several failed runs in this project, mostly from base image packages and npm's bundled dependencies.
- **Gain:** shows a security step in the pipeline.
- **Recommendation:** keep. It is a standard step, and the fixes are documented in `docs/security.md`.

## Simplifications not recommended

- **Removing the AI analyst.** It is a small module, it is cleanly separated from detection, and it is the subject of an explicit defense question. Removing it would reduce the project's academic value.
- **Removing the risk score.** It is the part that most needs a defense, and it is simple enough to explain on a whiteboard.
- **Removing correlation.** It is the link between events and what an analyst acts on.

## Needed to make the lab reproducible on Linux

- **Force the auth file source.** The agent prefers the systemd journal when `journalctl` is present, so the lab's synthetic log is ignored on Linux. A setting such as `SENTINEL_AUTH_SOURCE=file` would fix this. This is a small code change and should be made with a test.

## Comments and naming

I did not add comments across the code, and I did not rename classes. The names already match the terms in the project's documents: `Event`, `Detection` (as `*_detected` event types), `Incident`, `RiskScorer`, `Correlator`, `Collector`. Rename work would touch many files and tests at once. It is better done as its own change.

One comment is wrong and should be fixed: the docstring of `IncidentStore` says Phase 7 will replace the file with PostgreSQL, which is already the case for the API. It should say that the file store is used by the CLI.
