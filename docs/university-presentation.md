# SentinelBot: a transparent authentication-monitoring pipeline for Linux hosts

Presentation text for a 15-minute university defense. Slide titles are in bold. The numbers are the measured values in `docs/results/` and the status markers come from `docs/evaluation.md`.

## Title

**SentinelBot: transparent detection and correlation of Linux authentication events**

Author: Alireza. Supervisor and institution: to be added.

## Abstract

SentinelBot is a prototype for monitoring authentication activity on Linux servers. An agent turns sshd and sudo log lines into typed events. A server applies five rules with explicit thresholds, scores each detection with a documented heuristic, and groups related detections into incidents. An optional analyst module explains an incident from its structured facts; detection does not depend on it. The system was built as a laboratory project, tested with unit tests and six synthetic scenarios, and measured offline at 100 to 50,000 log lines. Its detection accuracy on real attack traffic has not been measured.

## Problem

**Why this matters.** Authentication is a common entry point for attacks on exposed SSH servers. A single failed login is normal; a pattern of failures, a root login, or a new privileged process is not. Log files record all of these, mixed together, with no state and no grouping.

**Why it is hard.** Lines are unstructured and change between software versions. An attack produces hundreds of lines, and its meaning is in the pattern. Simple alert rules produce many duplicate alerts.

## Objectives

- O1: typed, validated events from sshd and sudo messages.
- O2: five rules with explicit thresholds.
- O3: a score that can be reproduced from its stored factors.
- O4: grouping of related detections into one incident.
- O5: AI explanation separated from detection and measurable.
- O6: role-based access control on the API.
- O7: a reproducible, measured offline pipeline.
- O8: deployment on one host and on a two-node cluster.

Status and evidence for each objective are in `docs/objectives.md`.

## Architecture

**Pipeline.** Host logs → agent (parse, normalize, batch) → server (validate, detect, score, correlate, store) → dashboard, alerts, metrics. The AI step is last and optional.

**Why detection is on the server.** It sees all hosts with one set of rules, and a compromised agent cannot set conclusions. The cost is that a silent agent produces no alerts.

Diagrams are in `docs/diagrams.md`.

## Technologies

Python 3.12 with pydantic models shared by agent and server; FastAPI for the API; PostgreSQL for storage; Redis optionally for shared windows; Prometheus and Grafana for metrics; Next.js for the dashboard; Docker Compose and Kubernetes for deployment. Reasons and alternatives are in `docs/technology-decisions.md`.

## Security model

- **Assets:** host telemetry, incidents, service key, user accounts, signing secret, database.
- **Actors:** remote attacker, attacker controlling log text, compromised agent, dashboard user, network attacker, supply-chain attacker.
- **Method:** STRIDE per trust boundary (`docs/threat-model.md`).
- **Findings:** eleven findings in `docs/security-analysis.md`. One was fixed in this review: the agent's key bypassed role checks and carried admin rights. It is now limited to reading and ingesting, and the change is tested.
- **Open:** a shared key for all agents, no TLS by default between agent and API, tokens in local storage, unlimited ingest.

## Detection methodology

Five rules: SSH brute force (5 failures in 300 s per source), root login (every occurrence), authentication burst (30 attempts in 300 s per host), new root-owned process (against a baseline), and unexpected listening port (against an allowlist or baseline). Each has a cooldown so one attack produces a bounded number of detections. Each rule is specified in `docs/detection-rules.md`.

## Risk scoring

A heuristic score from 0 to 100: base points for the rule, plus repetition, combination and privilege points, capped and mapped to a severity band. Each detection stores its factors, so the score can be checked by hand. Example: a brute force followed by a root login from the same address gives the root detection 35 + 10 + 15 = 60.

**Honest statement.** The score is not validated and is not a probability. A critical review found that the repetition factor is nearly inactive for the brute-force rule because of the cooldown, and that the score has no outcome or asset factor. The redesign is documented in `docs/risk-scoring.md` and is not implemented.

## AI component

The model reads a structured summary of an incident: rule names, counts, times, source, host and status. It does not read raw logs. Its reply must match a schema; its confidence is capped at 0.5 when there are fewer than three detections; any failure falls back to fixed rule-based text. The model cannot change status, severity or the host.

**Honest statement.** Its explanation quality is not yet measured. Its value is an assumption until that measurement exists.

## Experimental methodology

- Six synthetic scenarios through the real agent, detection and correlation CLIs, with expected results written before each run. Uses documentation-only IP addresses.
- An offline benchmark that runs the same CLIs on generated logs of 100, 1,000, 10,000 and 50,000 lines, repeated three times, with wall time, CPU time and peak memory per stage.
- Unit and integration tests: 85 agent tests, 89 detection tests, and 115 backend tests passing with PostgreSQL tests run in CI.

## Results

| Result | Value | Status |
| --- | --- | --- |
| Lab scenarios matching expected output | 6 of 6 | Measured, functional only |
| Agent throughput at 10,000 and 50,000 lines | about 21,000 lines per second | Measured, one Windows laptop |
| Peak memory per stage | about 30 to 60 MB | Measured |
| Detection rate on labeled data | not measured | NOT YET MEASURED |
| False-positive rate on labeled data | not measured | NOT YET MEASURED |
| Detection latency | not measured | NOT YET MEASURED |
| API response time and database impact | not measured | NOT YET MEASURED |
| AI explanation quality | not measured | NOT YET MEASURED |

**Finding from the benchmark.** The file source reads 1 MiB per collection cycle. A 50,000-line log is therefore drained over several cycles, and alert latency grows with backlog size. The benchmark initially missed this and reported 10,196 of 50,000 events; the method now runs cycles until the file is consumed.

## Limitations

Linux only. Rule-based detection misses attacks that its rules do not describe. False positives and negatives are not measured on real traffic. The score is heuristic. Incidents do not span hosts. The baseline is shared across nodes in a cluster. The Docker-security scenario from the original plan is not implemented. The system is not a SIEM and not an EDR. Full list: `docs/limitations.md`.

## Future work

Labeled evaluation dataset; measured API and database performance; a file-source switch for the lab; per-agent keys and TLS; the redesigned risk score; per-host baselines. Deferred items and their reasons are in `docs/future-work.md`.

## Conclusion

SentinelBot shows that five explainable authentication rules, a documented score, and an incident model can be built, tested and measured on synthetic data in about five thousand lines of Python. It does not show how well they work on real attacks, and it says so. The most useful contributions are the explicit trade-offs (cooldowns, the server-side placement, the AI boundary), the security review that found and fixed a real privilege problem, and the measured limitations that point to the next work.
