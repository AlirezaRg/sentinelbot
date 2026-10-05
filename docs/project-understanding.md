# Project understanding (audit)

This document is an audit of the repository as it exists at commit `e8ea1a8`. It states what each part does, which parts contain project logic, which are generated or boilerplate, and which parts are worth understanding deeply for a defense. It was written by reading the code, and each claim points to a file.

Size: about 5,100 lines of Python in `src/` directories, plus tests, a Next.js dashboard, SQL migrations, Dockerfiles, Kubernetes manifests and CI configuration.

## What the system does, in one paragraph

An agent on a Linux host turns authentication logs and system snapshots into structured events. A central API stores those events, runs detection rules on them, scores each detection, groups related detections into incidents, and sends alerts. A dashboard, Prometheus metrics and Grafana show the result. An optional analyst module explains an incident in words, from the same structured facts the rules produced.

## Components

| Component | Path | What it does | Project logic or boilerplate |
| --- | --- | --- | --- |
| Agent | `agent/` | Reads auth logs, samples processes, listening sockets and system health. Emits `Event` objects. | Project logic |
| Auth parsers | `agent/src/sentinelbot_agent/auth/parsers.py` | Regular expressions for sshd and sudo messages | Project logic (core of the pipeline) |
| Auth sources | `agent/src/sentinelbot_agent/auth/sources.py` | Reads the systemd journal (`journalctl`) or log files, keeps a read cursor, handles rotation | Project logic |
| Detection | `detection/` | Five rules, sliding windows, cooldowns, baseline learning | Project logic (core) |
| Risk scoring | `detection/src/sentinelbot_detection/scoring.py` | Heuristic 0-100 score and severity band | Project logic (core) |
| Correlation | `detection/src/sentinelbot_detection/correlation.py` | Groups detections into incidents, incident lifecycle | Project logic (core) |
| Redis state | `detection/src/sentinelbot_detection/state.py` | Shared sliding windows and cooldowns for several API workers | Project logic, optional |
| Database models | `database/` | SQLAlchemy tables and Alembic migrations | Project models, generated migration scaffolding |
| API | `backend/` | FastAPI routes, auth, ingest pipeline, metrics, rate limiting | Project logic |
| Alerts | `alerts/` | Email channel, severity filter, cooldown, escalation | Project logic |
| AI analyst | `ai/` | Rule-based explanation (always available), optional Anthropic call, strict output validation | Project logic |
| Dashboard | `frontend/` | Next.js pages that call the API | Mostly project UI; `create-next-app` scaffolding around it |
| Docker and Compose | `docker/`, `docker-compose.yml` | Images and the single-host stack | Configuration |
| Kubernetes | `k8s/` | Manifests for a two-node cluster | Configuration |
| Monitoring | `monitoring/` | Prometheus scrape config, Grafana datasource and dashboard JSON | Configuration |
| CI | `.github/workflows/ci.yml`, `dependabot.yml` | Lint, types, tests, image scans, dependency audit | Configuration |

## Files that are critical

These files contain the decisions a defense will focus on. Read them in this order:

1. `agent/src/sentinelbot_agent/models.py`: the `Event` model and the `EventType` and `Severity` enumerations. Everything else passes these objects around.
2. `agent/src/sentinelbot_agent/auth/parsers.py`: which log lines become events, and why "Invalid user" lines are ignored (they would double-count attempts).
3. `detection/src/sentinelbot_detection/rules.py`: the five rules.
4. `detection/src/sentinelbot_detection/windows.py` and `state.py`: sliding windows and cooldowns, the mechanism that makes rules time-based.
5. `detection/src/sentinelbot_detection/scoring.py`: the risk formula.
6. `detection/src/sentinelbot_detection/correlation.py`: incident grouping and lifecycle.
7. `backend/src/sentinelbot_backend/container.py`: `ingest()`, the order of the pipeline on the server.
8. `ai/src/sentinelbot_ai/analyst.py` and `prompts.py`: what the model is allowed to see and how its answer is checked.

## Algorithms in use

| Algorithm | Where | Notes |
| --- | --- | --- |
| Sliding time window with a count threshold | `SshBruteForceRule`, `AuthBurstRule` | Keeps timestamps of recent events per key and compares their count with a threshold |
| Cooldown (suppression for a fixed period) | Every rule | Prevents one ongoing attack from creating hundreds of detections |
| Set difference against a learned baseline | `PrivilegedProcessRule`, `UnexpectedListeningPortRule` | First snapshot is learned, later new items alert |
| Additive scoring with caps | `RiskScorer` | Points for rule, repetition, privilege, combination and reputation, clamped to 0-100 |
| Gap-based grouping | `Correlator` | A detection joins an open incident if it arrives within 1800 seconds of its last activity |
| Atomic file replacement | `IncidentStore.save`, `StateStore` | Write to `*.tmp`, then `os.replace`, so a crash never leaves a half-written file |
| Read cursor with rotation detection | `FileSource`, `JournalSource` | Remembers the position in each log, resets when the file shrinks or is replaced |

## Dependencies that matter

- **psutil**: process and socket snapshots in the agent.
- **pydantic v2**: validates every event and every API payload. The `Event` model is the contract between agent and server.
- **FastAPI and uvicorn**: HTTP API.
- **SQLAlchemy 2 and Alembic**: database access and schema migrations.
- **redis-py and fakeredis**: shared state in production, and fast tests without a Redis server.
- **prometheus_client**: metric exposition.
- **httpx**: calls to the Anthropic API and the agent's HTTP sink.
- **Next.js 16, React 19, TanStack Query, Recharts**: dashboard.

Everything else (linters, type checkers, Trivy, Dependabot) supports quality, not the behavior.

## Configuration values that matter

Detection thresholds, all in `DetectionSettings`:

- `bruteforce_threshold = 5` failed logins from one source
- `bruteforce_window_seconds = 300`
- `auth_burst_threshold = 30` attempts on one host
- `auth_burst_window_seconds = 300`
- `cooldown_seconds = 900` between repeated detections of the same key
- `allowed_listening_ports`: ports that may listen without an alert

Scoring weights, all in `RiskSettings`: base points per rule, `repeat_points = 10` (cap 30), `privileged_points = 15`, `combination_points = 10` (cap 20), reputation adjustments, and `band_edges = (20, 40, 60, 80)`.

Correlation: `gap_seconds = 1800`.

Environment variables (`SENTINEL_` prefix) that change behavior: `COLLECTORS`, `AUTH_LOG_PATHS`, `STATE_PATH`, `OUTPUT_PATH`, `API_URL`, `API_KEY`, `DATABASE_URL`, `REDIS_URL`, `ALLOWED_PORTS`, `BASELINE_PATH`, `AUTH_SECRET`, `ALERT_MIN_SEVERITY`, `AI_PROVIDER`.

## Generated boilerplate

These parts were generated or scaffolded and should be described as such in a defense:

- `frontend/` project layout, configuration files and default Next.js pages: created with the Next.js scaffold. The pages that show SentinelBot data are project code.
- `database/migrations/` Alembic environment files (`env.py`, `script.py.mako`).
- Python packaging files (`pyproject.toml`) and the `py.typed` markers.
- Lock-like files and `.venv` folders (not tracked in git).
- Kubernetes and Compose files are configuration written by hand, not generated, but they follow common templates.

## Parts that are unnecessarily complicated

These are the places where the code does more than the project needs. The reasons and options are in `docs/simplification-report.md`.

- Two state backends (in-memory and Redis) behind the `StateStore` protocol.
- Two incident stores (JSON file for the CLI, SQL for the API).
- Two rate limiters (memory and Redis).
- Kubernetes, Prometheus and Grafana in addition to Compose. Useful, but a large amount of configuration to defend.

## Parts that must be understood for a defense

See `docs/must-understand.md`. In short: the event model, the auth parsers, the five rules and their thresholds, the cooldown and window mechanism, the scoring formula, the correlation rule, the incident lifecycle, the ingest order on the server, and the AI boundary.

## What is missing or unfinished

- The Docker-security detection (Experiment 6 in the lab plan) does not exist. No collector reads Docker state.
- The Containers page in the dashboard is a placeholder.
- The dashboard has no automated tests.
- The baseline for privileged processes and ports is shared between nodes in the same deployment. This is a known source of false positives.
- Kubernetes manifests were checked with kustomize, not with a live server dry run.
