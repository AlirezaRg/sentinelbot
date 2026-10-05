# Architecture explained

This document explains the system as a pipeline. Each arrow is a step where data changes shape or moves to another component. For each step it says what data moves, in what format, why it moves, and which component handles it.

```
Linux host
  ↓   (1) log lines and system snapshots
SentinelBot agent
  ↓   (2) Event objects (JSON)
Event collection and normalization
  ↓   (3) validated Event objects
Detection
  ↓   (4) detection Events
Risk scoring
  ↓   (5) scored detection Events
Correlation
  ↓   (6) Incident records
Database
  ↓   (7) rows for the dashboard and API
Dashboard / Alerts / AI analysis
```

## (1) Linux host → agent

- **Data:** raw lines from `journalctl -o json` or from `auth.log` / `secure`. Process list from `/proc` through psutil. Listening sockets. CPU and memory.
- **Format:** text lines and kernel data.
- **Why:** these are the only facts about the host that exist. Everything downstream is derived from them.
- **Component:** `agent/src/sentinelbot_agent/collectors/` and `auth/sources.py`.

## (2) Agent → Event objects

- **Data:** one `Event` per relevant line or per snapshot.
- **Format:** a pydantic model, serialized as JSON. Fields: `event_id`, `timestamp`, `host_id`, `event_type`, `severity`, `source`, `source_ip`, `username`, `message`, `metadata`.
- **Why:** a single schema lets every later stage be written once.
- **Component:** `agent/src/sentinelbot_agent/models.py`, `agent.py` (collect cycle), `output.py` (sinks).

The agent writes events in batches of up to 200. It sends them over HTTP to `POST /api/v1/events`, or appends them to a JSON Lines file when no API is configured. A `--once` run performs one collection cycle and exits, which is what the lab uses.

## (3) Event collection and normalization

- **Data:** raw lines become typed events. Usernames and IPs are extracted. Sudo commands are reduced to the program name.
- **Format:** `Event` with a typed `event_type` such as `ssh_login_failed`.
- **Why:** rules should match on types and fields, never on message text. This is what makes them testable and stable across message wording changes.
- **Component:** `auth/parsers.py`. Normalization is the parser step; there is no separate normalization service.

## (4) Detection

- **Data:** the event stream, in arrival order.
- **Format:** the same `Event` type, with `event_type` ending in `_detected` and metadata that records the threshold and window.
- **Why:** a rule decides that a pattern happened. It does not decide how serious that is.
- **Component:** `detection/src/sentinelbot_detection/rules.py`, run by `engine.py`. The API runs it in `Container.ingest()`, and `sentinelbot-detect` runs it on a file.

Example: five `ssh_login_failed` events from one IP within 300 seconds become one `ssh_bruteforce_detected` event. The cooldown then suppresses further detections for that IP for 900 seconds.

## (5) Risk scoring

- **Data:** each detection, plus recent detections from the same source.
- **Format:** the detection with `risk_score`, `risk_factors` (a list of named points), and a final `severity`.
- **Why:** two detections of the same rule can differ in importance. A brute force that also targets root is more serious than one that targets an unused account.
- **Component:** `detection/src/sentinelbot_detection/scoring.py`.

The score is heuristic. It is documented in `docs/risk-scoring-explained.md`.

## (6) Correlation

- **Data:** scored detections.
- **Format:** an `Incident` with `incident_id`, title, description, severity, risk score, rules, counts, time range, related event IDs and recommended actions.
- **Why:** one attack produces several detections. An analyst needs one object to act on.
- **Component:** `detection/src/sentinelbot_detection/correlation.py`.

Details: `docs/correlation-explained.md`.

## (7) Database

- **Data:** events, incidents, users, hosts, alerts.
- **Format:** PostgreSQL rows through SQLAlchemy.
- **Why:** persistence across restarts and queries from the dashboard.
- **Component:** `database/src/sentinelbot_database/models.py` and the SQL repositories in `backend/src/sentinelbot_backend/storage_sql.py`.

## (8) Outputs

### Dashboard

- **Data:** JSON from `/api/v1/...`.
- **Format:** HTTP JSON. The browser calls `/backend/...`, which Next.js rewrites to the API.
- **Why:** the analyst reads incidents, changes their status, and asks for an explanation.
- **Component:** `frontend/`.

### Alerts

- **Data:** new or escalated incidents at or above the configured severity.
- **Format:** plain email message built by `alerts/src/sentinelbot_alerts/message.py`.
- **Why:** an analyst should hear about a serious incident without watching the dashboard.
- **Component:** `alerts/`. The notifier runs after correlation. A failing channel does not stop ingest, because the notifier isolates failures.

### AI analysis

- **Data:** the incident's structured fields, without raw logs or IDs.
- **Format:** one JSON object from the model, or the rule-based result.
- **Why:** to turn facts into a readable explanation and investigation steps.
- **Component:** `ai/`. See `docs/ai-analyst-explained.md`.

### Metrics

- **Data:** counters and gauges updated during ingest.
- **Format:** Prometheus text format on `/metrics`.
- **Why:** operators need a time series view of the pipeline.
- **Component:** `backend/src/sentinelbot_backend/metrics.py`, then Prometheus and Grafana.

## Where each stage runs

| Stage | Where it runs | Why there |
| --- | --- | --- |
| Collection | Agent, on each host | Only the host can read its own logs and processes |
| Detection, scoring, correlation | API (also CLI for files) | Rules need events from all hosts, and one place keeps the baseline consistent |
| Storage | API, PostgreSQL | Persistence and dashboard queries |
| Alerts | API | One place decides when to notify |
| AI analysis | API, on request | Runs only when an analyst asks, so it adds no delay to ingest |

## Why the boundary is where it is

Detection is on the server, not the agent. A compromised agent can lie about what it sends, so the server does not trust agent-side conclusions. A consequence is that a silent agent produces no alerts: the server can only detect what arrives. Detecting a silent agent would need a separate heartbeat check, which the project does not implement.
