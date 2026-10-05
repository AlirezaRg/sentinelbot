# What must be understood

This document separates the parts of SentinelBot you need to explain on your own from the parts you only need to know exist. For every essential component it gives: what it does, why it exists, its input, its processing, its output, its dependencies, its failure modes, its security implications, and how to test it.

## Essential

### 1. Event model

- **What it does:** defines the one shape of data that moves through the whole system.
- **Why it exists:** if the agent, detection, API and dashboard each used their own format, every boundary would need translation code and bugs would hide there.
- **Input:** a Python call that creates an `Event` from a parsed log line or a snapshot.
- **Processing:** pydantic validates each field. `host_id` and `message` have length limits. `source_ip` must be a valid IP address or empty.
- **Output:** JSON Lines on disk, or JSON in an HTTP batch.
- **Dependencies:** pydantic v2.
- **Failure modes:** an invalid event raises a validation error when it is constructed. A reviewer should confirm how the calling code handles that error before claiming one bad line cannot stop a batch.
- **Security implications:** length limits prevent a hostile log line from filling storage. The model stores usernames and IPs, but never passwords, because the parsers never extract them.
- **How to test:** `agent/tests/` contains model tests. Check that an invalid IP is rejected and that a message longer than 2000 characters is rejected.

### 2. Auth log parsing

- **What it does:** turns a sshd or sudo log message into an `AuthRecord` (event type, severity, username, IP, metadata).
- **Why it exists:** rules cannot work on raw text. Parsing is the boundary between "log text" and "security facts".
- **Input:** the program name (`sshd`, `sshd-session`, `sudo`) and the message text.
- **Processing:** regular expressions for `Accepted`, `Failed`, and sudo `COMMAND=` lines. "Invalid user X from IP" is deliberately ignored, because the same attempt also produces a `Failed ... for invalid user` line, and counting both would double every attempt.
- **Output:** an `AuthRecord`, or `None` for lines that are not relevant.
- **Failure modes:** a new OpenSSH message format would not match and would be silently ignored. This is a false-negative risk.
- **Security implications:** sudo commands are reduced to the executable name, so command arguments (which may contain secrets) are not stored.
- **How to test:** parser tests in `agent/tests/`. Use one real example line per message type.

### 3. Log sources and cursors

- **What it does:** reads new lines from the systemd journal or from log files, and remembers where it stopped.
- **Why it exists:** without a cursor, every agent run would re-send the whole log. With a cursor, each line is read once.
- **Input:** `journalctl` output in JSON format, or a file path.
- **Processing:** the journal source stores a journal cursor string. The file source stores a byte offset and detects rotation when the file is smaller than the offset or the inode changed.
- **Output:** raw log lines passed to the parsers.
- **Failure modes:** if the state file is lost, the agent re-reads recent history once. If the file rotates faster than the agent polls, lines can be lost. This is a known limitation.
- **Security implications:** the agent needs read access to the journal. The Docker image adds the `systemd-journal` group for this reason.
- **How to test:** the agent's tests in `agent/tests/` cover source and cursor behavior. Check the file names with `ls agent/tests` before citing one in a defense. The lab scenario `run_scenario.py` covers the file source.

### 4. Detection rules

- **What it does:** looks at a stream of events and emits a detection when a pattern crosses a threshold.
- **Why it exists:** a single failed login is normal. Many failures from one source in a short time is a pattern worth attention.
- **Input:** events, one at a time, in arrival order.
- **Processing:** each rule keeps a sliding window of timestamps per key, compares the count with a threshold, and then sets a cooldown.
- **Output:** `Event` objects with `event_type` ending in `_DETECTED` and metadata that explains the decision.
- **Failure modes:** a window too short misses slow attacks. A threshold too low creates false positives. Rules only see what the agent sends.
- **Security implications:** detection rules run on the server, so an agent cannot suppress a detection by lying about its own state, but it can stop sending events.
- **How to test:** `detection/tests/test_rules.py` feeds events in and checks the output.

Details for each rule are in `docs/detection-rules.md`.

### 5. Sliding windows and cooldowns

- **What it does:** a window stores the times of recent events per key. A cooldown stops a key from firing again for a fixed period.
- **Why it exists:** these two mechanisms are what makes a rule time-based and keeps it from flooding the dashboard.
- **Input:** key, timestamp, optional value.
- **Processing:** the window drops timestamps older than its length, then returns what is left. The cooldown records the last time it allowed a key and refuses until the period has passed.
- **Output:** the list of recent entries, or a boolean.
- **Failure modes:** with in-memory state, a restart resets all windows. With Redis, the cooldown check is not atomic, so two API workers could both allow the same key at the same moment. This is a known race that produces a duplicate, not a missed alert.
- **Security implications:** `max_tracked_keys` caps memory. An attacker using many source addresses cannot exhaust memory, because old keys are dropped.
- **How to test:** `detection/tests/test_windows.py`, and `test_redis_state.py` for Redis (needs `SENTINEL_TEST_REDIS_URL`).

### 6. Risk scoring

- **What it does:** turns a detection into a number from 0 to 100 and a severity band.
- **Why it exists:** rules say that something happened. Scoring says how much it matters, given context (repetition, privilege, other rules from the same source).
- **Input:** a detection and the recent history of that source.
- **Processing:** add the factors (base, repetition, privilege, combination, reputation), clamp to 0-100, map to a band. The rule's own severity is a floor.
- **Output:** the detection with `severity`, `risk_score` and `risk_factors` in its metadata.
- **Failure modes:** the weights are chosen by hand. Scores are useful for ordering, not for proving anything.
- **Security implications:** trusted and known-bad address lists are operator-supplied. A wrong entry in the trusted list lowers the score of a real attack.
- **How to test:** `detection/tests/test_scoring.py`. Each factor has its own test.

Full formula and examples: `docs/risk-scoring-explained.md`.

### 7. Event correlation and incidents

- **What it does:** groups detections that belong to one story into one incident.
- **Why it exists:** an analyst should see one brute-force incident, not 200 detections.
- **Input:** detections, in arrival order.
- **Processing:** group by host and source address. If an active incident for that group had activity within the gap, the detection joins it. Otherwise a new incident starts.
- **Output:** an `Incident` with title, description, severity, risk score, rules, counts, first and last seen, and recommended actions.
- **Failure modes:** if the gap is too short, one attack becomes several incidents. If too long, unrelated events merge.
- **Security implications:** incidents only keep event IDs and the last 200 related IDs, so storage stays bounded.
- **How to test:** `detection/tests/test_correlation.py`. The lab scenario `campaign` shows two rules merging into one incident.

Details: `docs/correlation-explained.md`.

### 8. API ingest pipeline

- **What it does:** receives a batch of events from an agent and runs detection, scoring, correlation, storage, metrics and alerts, in that order.
- **Why it exists:** the server is the place where detection runs for all hosts, so the rules see every host.
- **Input:** `POST /api/v1/events` with a list of events and the `X-API-Key` header.
- **Processing:** see `ingest()` in `backend/src/sentinelbot_backend/container.py`. Events from the agent are scored. Detections from the agent are stored as they are. Correlation runs only for detections. The incident store is saved. The baseline is saved. Alerts are sent.
- **Output:** the number of incidents touched. Duplicate event IDs return 409, which the agent treats as success.
- **Failure modes:** if the database is unavailable, the request fails and the agent retries with backoff.
- **Security implications:** agents need the service key. Users need a token. Login is rate limited.
- **How to test:** `backend/tests/test_api.py` and `test_server_detection.py`.

### 9. Database model

- **What it does:** stores hosts, events, incidents, detection rules, alerts and users.
- **Why it exists:** events and incidents must survive restarts and be queried by the dashboard.
- **Input:** SQLAlchemy calls from the repositories.
- **Processing:** tables are created by Alembic migrations. A test checks that migrations match the models, so drift is caught.
- **Output:** rows.
- **Failure modes:** a missing migration causes an error at startup, which the init container reports.
- **Security implications:** the database password is in a secret. The `users` table holds scrypt hashes, never passwords.
- **How to test:** `database/tests/test_migrations.py` compares the migrations with the models. `backend/tests/test_sql_backend.py` needs PostgreSQL.

### 10. Redis

- **What it does:** shares sliding windows and cooldowns between API workers, and holds the rate limiter counters.
- **Why it exists:** if two workers each keep their own windows, an attack split across them is never counted together.
- **Input and output:** sorted sets per key, with timestamps as scores.
- **Failure modes:** Redis unavailable means the API cannot run the shared state. The code uses the in-memory state only when no Redis URL is configured.
- **Security implications:** Redis holds only counters and timestamps, but it is still a network service. Restrict its access in any deployment outside the lab.
- **How to test:** `detection/tests/test_redis_state.py` (needs a real Redis).

### 11. Prometheus metrics

- **What it does:** exposes counters and gauges on `/metrics`: events, detections, incidents, incident status, detection latency, and agent state.
- **Why it exists:** operators need to see whether the pipeline is running, not only the dashboard.
- **Input:** calls from the ingest pipeline.
- **Output:** text format for Prometheus.
- **Failure modes:** a renamed metric breaks the Grafana dashboard. `test_grafana_dashboard.py` checks the dashboard references.
- **Security implications:** `/metrics` requires a viewer token or the service key.
- **How to test:** `backend/tests/test_metrics.py`.

### 12. Grafana

- **What it does:** draws the metrics as a dashboard.
- **Why it exists:** a visual view of rates over time, which the dashboard does not provide.
- **Input:** Prometheus datasource, JSON dashboard file.
- **Failure modes:** a wrong datasource UID shows empty panels.
- **How to test:** `backend/tests/test_grafana_dashboard.py` checks the metric names used by the dashboard exist.

### 13. Docker architecture

- **What it does:** packages the API, agent and dashboard as images. Compose starts the full stack on one host.
- **Why it exists:** reproducible setup and a clear boundary for each service.
- **Key decisions:** every image runs as a non-root user (uid 10001). The agent uses host PID and read-only journal mounts. Ports are bound to 127.0.0.1 by default.
- **Failure modes:** a missing `SENTINEL_JOURNAL_GID` means the agent cannot read the journal.
- **Security implications:** the agent is the most privileged container. It needs host PID visibility and journal read access, and nothing else.
- **How to test:** `docker compose config` validates the file. `docker compose up` and the lab scenarios exercise the path.

### 14. Kubernetes architecture

- **What it does:** runs the same components in a cluster, with the agent as a DaemonSet (one per node).
- **Why it exists:** shows that the agent runs on several nodes, and that the server receives events from all of them.
- **Key decisions:** the API runs an Alembic migration in an init container before it starts. The agent has `hostPID` and `supplementalGroups` for the journal.
- **Failure modes:** a node without the journal group cannot read logs. The baseline is shared, which can create false alerts across nodes.
- **How to test:** `kubectl apply -k k8s/` on a cluster, then `kubectl get pods`. Manifests were tested on a two-node k3s cluster.

### 15. AI analyst

- **What it does:** explains an incident in text, using only the structured incident fields.
- **Why it exists:** analysts need a readable summary and next steps. The rules produce facts, not prose.
- **Input:** `title`, `description`, `severity`, `risk_score`, `host`, `source_ip`, `usernames`, `rules_triggered`, counts and time range. Raw log text and identifiers are not sent.
- **Processing:** the offline version builds the analysis from rules. The optional version sends a prompt to Anthropic, parses one JSON object, validates it, and caps confidence when there are fewer than three detections.
- **Output:** an `AnalysisResult` with a `provider` field, so you can tell whether the text came from the model or the rules.
- **Failure modes:** an unavailable API or an invalid reply falls back to the rules, and `fallback_reason` records why.
- **Security implications:** the model's text is shown to analysts, so it must not be treated as an instruction. The prompt tells the model to suggest only investigation and conservative remediation.
- **How to test:** `ai/tests/` and `backend/tests/test_analysis_api.py`.

Details: `docs/ai-analyst-explained.md`.

## Important (understand the idea, not every line)

- **Alerts:** email over STARTTLS with a minimum severity, a per-incident cooldown, and an escalation bypass. `alerts/tests` cover the policy.
- **Authentication:** scrypt password hashing, HMAC-SHA256 signed tokens with expiry, three roles, and a login rate limit. Understand the token format and the role check. The hashing parameters can be described as "a standard password-hashing function" unless you read the implementation details.
- **Dashboard:** Next.js pages that call the API through a rewrite. You should explain the data flow, not the React component tree.
- **CI:** lint, type checks, tests, image scans and dependency audit. Explain what each job protects against.
- **Migrations:** what Alembic does and why the drift test exists.

## Implementation details (treat as library behavior)

- How FastAPI routes requests and validates bodies.
- How uvicorn serves ASGI.
- How SQLAlchemy builds SQL.
- How psutil reads `/proc`.
- How pydantic generates validation code.
- How React and TanStack Query manage state.
- How Recharts draws charts.
- How Prometheus scrapes and stores samples.

You should know what each library is for and where it is used. You do not need to explain its internals.
