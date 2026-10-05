# Defense questions

Each answer is technically correct for the current code. Where the honest answer is "not measured" or "not implemented", the answer says so. A longer list with more examples is in `defense-preparation.md`.

## Choice of technology

**Why did you choose FastAPI?**
FastAPI uses the same pydantic models for request validation that the agent uses for events, so the contract is checked at the boundary without a second schema. Flask would need a separate validation layer; Django brings an ORM and admin interface the project does not use.

**Why PostgreSQL?**
Several API workers write at the same time, incidents need relational queries, and event metadata is stored as JSON. SQLite serializes writes and would not support the multi-worker deployment.

**Why Redis?**
Sliding windows and cooldowns must be shared between API workers. If each worker kept its own window, an attack split across workers would never reach the threshold. Redis is optional: with one worker, the in-memory state is used.

**Why Prometheus?**
It is the standard pull model. The API exposes counters and gauges on `/metrics` and needs no code in the pipeline's critical path beyond counting.

**Why Kubernetes?**
The agent is a per-node component, so a DaemonSet maps to it directly. It was tested on a two-node cluster. A single host does not need it, and Compose is the default for that case.

**Why Next.js?**
The dashboard is thin. A rewrite to the API keeps one origin for the browser, so the API needs no CORS configuration. The framework is a convenience, not a requirement.

## Detection

**Why rule-based detection?**
A rule can be stated, tested and explained. Each detection can be reproduced from the events. A model cannot give that guarantee, and it needs labeled data this project does not have.

**What does the SSH brute-force rule detect, exactly?**
Five failed logins from one source address within 300 seconds. Once it fires, it stays quiet for that source for 900 seconds.

**What happens after the fifth failed login?**
The rule emits one detection, scored at 40 points, with severity high. It joins or starts an incident for that source. The sixth to eighth failures are counted in the window but do not produce another detection because of the cooldown. Lab scenario `bruteforce` shows exactly this.

**How do you handle false positives?**
The rules have explicit thresholds, so each one can be tuned. Incidents carry recommended actions and an analyst can mark them as false positives. The false-positive rate on real traffic is not measured yet; the method to measure it is in `evaluation.md`.

**How do you avoid duplicate alerts?**
Three mechanisms: cooldowns in each rule, grouping of detections into incidents, and a per-incident cooldown in the email policy. Duplicate events sent by an agent are rejected by event identifier.

**What about a slow attack that stays under the threshold?**
It is a false negative. The per-host burst rule covers some distributed cases, but a slow attack with fewer than 30 attempts in 5 minutes is not detected. This is listed in `detection-rules.md`.

**Why is the root-login rule severity high even when the login is legitimate?**
The rule cannot know who is authorized. A direct root login is a standard hardening concern, so every occurrence is reported, and the recommended actions ask the analyst to confirm it was expected.

## Risk scoring

**How is the risk score calculated?**
Base points for the rule, plus repetition, combination and privilege points, capped at 100. Each factor is stored with the detection. The formula and the worked examples are in `risk-scoring.md`.

**Is the score a probability of attack?**
No. It is a heuristic ordering of detections. It has not been validated against labeled data, and the project does not describe it as a probability.

**What is the weakness of the current score?**
The repetition factor counts detections, not attempts, and the cooldown suppresses repeated detections. A brute force of 8 failures and one of 800 get the same score. The redesign that fixes this is documented but not implemented.

**Why does the incident take the maximum score and not the sum?**
A campaign with many detections would otherwise drift to 100 by length alone. The maximum says how serious the worst moment was.

## Correlation

**What is the difference between an event and an incident?**
An event is one observation, such as a failed login. A detection is a conclusion from events, such as a brute force. An incident is a group of detections from the same host and source within 30 minutes, which an analyst acts on.

**What happens if the attack pauses for more than 30 minutes?**
A new incident starts. That is intentional, because a long pause usually means a different episode.

**What happens after an analyst resolves an incident and the attacker returns?**
A new incident starts. Resolved incidents are never reused, so a closed case does not absorb new evidence silently.

## AI

**Why does the system use AI at all?**
An analyst needs a readable explanation and a list of checks, and that takes time to write for every incident. The AI drafts that text from structured facts.

**Why is AI not responsible for detection?**
Detection must be testable and repeatable. A model's answer may change between calls, and it can invent evidence. Keeping it out of the decision path means detection works when the model is off or wrong.

**How do you prevent hallucinations?**
You cannot prevent them completely. The prompt forbids unsupported claims, the reply must match a schema, confidence is capped when evidence is thin, and the evidence list is shown for checking. Explanation accuracy is not yet measured.

**How do you handle prompt injection through log data?**
Usernames from logs are length-limited and included as data. The model cannot change status, severity or host state, and its reply is validated and displayed as text. The residual risk is a misleading explanation, which is why the evidence is displayed with it.

**What happens if the model is unavailable?**
The rule-based explanation is used instead, and the result records the reason in `fallback_reason`.

## Security

**What happens if the agent is compromised?**
A compromised agent can send false events or stop sending. It cannot change rules or incidents directly, because detection runs on the server. It can, however, use its service key to send events for any host name it chooses. Per-agent keys are the planned fix.

**What security risks does the agent itself introduce?**
It runs with host PID visibility and read access to the journal. A compromised agent could read more of the host than a normal service. The container is non-root, capabilities are dropped in Kubernetes, and the root filesystem is read-only there.

**What did the security review find?**
Eleven findings. The one fixed in this review: the agent's service key was mapped to admin and bypassed role checks entirely, so it could change incident status. It is now limited to reading and ingesting, and the change is tested. Open items include a shared key for all agents and no TLS between agent and API by default.

**How is the API protected?**
Passwords are hashed with scrypt. Tokens are HMAC-signed and expire. Roles are checked on every route. Login is rate limited per client address.

## Databases

**What happens if PostgreSQL becomes unavailable?**
Requests fail with an error and the agent retries. What happens to events held by the agent during a long outage has not been tested; the code's retry behavior is in `agent/src/sentinelbot_agent/output.py`.

**How do you change the schema?**
With an Alembic migration. A test compares migrations with the models, so an unmatched change fails CI.

## Networking

**How does the browser reach the API?**
Through a Next.js rewrite of `/backend/*`, so the browser only talks to one origin.

**Is the traffic between agent and API encrypted?**
Not in the default stack. The Compose network is private to the host, but a deployment across untrusted networks must add TLS in front of the API. This is documented as a finding.

## Docker and Kubernetes

**Why do the images run as a non-root user?**
So a compromised process has fewer rights in the container. Every image uses user id 10001.

**Why does the agent need `pid: host`?**
Without it, the process list shows only the container's processes. This is the most sensitive setting in the project and is documented.

**How does the agent reach every Kubernetes node?**
A DaemonSet schedules one pod per node. Each pod mounts the node's journal read-only.

## Monitoring

**What metrics are exposed, and who can read them?**
Event, detection and incident counts, incident status, detection latency and agent gauges. `/metrics` requires a viewer token or the service key.

## Testing

**What do the tests cover?**
Parsers, each rule with its cooldown edges, scoring factors, correlation, the API's routes and roles, migrations against models, alerts, the AI fallback, and Redis state. Agent: 85 tests. Detection: 89 tests, plus one Redis test that runs in CI. Backend: 115 tests, plus PostgreSQL tests that run in CI.

**How did you evaluate the detection engine?**
Functionally: six synthetic scenarios with expected results fixed before each run. All six matched. Quantitatively: not yet. Recall and false-positive rates need a labeled dataset, which the project does not have. This is stated in `evaluation.md`.

**Did the tests find anything?**
Yes. The new role-matrix test found that the API-key branch returned a principal without checking the required role at all, which the earlier admin mapping had hidden. That was fixed.

## Performance

**How fast is the pipeline?**
Measured offline on one Windows laptop: the agent parsed about 21,000 lines per second at 10,000 and 50,000 lines. Detection and correlation together took about 1.7 seconds for 50,000 lines. These numbers exclude the API and database, which are not yet measured.

**How much memory does it use?**
Peak resident memory was 30 to 57 MB per stage across the sizes tested, measured on the offline pipeline.

**Why does the agent sometimes need several cycles for one log?**
The file source reads at most 1 MiB per collection cycle. A large backlog is drained over several cycles, so latency grows with backlog size. It was found by the benchmark and is listed as a limitation.

## Limitations and comparison

**What are the system's limitations?**
Linux only. Rule-based coverage. Unmeasured accuracy on real traffic. A heuristic score. No cross-host incidents. A shared baseline across nodes. No Docker checks. Full list in `limitations.md`.

**What is the difference between SentinelBot and a SIEM?**
A SIEM collects and searches logs from many sources and keeps them for compliance. SentinelBot collects authentication and host state from Linux servers and applies a few rules. It is narrower and transparent; a SIEM is broader and mature.

**What is the difference between SentinelBot and an EDR?**
An EDR observes process and file behavior in depth at kernel level and can block or isolate. SentinelBot observes authentication and listening ports and snapshots of processes, and it cannot block.

**Why not use OSSEC or Wazuh?**
Those tools already exist and are mature. The purpose here is to build and explain a complete pipeline, and to measure it.

**What would you do differently?**
Use per-agent keys from the start, a single state backend, and per-host baselines. Those three decisions caused most of the later complexity or the known false positives.
