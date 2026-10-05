# Defense preparation

Fifty-plus questions an examiner may ask, grouped by topic. Each question has a short answer (one sentence to say first), a detailed answer (what to say next), and an example from SentinelBot. Practice saying the short answer out loud before reading the rest.

Facts in the answers come from the code and from the lab runs. Where something is not implemented or not measured, the answer says so.

## Architecture

**1. Why is detection on the server and not on the agent?**
- *Short:* so rules see all hosts and a compromised agent cannot change the rules.
- *Detailed:* the server holds the rules, the state and the baseline. An agent only forwards facts. A compromised agent can stop sending events, but it cannot make the server accept a fake conclusion from itself, because conclusions are not accepted from agents. Trade-off: a silent agent produces no alert.
- *Example:* `Container.ingest()` runs detection on events where `source != "detection"`.

**2. What is the difference between the agent, the API and the dashboard?**
- *Short:* the agent collects, the API decides and stores, the dashboard shows.
- *Detailed:* the agent runs on each host and has no database. The API runs detection, scoring, correlation and alerts, and owns the database. The dashboard is a read-mostly client that also changes incident status.
- *Example:* `POST /api/v1/events` receives batches from the agent. `GET /api/v1/incidents` serves the dashboard.

**3. Why is there a separate CLI for detection?**
- *Short:* to run the same rules on a file, without a server.
- *Detailed:* the CLI makes the lab reproducible and lets the detection package be tested alone. It is the path used by `run_scenario.py`.
- *Example:* `sentinelbot-detect --input events.jsonl --output detections.jsonl`.

**4. What does the system do if the agent sends the same batch twice?**
- *Short:* the second copy is rejected as duplicate, and the agent treats that as success.
- *Detailed:* each event has a UUID. The server returns 409 for an ID it already stored. The agent considers 409 a successful delivery, so retries are safe.
- *Example:* `ingest()` path and the 409 handling described in `docs/correlation-explained.md`.

**5. Why is the event model shared between agent and server?**
- *Short:* one definition means no translation layer to get wrong.
- *Detailed:* the server imports the agent's `Event` class. A change to the model is caught by both sides at once. The cost is a dependency from server to agent package.

## Linux

**6. How does the agent know which log lines are important?**
- *Short:* it parses only sshd and sudo authentication messages with fixed patterns.
- *Detailed:* `auth/parsers.py` has regular expressions for accepted and failed logins and sudo commands. Everything else is ignored.
- *Example:* `Failed password for invalid user admin from 198.51.100.23 port 40000` becomes `ssh_login_failed`.

**7. Why does the agent read the systemd journal first?**
- *Short:* the journal is where modern Debian logs authentication messages.
- *Detailed:* on Debian 13 sshd logs through `sshd-session`, and the journal has all programs in one place. The file fallback handles older systems.

**8. How does the agent avoid reading the same line twice?**
- *Short:* it stores a cursor for each source and continues from there.
- *Detailed:* the journal source stores the journal cursor string. The file source stores a byte offset and resets when the file is smaller than the offset, which is how rotation is detected.

**9. What happens after log rotation?**
- *Short:* the file source detects that the file shrank or changed and starts from the beginning of the new file.
- *Detailed:* if rotation happens faster than the agent polls, lines written to the old file between the last read and the rotation can be lost. This is a known limitation.

**10. Why does the Docker agent need the systemd-journal group?**
- *Short:* journal files are readable only by root and that group.
- *Detailed:* the agent runs as uid 10001. It gets read access through the group ID set in `SENTINEL_JOURNAL_GID`. The group ID is a host value, which is why it is an environment variable.

**11. Why does the agent need host PID access?**
- *Short:* without it, the process list shows only the container's own processes.
- *Detailed:* the process collector reads `/proc`. Host PID namespace gives the agent the host's processes. This is the most privileged setting in the project and is explained in `docs/security.md`.

**12. How is the privileged process rule related to Linux?**
- *Short:* it uses the user ID and executable path that Linux reports for each process.
- *Detailed:* the rule looks at processes whose owner is root, skips kernel threads (parent PID 2), and compares `(name, executable)` with a learned baseline.

## Python

**13. Why Python?**
- *Short:* the detection logic must be readable and easy to test.
- *Detailed:* see `docs/technology-decisions.md`. The cost is performance, which is not yet measured.

**14. Why pydantic?**
- *Short:* it validates types and lengths at every boundary.
- *Detailed:* events from the network and from log lines pass through the same model. An invalid event fails at construction, not later in a rule.

**15. Why do you use mypy in strict mode?**
- *Short:* type errors become build failures, not runtime surprises.
- *Detailed:* strict mode forces annotations on every function. It caught real mistakes during development.

**16. How do you handle secrets in Python code?**
- *Short:* secret fields are excluded from `repr()`, and they are read from environment variables.
- *Detailed:* `repr=False` on fields such as the API key and the SMTP password keeps them out of logs and tracebacks. The code never writes them to files.

## Cybersecurity

**17. What exactly does the SSH brute-force rule detect?**
- *Short:* five failed logins from the same IP address within five minutes.
- *Detailed:* the rule keeps a sliding window of failure times per source. When the count reaches five, it emits one detection and starts a 15-minute cooldown for that IP.
- *Example:* lab scenario `bruteforce` produced one detection from eight failures.

**18. What happens after the fifth failed login?**
- *Short:* the rule fires, a detection event is created, and it is scored and correlated.
- *Detailed:* the detection gets a base score of 40, its severity is HIGH, and it joins or creates an incident for that IP. Failures six, seven and eight are counted in the window but do not produce a second detection, because of the cooldown.

**19. Why is there a cooldown?**
- *Short:* one attack would otherwise create hundreds of detections.
- *Detailed:* the cooldown suppresses repeated detections for the same key for 900 seconds. The trade-off is that the incident shows one detection for many failures.

**20. What is the difference between an event and an incident?**
- *Short:* an event is one observation; an incident is a group of related detections an analyst acts on.
- *Detailed:* see `docs/correlation-explained.md`. Events are stored. Detections are a subset of events. Incidents are groups of detections.

**21. How do you detect a successful attack after brute force?**
- *Short:* a successful root login from the same source is a separate detection, and correlation joins it to the brute-force incident.
- *Detailed:* the `campaign` scenario does this. The root login gets a combination bonus because another rule fired from the same source.

**22. Can an attacker avoid detection by spreading attempts across IPs?**
- *Short:* partly. The per-IP rule misses it, but the host-wide burst rule can still fire.
- *Detailed:* `auth_burst` counts attempts per host. A very slow distributed attack under 30 attempts in five minutes is not caught. This is a stated false negative.

**23. What are the false positives?**
- *Short:* a user retyping a password, a script retrying a login, a backup job logging in often, and an administrator logging in as root on purpose.
- *Detailed:* the rules cannot tell authorized automation from an attacker. The analyst decides using the incident's recommended actions, and can mark the incident as a false positive.

**24. What are the false negatives?**
- *Short:* slow attacks, attacks through sudo or su, logins with keys that do not produce `Accepted ... for root`, and any service that is not on the list of known services.
- *Detailed:* see `docs/detection-rules.md`, each rule has a false-negative entry.

**25. What security risks does the agent itself introduce?**
- *Short:* it runs with host PID and journal read access, so a compromised agent could read more of the host than a normal service.
- *Detailed:* the mitigations are non-root user, no privileged mode, read-only journal mounts, and the fact that the agent only sends events. The agent holds the API key, so a stolen key lets someone send fake events.

**26. How is the API protected?**
- *Short:* login with scrypt-hashed passwords, signed tokens with expiry, roles, and rate limiting on login.
- *Detailed:* the service key is used by agents and treated as admin. `/metrics` requires a viewer. Tokens use HMAC-SHA256 with a secret of at least 32 characters.

**27. Why not use an existing SIEM or EDR?**
- *Short:* SentinelBot is a study of how these systems work, not a replacement for them.
- *Detailed:* see questions 75 and 76.

## Detection

**28. Why these five rules?**
- *Short:* they cover the most common Linux host attack pattern (SSH) and two signs of persistence or exposure (new root processes and listening ports).
- *Detailed:* they are the rules that can be implemented from data the agent collects, and tested without an attacker.

**29. Why are the thresholds five and thirty?**
- *Short:* they are reasonable defaults chosen by hand, not learned.
- *Detailed:* five failures in five minutes is a common alarm threshold. Thirty attempts per host in five minutes is set high to avoid firing on normal automation. Neither was validated on real traffic, which is stated in the evaluation document.

**30. Why is there a learned baseline for processes and ports?**
- *Short:* every host runs different services, so a fixed list would be wrong for most of them.
- *Detailed:* the first snapshot is the baseline, and later new items alert. The downside is that the baseline is learned from the state at that moment, which may already include an attack.

**31. What is the known problem with the baseline?**
- *Short:* it is shared across nodes in one deployment.
- *Detailed:* a process that runs only on one node looks new on the other. This produced false alerts in the Kubernetes test. Per-host baselines are the fix and are listed as future work.

## Risk scoring

**32. How is the risk score calculated?**
- *Short:* base points for the rule, plus repetition, combination and privilege points, capped at 100.
- *Detailed:* see `docs/risk-scoring-explained.md` for the formula and worked examples.

**33. Is the risk score scientifically validated?**
- *Short:* no. It is a heuristic.
- *Detailed:* the weights were chosen by hand. There is no labeled data to validate them, and the evaluation document defines how to measure usefulness once labels exist.

**34. Why is the final severity never lower than the rule's severity?**
- *Short:* a rule's own judgment should not be overruled by a number that only adds context.
- *Detailed:* a brute force from a trusted address gets a lower score, but it is still a brute force. The floor keeps the rule's meaning.

**35. Why does the incident take the maximum score and not the sum?**
- *Short:* a long campaign would otherwise drift to 100 just by having many detections.
- *Detailed:* the maximum says how serious the worst moment was. The count of detections is shown separately.

**36. How do you explain a score to an analyst?**
- *Short:* the detection stores each factor with its points, so the score can be added up by hand.
- *Detailed:* the lab campaign shows 35 + 10 + 15 = 60, with each factor listed.

## Correlation and incidents

**37. How are detections grouped into incidents?**
- *Short:* by host and source IP, if within 30 minutes of the incident's last activity.
- *Detailed:* see `docs/correlation-explained.md`.

**38. What happens if the attack pauses for more than 30 minutes?**
- *Short:* a new incident starts.
- *Detailed:* this is intentional. The two incidents are separate stories, and the analyst can see both.

**39. What happens after an analyst resolves an incident and the attacker returns?**
- *Short:* a new incident starts, because resolved incidents are never reused.
- *Detailed:* a closed case should not absorb new evidence silently. The new incident is the new story.

**40. Why are incidents limited to 200 related event IDs?**
- *Short:* to keep each incident a bounded size.
- *Detailed:* the count of detections is kept separately, so the total is still correct.

## Databases

**41. Why PostgreSQL?**
- *Short:* several API workers write at the same time, and the schema needs JSON columns.
- *Detailed:* see `docs/technology-decisions.md`. SQLite would fail under concurrent writes.

**42. What does the database store?**
- *Short:* hosts, events, incidents, detection rules, alerts and users.
- *Detailed:* the `users` table stores scrypt hashes, never passwords.

**43. How do you change the database schema?**
- *Short:* with an Alembic migration, reviewed and tested.
- *Detailed:* a test compares the migrations with the models, so a model change without a migration fails CI. The init container runs migrations before the API starts.

**44. What happens if PostgreSQL becomes unavailable?**
- *Short:* ingest fails, and the agent retries with backoff.
- *Detailed:* this has not been tested. From the code: the API returns an error, and the agent's HTTP sink retries with backoff. What happens to events when retries run out, and how much a long outage can hold in memory, must be read in `agent/src/sentinelbot_agent/output.py` and tested before making a claim about it.

**45. Why is Redis used?**
- *Short:* to share windows and cooldowns between several API workers.
- *Detailed:* without it, each worker would count only its own share of events, and an attack split across workers would be missed. It is optional for one worker.

**46. What happens if Redis is unavailable?**
- *Short:* a configured Redis that cannot be reached stops the shared state.
- *Detailed:* the cooldown check is not atomic in Redis, so two workers could both emit the same detection at the same moment. That produces a duplicate, not a missed alert. This race is documented in `docs/must-understand.md`.

## Networking

**47. How does the agent send events to the server?**
- *Short:* HTTP POST of JSON batches of up to 200 events, with the service key.
- *Detailed:* the sink retries on failure and drops batches that the server rejects as duplicates.

**48. Why are the API and Prometheus bound to 127.0.0.1?**
- *Short:* so they are not reachable from other machines by default.
- *Detailed:* a reverse proxy with TLS should be added before any public exposure. The Kubernetes NodePorts do not have TLS, which is stated in `docs/security.md`.

**49. How is the browser connected to the API?**
- *Short:* through a Next.js rewrite, so the browser sees one origin.
- *Detailed:* `/backend/...` in the browser becomes `${SENTINEL_API_URL}/...` on the server. This avoids CORS configuration.

## Docker

**50. Why do the images run as a non-root user?**
- *Short:* if an attacker gets into the container, they have fewer rights.
- *Detailed:* every image uses uid 10001. The agent is the exception in privilege terms, because it needs host PID and journal access, which it gets through host configuration and group membership, not root.

**51. Why is there a multi-stage build?**
- *Short:* the build tools are not in the final image.
- *Detailed:* the API and agent build wheels in a first stage and copy only the installed packages into the runtime image. The frontend copies only the standalone server output.

**52. Why was npm removed from the frontend image?**
- *Short:* the dashboard does not need npm at runtime, and npm's bundled packages had known vulnerabilities.
- *Detailed:* Trivy reported HIGH findings in npm's own dependencies. Removing npm from the runtime stage removes them without changing what the dashboard does.

## Kubernetes

**53. Why use Kubernetes?**
- *Short:* the agent is a per-node component, which fits a DaemonSet directly.
- *Detailed:* see `docs/technology-decisions.md`. Compose is enough for one host.

**54. How does the agent get onto every node?**
- *Short:* the DaemonSet schedules one agent pod per node.
- *Detailed:* the pod has host PID, the journal mounts and the journal group. It is tested on a two-node cluster.

**55. What is missing for production Kubernetes?**
- *Short:* TLS ingress, image registry, network policies, and a live server dry run of the manifests.
- *Detailed:* all of these are listed in `docs/security.md` and `docs/deployment.md`.

## Monitoring

**56. What metrics are exposed?**
- *Short:* event counts, detection counts, incident counts, incident status, detection latency, and agent gauges.
- *Detailed:* see `backend/src/sentinelbot_backend/metrics.py`.

**57. How do you know the pipeline is working?**
- *Short:* the health endpoint, the metrics, and the lab scenarios.
- *Detailed:* `/health` checks the process. The metrics show whether events and detections are arriving. The lab shows that a known input produces a known output.

## AI

**58. Why is AI in the system at all?**
- *Short:* analysts need a readable explanation and next steps, which the rules do not produce.
- *Detailed:* see `docs/ai-analyst-explained.md`. The AI explains; it does not detect.

**59. Why isn't AI responsible for detection?**
- *Short:* a model that decides whether an attack happened cannot be tested the way a rule can, and it can invent evidence.
- *Detailed:* rules give the same answer for the same input, so a defense can show the test. The model is kept outside the decision path, so detection works when the model is off.

**60. What can the AI see?**
- *Short:* only the structured incident fields, not raw logs or IDs.
- *Detailed:* see `build_user_prompt` in `ai/src/sentinelbot_ai/prompts.py`.

**61. How do you know the AI is not making things up?**
- *Short:* you cannot know completely. The system checks format, caps confidence, and shows the evidence next to the text.
- *Detailed:* the explanation quality is not yet measured. `docs/evaluation.md` defines the procedure.

**62. What happens if the model returns invalid JSON?**
- *Short:* the rule-based explanation is used, and the reason is recorded.
- *Detailed:* the `fallback_reason` field shows "model reply failed validation".

**63. What is prompt injection, and how does the system handle it?**
- *Short:* an attacker putting instructions in a log field, such as a username. The model cannot take actions, and its output cannot change severity or status.
- *Detailed:* see `docs/ai-analyst-explained.md`. The residual risk is a misleading explanation, which is why the evidence is shown beside it.

## Testing

**64. What do the tests cover?**
- *Short:* parsing, rules, scoring, correlation, the API, migrations, alerts, the AI fallback, and the Redis state.
- *Detailed:* agent 85 tests, detection 89 tests plus one Redis test that needs a server. The CI runs the rest against PostgreSQL and Redis.

**65. How do you test a detection rule?**
- *Short:* feed in events, check the detection.
- *Detailed:* each rule test builds a sequence of events with controlled timestamps, then asserts how many detections come out and what they contain. Cooldown and window edges are tested separately.

**66. Are the tests meaningful or just coverage?**
- *Short:* they check behavior, such as the fifth failure triggering a detection, not line counts.
- *Detailed:* the lab adds end-to-end checks that do not depend on the tests' own assumptions.

**67. What did the lab show?**
- *Short:* six scenarios, six expected results.
- *Detailed:* see `docs/laboratory-experiments.md`. The lab is a functional check on synthetic input, not a measurement of accuracy.

## Performance

**68. How fast is the system?**
- *Short:* not yet measured.
- *Detailed:* `docs/evaluation.md` defines the throughput, latency and resource measurements and the procedure for each. Lab runs take a fraction of a second, but that is dominated by process startup and says nothing about throughput.

**69. How much memory does the detection state use?**
- *Short:* not yet measured.
- *Detailed:* the windows are capped by `max_tracked_keys` (10,000 by default), so memory is bounded by design. The actual number is not measured.

**70. Can the system handle a large attack?**
- *Short:* the rules keep bounded state, so a flood does not exhaust memory. Throughput under a flood is not measured.

## Limitations

**71. What is the biggest limitation?**
- *Short:* there is no measured accuracy on real traffic.
- *Detailed:* everything that has been checked was checked on synthetic input or unit tests. The honest claim is "the rules behave as designed on controlled input".

**72. What does the system not do?**
- *Short:* no network analysis, no malware analysis, no automatic blocking, no cross-host correlation, no Docker security checks.
- *Detailed:* see `docs/project-understanding.md`, "What is missing or unfinished".

**73. Why is there no automatic response, such as blocking the attacker?**
- *Short:* automatic blocking can lock out the administrator, and the project does not have the evidence to decide safely.
- *Detailed:* the recommended actions tell the analyst what to check first. Blocking is listed as a manual step.

**74. What would you do with more time?**
- *Short:* per-host baselines, a file-source switch for the lab, a Docker collector, and measured evaluation on a labeled dataset.
- *Detailed:* these are the items in `docs/simplification-report.md` and `docs/evaluation.md`.

## Comparison with other systems

**75. How is SentinelBot different from a SIEM?**
- *Short:* a SIEM collects logs from many sources and searches them; SentinelBot collects host telemetry from Linux servers and runs a small set of rules.
- *Detailed:* a SIEM is broader and more mature. SentinelBot is narrow and transparent, which is the point of the study.

**76. How is it different from an EDR?**
- *Short:* an EDR watches process and file behavior on endpoints and can block; SentinelBot watches authentication and some host state, and does not block.
- *Detailed:* EDR has kernel-level sensors and response actions. SentinelBot has neither, and says so.

**77. Why not use an existing open-source tool such as OSSEC or Wazuh?**
- *Short:* those tools already exist and are mature. This project's purpose is to build and explain the pipeline.
- *Detailed:* the value of the project is the design and the honesty about its limits, not a replacement for those tools.

## Ownership

**78. Which parts did you design, and which were generated or supplied by tools?**
- *Short:* the architecture, the rules, the scoring, the correlation and the evaluation plan were designed in this project. Framework code, scaffolding and boilerplate were generated or supplied.
- *Detailed:* `docs/project-understanding.md` lists which parts are project logic and which are scaffolding. The honest statement is that AI tools wrote much of the code under the author's direction, and the author must be able to explain every design decision and every module on the critical path.

**79. What would you change if you started again?**
- *Short:* a single state backend, a file-source switch in the agent from the start, and per-host baselines.
- *Detailed:* the two-backend design and the shared baseline were the two decisions that caused the most later complexity.
