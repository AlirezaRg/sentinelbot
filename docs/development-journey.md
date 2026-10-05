# Development journey

This document records how SentinelBot was built: the order of the decisions, the problems that appeared when the system ran for real, and what was changed in response. It is written for a defense. Each stage lists why it was needed, what problem it solved, what design decision was made, and what was tested.

Commit hashes refer to the repository history on `main`.

## Phase 1: Problem definition

- **Why needed:** a project without a defined problem cannot be evaluated.
- **Problem:** small Linux servers exposed to the internet receive constant SSH attacks. Administrators need a way to notice patterns (repeated failures, root logins, unexpected processes or ports) without running a full commercial SIEM.
- **Design decision:** scope to host-level telemetry on Linux. Do not try to cover networks, cloud accounts or malware analysis.
- **Tested:** not applicable at this stage. The output was a written scope.

## Phase 2: Architecture

- **Why needed:** the parts had to agree on one data model before any of them was written.
- **Problem:** five stages (collect, detect, score, correlate, present) needed clear boundaries.
- **Design decision:** agent on each host, detection on the central server, one `Event` model for all stages. Detection is on the server so that rules see every host. AI is a separate, optional last step.
- **Tested:** the architecture was reviewed against the goals. See `docs/architecture.md` and `docs/architecture-explained.md`.

## Phase 3: Linux agent

- **Why needed:** the only source of truth for host facts is the host.
- **Problem:** log formats change between OpenSSH versions. On Debian 13, sshd messages come from `sshd-session`, not `sshd`.
- **Design decision:** read the systemd journal when available, fall back to log files. Keep a read cursor so each line is read once. Use pure parsing functions so they can be tested without a host.
- **Tested:** 85 agent tests pass in the lab environment (see `docs/laboratory-experiments.md`).

## Phase 4: Event model

- **Why needed:** every later stage depends on the same shape of data.
- **Problem:** detections and raw events must be told apart, because rules and analysts treat them differently.
- **Design decision:** one pydantic model with an explicit `event_type` enumeration. Detections use `*_detected` types. Length limits on user-controlled fields.
- **Tested:** model validation tests in `agent/tests/`.

## Phase 5: Detection

- **Why needed:** this is the core academic contribution.
- **Problem:** a single failed login is normal. The rules needed time windows and thresholds, and a way to stop repeated alerts for one attack.
- **Design decision:** five transparent rules with thresholds in configuration. Sliding windows and cooldowns for state. A learned baseline for processes and ports, because a fixed list would be wrong on every new host.
- **Tested:** 89 detection tests pass, with one Redis test skipped locally (it runs in CI). The lab scenarios exercise the rules end to end.

## Phase 6: Risk scoring

- **Why needed:** the analyst needs to rank detections.
- **Problem:** detections from the same rule are not equally important. A brute force from a known-bad address and a single failure from an unknown one should not look the same.
- **Design decision:** a heuristic score made of named factors, capped at 100, with the rule's own severity kept as a floor. Every factor is stored so the score can be explained.
- **Tested:** `detection/tests/test_scoring.py`. The campaign lab scenario reproduces the score by hand (35 + 10 + 15 = 60).
- **Limitation found:** the score was not validated against labeled data, so it is documented as heuristic.

## Phase 7: Correlation

- **Why needed:** the analyst needs one object per attack, not one per detection.
- **Problem:** a brute force produces several detections over time. Without correlation, each one is its own alert.
- **Design decision:** group by host and source, with a 30-minute gap. Keep the closed-incident rule: a RESOLVED incident is never reused, so a later attack gets a clean record.
- **Tested:** `detection/tests/test_correlation.py`. The lab `campaign` scenario merges two rules into one incident.

## Phase 8: Backend

- **Why needed:** the detection code needs a server, a storage layer and an API.
- **Problem:** if detection ran in each agent, rules would see only one host, and a compromised agent could suppress its own alerts.
- **Design decision:** detection runs in the API ingest pipeline, so rules see all hosts. The agent only collects and sends.
- **Tested:** `backend/tests/test_api.py`, `test_server_detection.py`.

## Phase 9: Database

- **Why needed:** incidents must survive restarts and the dashboard needs to query them.
- **Problem:** a JSON file works for the lab, but not for several API workers writing at once. A migration problem also appeared on the VM: the code expected a `UserRow` that the old installed package did not have.
- **Design decision:** PostgreSQL with SQLAlchemy models and Alembic migrations. A test checks that migrations match the models, so the mismatch found on the VM is caught in CI.
- **Tested:** `database/tests/test_migrations.py`, `backend/tests/test_sql_backend.py` (PostgreSQL in CI).

## Phase 10: Monitoring

- **Why needed:** operators need to see whether the pipeline is running.
- **Problem:** the first Prometheus setup failed because the container user could not read its secret file. The fix was an ownership change on the host.
- **Design decision:** metrics from the API process, scraped by Prometheus, shown in a provisioned Grafana dashboard. A test checks that the dashboard refers to metrics that exist.
- **Tested:** `backend/tests/test_metrics.py`, `test_grafana_dashboard.py`.

## Phase 11: Dashboard

- **Why needed:** analysts need to act on incidents.
- **Problem:** the dashboard showed "Internal Server Error" for a while. The API container was not running because a native process already held port 8000. The dashboard was healthy; its dependency was not.
- **Design decision:** a thin Next.js app with a rewrite to the API, so the browser uses one origin. Login with user accounts and roles.
- **Tested:** type checking and production build in CI. No automated UI tests yet (listed as a limitation).

## Phase 12: AI analysis

- **Why needed:** analysts need readable explanations and next steps.
- **Problem:** a model that reads raw logs could invent evidence. The design had to keep detection independent of the model.
- **Design decision:** the model reads only the structured incident. The output is validated, its confidence is capped by the number of detections, and a rule-based explanation is always available as fallback.
- **Tested:** `ai/tests/`, using mocked model replies. The live model was not measured.

## Phase 13: Testing

- **Why needed:** a security tool that fails silently is worse than none.
- **Problem:** the CI pipeline failed several times for reasons outside the code: CRLF line endings broke shell continuation lines, one GitHub action version did not exist, and base image packages had known vulnerabilities.
- **Design decision:** lint, type check and test every package in a matrix. Run integration tests against real PostgreSQL and Redis. Scan the images with Trivy and fail on fixable critical and high findings. Audit dependencies.
- **Tested:** the final CI run on commit `9a63a04` passed all jobs.

## Phase 14: Evaluation

- **Why needed:** a defense needs measured claims, not expected ones.
- **Problem:** the project had functional tests, but no measurements.
- **Design decision:** define the metrics and the procedure for each (`docs/evaluation.md`). Record only what was measured. Mark the rest as not measured.
- **Tested:** the laboratory scenarios ran on 2026-10-05. Performance and accuracy metrics are not yet measured.

## Phase 15: Deployment

- **Why needed:** the system must run outside a developer machine.
- **Problem:** several issues appeared on the real VM, and they are the most useful part of this history:
  - The agent in Docker collected no SSH events. Cause: no journal access and no state directory. Fix: group membership for the journal and a writable state volume.
  - Duplicate "unexpected port" and "privileged process" incidents appeared every few minutes. Cause: no allowlist and no persisted baseline. Fix: a port allowlist and a baseline file.
  - Two Kubernetes nodes could not pull images. Cause: the cluster could not reach the registry. Fix: import the images directly into each node.
  - The baseline is shared across nodes, so a process on one node looks new on the other. This is not fixed.
- **Design decision:** Compose for a single host, Kubernetes for the multi-node test, with a DaemonSet for the agent.
- **Tested:** Compose stack running on the Debian VM, and a two-node k3s cluster with all pods running.

## Phase 16: Publication

- **Why needed:** the project should be visible and reproducible by others.
- **Problem:** the repository initially contained a line-ending conflict that broke CI, and the commit history contains automated co-author lines that are part of the record.
- **Design decision:** LF line endings enforced by `.gitattributes`, MIT license, contribution guide, and a security policy. The history was not rewritten.
- **Tested:** CI passed on `main`. A scan for personal paths and secrets found only test placeholders.

## Phase 17: Documentation for defense

- **Why needed:** the author must be able to explain the system without reading every file.
- **Design decision:** the documents in `docs/` separate what is implemented, what is measured, and what is planned.
- **Tested:** the laboratory scenarios were run to check the claims in the detection and correlation documents.
