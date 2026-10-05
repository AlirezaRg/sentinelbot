# Presentation outline

Target length: 10 to 15 minutes, plus questions. Each section lists its goal, the main point to make, and what to show. The presentation is about engineering decisions. Technology names are secondary.

## 1. Problem (1 min)

- **Goal:** show why the problem is real.
- **Say:** internet-facing Linux servers receive constant SSH guessing. Administrators need to notice patterns, not just grep logs.
- **Show:** a raw `auth.log` excerpt with failed logins from one address.

## 2. Motivation (1 min)

- **Goal:** explain why a student project is worth doing.
- **Say:** the goal is to build a small, transparent detection pipeline and be able to explain every step. Commercial systems are opaque; this one is not.
- **Show:** nothing. Speak.

## 3. Objectives (1 min)

- **Goal:** state what was built and what was not.
- **Say:** collect host authentication telemetry, detect five patterns, score them, correlate them into incidents, and explain the result. Not in scope: network analysis, malware, automatic blocking.
- **Show:** the five rules in a table.

## 4. Architecture (2 min)

- **Goal:** let the audience follow one event through the system.
- **Say:** agent on the host, server for detection, database for storage, dashboard and alerts for output. Detection is on the server so it sees every host.
- **Show:** the Mermaid diagram from the README, then the pipeline in `docs/architecture-explained.md`.

## 5. Agent (1 min)

- **Goal:** show how raw logs become typed events.
- **Say:** the agent parses only authentication messages. An `Accepted` line for root becomes a `ssh_root_login` event. A read cursor means each line is read once.
- **Show:** one log line and the resulting event JSON from the lab output.

## 6. Detection engine (2 min)

- **Goal:** explain one rule well.
- **Say:** the SSH brute-force rule keeps a time window per source address. At five failures in five minutes it emits one detection and starts a cooldown.
- **Show:** the whiteboard sequence from `docs/architecture-explained.md`. Then the `bruteforce` lab run: eight failures, one detection.

## 7. Risk scoring (2 min)

- **Goal:** make the score defensible.
- **Say:** the score is a heuristic. Base points for the rule, plus repetition, combination and privilege, capped at 100. It is not validated.
- **Show:** the `campaign` factors: 35 + 10 + 15 = 60.

## 8. Incident correlation (1 min)

- **Goal:** distinguish event, detection and incident.
- **Say:** events are observations, detections are conclusions from events, incidents are groups of detections an analyst acts on.
- **Show:** the `campaign` incident with two rules, one incident.

## 9. AI analyst (1 min)

- **Goal:** show that AI is not the detector.
- **Say:** the model reads a structured summary of an incident the rules already produced. Its output is validated, its confidence is capped, and a rule-based fallback always exists.
- **Show:** the fallback table in `docs/ai-analyst-explained.md`.

## 10. Dashboard (1 min)

- **Goal:** show the analyst's view.
- **Say:** incidents, their status, recommended actions, and metrics in Grafana.
- **Show:** the dashboard and Grafana, if they are running. If not, show screenshots taken from a running stack.

## 11. Experimental demonstration (2 min)

- **Goal:** show that the system behaves as designed on controlled input.
- **Say:** six synthetic scenarios, all with expected results written before the run. Five of six are single-rule cases; the campaign shows correlation.
- **Show:** the results table from `docs/laboratory-experiments.md`.

## 12. Evaluation (1 min)

- **Goal:** be honest about what has been measured.
- **Say:** functional checks pass. Detection rate, false-positive rate, latency, throughput, CPU, memory and API time are defined but not yet measured. Here is how each would be measured.
- **Show:** the status table in `docs/evaluation.md`.

## 13. Limitations (1 min)

- **Goal:** show that the author understands the system's weaknesses.
- **Say:** the shared baseline across nodes causes false alerts. A slow distributed attack is missed. The risk score is hand-tuned. No Docker security checks. No automatic response.
- **Show:** the limitations list in `docs/security.md`.

## 14. Future work (30 s)

- **Goal:** show direction, without promising more than the project can do.
- **Say:** per-host baselines, a file-source switch for the lab, a Docker collector, and a labeled evaluation.

## 15. Conclusion (30 s)

- **Goal:** end on the engineering decisions.
- **Say:** the key decisions were detection on the server, rules that can be explained, a score that shows its factors, correlation with a clear gap, and an AI step that cannot decide. The system is a prototype, and its results are only as strong as the evidence shown.

## Questions to expect

Start from `docs/defense-preparation.md`. The most likely are: why this threshold, what is a false positive, why not an existing SIEM, and what has been measured.
