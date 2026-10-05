# Evaluation methodology

This document defines how SentinelBot should be evaluated, how each metric is measured, and what has been measured so far. No performance or accuracy result is reported here unless it was measured. Metrics that have not been measured are marked **NOT YET MEASURED**.

## Status at a glance

| Metric | Status |
| --- | --- |
| Detection rate (recall) on synthetic scenarios | Functional check only: 4 of 4 attack scenarios produced the expected rule. Not a rate over many runs. |
| False-positive rate on normal activity | Functional check only: 0 detections on the `normal` scenario (3 events). Not a rate. |
| Detection latency | **NOT YET MEASURED** |
| Event processing throughput | **NOT YET MEASURED** |
| CPU consumption (agent, API) | **NOT YET MEASURED** |
| Memory consumption (agent, API) | **NOT YET MEASURED** |
| API response time | **NOT YET MEASURED** |
| Risk score usefulness | **NOT YET MEASURED** (no labeled dataset) |
| AI explanation quality | **NOT YET MEASURED** |

The functional checks are in `docs/laboratory-experiments.md`. They show that the pipeline behaves as designed on six hand-written inputs. They do not show how it behaves on real traffic, so they must not be reported as detection rates.

## Metric definitions and how to measure them

### 1. Detection rate (recall)

- **Definition:** of the attack instances in a labeled dataset, the fraction that produced the expected detection.
- **Formula:** `TP / (TP + FN)`, where TP is an attack instance that produced its detection and FN is one that did not.
- **Dataset needed:** a set of attack sessions, each labeled with the rule it should trigger. The lab can generate them, with the attack parameters varied (number of failures, spacing, number of sources).
- **Procedure:** generate N sessions with `run_scenario.py`-style functions and different random seeds. Run each through the pipeline. Count sessions with the expected rule in `detections.jsonl`.
- **Important:** a rate measured on synthetic sessions describes the rules on those sessions. It does not describe real attacks. Say so in any report.

### 2. False-positive rate

- **Definition:** of the normal sessions in a labeled dataset, the fraction that produced at least one detection.
- **Formula:** `FP / (FP + TN)`, where FP is a normal session that produced a detection and TN is one that did not.
- **Dataset needed:** normal sessions that include realistic patterns that could look like attacks: a user retyping a password, a script that retries a login, many successful logins from one automation account, a backup job that logs in often.
- **Procedure:** the same as recall, with normal sessions. Count how many produced any detection.

### 3. Detection latency

- **Definition:** time from the timestamp of the last event that completes a detection to the moment the detection is written.
- **Measurement:** the detection event carries the timestamp of the triggering event. Compare it with the wall-clock time when `sentinelbot-detect` writes the output. For the API, use the `sentinel_detection_latency_seconds` histogram on `/metrics`.
- **Note:** the agent collects on an interval (`SENTINEL_INTERVAL_SECONDS`, default 60). Most of the latency is the collection interval, not detection. Report both.

### 4. Event processing throughput

- **Definition:** events per second that the detection pipeline processes.
- **Measurement procedure (to be run):**
  1. Generate a synthetic auth log with N lines (mix of successful, failed and invalid lines).
  2. Time `sentinelbot-agent --once` and divide N by the elapsed time. This measures parsing.
  3. Time `sentinelbot-detect` on the resulting events file. This measures rules, scoring, and output.
  4. Time `sentinelbot-correlate`. This measures incident grouping.
- **Caveat:** process startup dominates small N. Use N of at least 100,000 and repeat at least 5 times. Report the median.
- **Hardware:** record CPU model, core count, RAM and OS for every result.

### 5. CPU and memory consumption

- **Definition:** CPU time and peak resident memory of each process during a run.
- **Measurement procedure (to be run):** on Linux, run each command under `/usr/bin/time -v` and record "User time", "System time" and "Maximum resident set size". On Windows, use `Get-Process` sampled every second, or record peak working set.
- **Components:** the agent during a collection cycle, `sentinelbot-detect` on a large events file, and the API under load (see item 6).

### 6. API response time

- **Definition:** time from request to response for the dashboard's main endpoints.
- **Endpoints:** `GET /api/v1/incidents`, `GET /api/v1/events`, `POST /api/v1/events` with a batch of 200.
- **Measurement procedure (to be run):** send 200 requests per endpoint with a fixed concurrency (for example 4 workers) using a load tool such as `hey` or a small Python script with `httpx`. Record p50, p95 and p99 latency, and the error rate.
- **Setup:** PostgreSQL with at least 100,000 events loaded, so the numbers reflect realistic table sizes. Record the dataset size with the results.

### 7. Risk score usefulness

- **Definition:** whether a higher score corresponds to a more serious incident, as judged by an analyst.
- **Measurement procedure (to be run):** label a set of incidents with an analyst severity (for example 1 to 5). Compute the rank correlation (Spearman) between the risk score and the label.
- **Caveat:** requires a labeled set and a judge. Without these, the score is a heuristic and must be described as one.

### 8. AI explanation quality

- **Definition:** whether the explanation is accurate, grounded in the input, and useful.
- **Measurement procedure (to be run):** for a sample of incidents, check each claim in the explanation against the input fields. Count unsupported claims. Rate usefulness on a short scale with a fixed rubric.
- **Also measure:** how often the fallback is used, and why (from `fallback_reason`).

## Reporting rules

- Report the dataset, the seed, the hardware and the software version with every number.
- Report medians and percentiles, not single runs.
- Separate synthetic results from results on real hosts.
- Keep failed or surprising runs in the report.
- Never fill a cell with an estimate. Use **NOT YET MEASURED** until a run exists.
