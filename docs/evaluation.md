# Evaluation

This document defines the evaluation, states which metrics were measured and how, and marks every metric that has not been measured. No number appears here unless a script produced it and the raw output is in `docs/results/`.

## Status

| Metric | Status | Source |
| --- | --- | --- |
| Rule behaviour on synthetic scenarios | Measured: 6 of 6 scenarios matched their expected output | `docs/results/lab-scenarios-2026-10-05.json` |
| Detection rate (recall) on a labeled dataset | NOT YET MEASURED (no labeled dataset of sessions yet) | — |
| False-positive rate on normal sessions | NOT YET MEASURED as a rate; one normal scenario produced 0 detections | `docs/results/lab-scenarios-2026-10-05.json` |
| False-negative rate | NOT YET MEASURED as a rate; known false-negative cases are listed in `detection-rules.md` | — |
| Event processing throughput (offline pipeline) | Measured | `docs/results/benchmark-offline-2026-10-05.json` |
| CPU consumption (offline pipeline) | Measured | same |
| Memory consumption (offline pipeline) | Measured (peak RSS) | same |
| Detection latency | NOT YET MEASURED (see method below) | — |
| API response time | NOT YET MEASURED (needs the running stack) | — |
| Database impact | NOT YET MEASURED (benchmark does not write to PostgreSQL) | — |
| Risk score usefulness | NOT YET MEASURED (no analyst labels) | — |
| AI explanation quality | NOT YET MEASURED | — |

## Measured results

### 1. Lab scenarios (functional)

Six synthetic scenarios were run through the real agent, detection and correlation code. Each expected result was written from the rule definitions before the run.

| Scenario | Expected | Observed |
| --- | --- | --- |
| normal (3 successful logins) | No detection | 0 detections, 0 incidents |
| bruteforce (8 failures from one IP) | 1 `ssh_bruteforce` | 1 detection, risk 40 |
| burst (35 failures from 35 IPs in 35 s) | 1 `auth_burst` | 1 detection, risk 20 |
| root (1 root login) | 1 `root_login` | 1 detection, risk 50 |
| combined (brute force, root login, normal logins from different IPs) | 2 incidents | 2 incidents |
| campaign (brute force then root login from the same IP) | 1 incident with 2 rules | 1 incident, 2 detections, risk 60 |

This is a functional check on six hand-written inputs. It is not a detection rate.

### 2. Offline pipeline benchmark

Method: `scripts/lab/benchmark.py`. Each size was generated with a fixed seed (70% failed logins, 20% successful, 10% root). The agent, detection and correlation stages ran as child processes. Wall time, CPU time (user plus system) and peak resident memory (sampled every 10 ms over the whole process tree) were recorded. Each size was repeated three times; the median is reported. Counts were identical across repeats.

Environment: Windows 11, Python 3.12.10, single run, laptop (no other load controlled). Results from another machine will differ.

| Input lines | Events | Detections | Incidents | Agent wall (s) | Agent CPU (s) | Agent peak RSS (MB) | Detect wall (s) | Detect CPU (s) | Detect peak RSS (MB) | Correlate wall (s) | Correlate CPU (s) | Correlate peak RSS (MB) | Agent events/s |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 100 | 10 | 10 | 0.208 | 0.156 | 37 | 0.261 | 0.219 | 43 | 0.179 | 0.125 | 30 | 480 |
| 1,000 | 1,000 | 104 | 101 | 0.238 | 0.188 | 39 | 0.286 | 0.188 | 43 | 0.187 | 0.125 | 30 | 4,196 |
| 10,000 | 10,000 | 855 | 376 | 0.463 | 0.422 | 56 | 0.479 | 0.391 | 44 | 0.219 | 0.188 | 32 | 21,601 |
| 50,000 | 50,000 | 4,228 | 1,354 | 2.349 | 2.047 | 57 | 1.259 | 1.188 | 44 | 0.442 | 0.344 | 37 | 21,289 |

How to read these numbers:

- At 100 and 1,000 lines, most of the wall time is process start-up. Use the 10,000 and 50,000 rows for throughput.
- Agent throughput is about 21,000 lines per second on this machine for the file source. It is not the throughput of the whole system, because the API and database are not in this path.
- Peak memory is almost constant (about 40 to 60 MB per stage). Memory is bounded by the sliding-window limits and the incident store in this test, not by input size, except for the incident store, which grows with the number of incidents.

### 3. A finding from the benchmark

The file source reads at most 1 MiB per collection cycle (`MAX_FILE_READ_BYTES` in `agent/src/sentinelbot_agent/auth/sources.py`). The first benchmark attempt ran one cycle on a 50,000-line log and read only 10,196 events. The benchmark now runs cycles until the file is consumed, which took several cycles at that size.

Consequence: under a backlog, the agent sends events at the rate of one chunk per collection interval. At the default interval of 60 seconds, a backlog of about 10 MB would take about 10 minutes to drain, so alert latency grows with backlog size. This is a real limitation and is listed in `docs/limitations.md`. It is also the reason detection latency must be measured separately, not inferred from throughput.

## Methods for the metrics not yet measured

### Detection rate and false-positive rate on a labeled set

1. Write a generator with a seed parameter for each attack type (brute force with 5 to 200 attempts, spacing from 1 s to 10 min, 1 to 50 sources) and for normal sessions (automation logins, mistyped passwords, a monitoring tool that logs in often).
2. Label each session with the rule it should trigger, or "none".
3. Run each session through the pipeline with a fresh state directory.
4. Recall = detected attack sessions / attack sessions. False-positive rate = normal sessions with any detection / normal sessions.
5. Report counts with the seed range and the generator version. Give a confidence interval, for example Wilson, when reporting a rate.

Note that results describe the rules on the generator's sessions. They are not a statement about real attacks.

### Detection latency

1. Timestamp each event at generation (the generator knows it).
2. The detection event carries the timestamp of its triggering event. Compare it with the wall-clock time at which `sentinelbot-detect` writes the output.
3. Separate two parts: time from generation to agent read (dominated by the collection interval) and time from read to detection output (measured by the pipeline).
4. Report the median and 95th percentile over at least 100 sessions.

### API response time and database impact

1. Start the Compose stack on a host with PostgreSQL seeded with at least 100,000 events (generated with the benchmark's generator and posted through the API).
2. Use `hey` or an `httpx` script with fixed concurrency (for example 4 workers, 500 requests per endpoint) against `GET /api/v1/incidents`, `GET /api/v1/events` and `POST /api/v1/events` with a batch of 200.
3. Report p50, p95, p99 and error rate. Record the database size before and after.
4. Repeat with the same dataset after `VACUUM ANALYZE` to show the effect of statistics.

### Risk score usefulness

1. Ask at least two analysts to label a sample of incidents on a 1 to 5 severity scale, blind to the score.
2. Compute Spearman's rank correlation between the score and the mean label, and the agreement between analysts (Cohen's kappa).
3. Report the sample size; a sample under 30 incidents does not support a conclusion.

### AI explanation quality

1. Sample incidents, and for each explanation list every factual claim.
2. Check each claim against the incident fields. Count unsupported claims per explanation.
3. Rate usefulness with a fixed three-point rubric. Report the fallback rate from `fallback_reason`.

## Reporting rules

- Report the dataset, seed, hardware and software versions with every number.
- Report medians and percentiles over repeats, not single runs.
- Keep synthetic and real-host results apart.
- Keep failed or surprising runs in the report. The benchmark finding above is an example.
- Use **NOT YET MEASURED** until a run exists. Do not estimate.
