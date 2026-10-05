# Experiments

This document is the index for the experiments. Full details, expected results and observed results are in `laboratory-experiments.md`. Measured numbers are in `evaluation.md` and `docs/results/`.

## Index

| Scenario | Purpose | Script | Result file | Status |
| --- | --- | --- | --- | --- |
| A. Normal SSH activity | Expect no incident | `run_scenario.py normal` | `docs/results/lab-scenarios-2026-10-05.json` | Run; 0 detections |
| B. Repeated failed SSH authentication | Expect detection | `run_scenario.py bruteforce` | same | Run; 1 detection, risk 40 |
| C. Authentication burst | Expect detection | `run_scenario.py burst` | same | Run; 1 detection, risk 20 |
| D. Unexpected listening port | Expect detection | none | none | Not run; unit tests cover the rule |
| E. New privileged process | Expect detection | none | none | Not run; unit tests cover the rule |
| F. Docker security misconfiguration | Expect detection | none | none | **Not implemented.** No collector or rule exists. |
| G. Multiple correlated events | Expect one incident | `run_scenario.py campaign` | same | Run; 1 incident, 2 detections, risk 60 |
| Combined | Mixed sources | `run_scenario.py combined` | same | Run; 2 incidents |
| Benchmark | Throughput and resources | `benchmark.py` | `docs/results/benchmark-offline-2026-10-05.json` | Run at 100 to 50,000 lines |

Scenario F is listed in the original plan. It is not implemented, and no result should be reported for it.

## Scenarios D and E

They need network and process snapshots. The lab script writes only authentication logs. Adding them means writing `network_snapshot` and `process_snapshot` events in the lab, with synthetic listening ports and process names. The rule logic is already covered by unit tests in `detection/tests/`.

## Reproducing everything

From the repository root, with the lab venv (see `laboratory-experiments.md`):

```powershell
.lab\venv\Scripts\python.exe scripts\lab\run_scenario.py all --out .lab\runs
.lab\venv\Scripts\python.exe scripts\lab\benchmark.py --sizes 100 1000 10000 50000 --repeats 3 --out .lab\benchmark
```

The results are written to `.lab/`, which is not committed. Copy them to `docs/results/` with a date to keep them.

## Rules for new experiments

1. Write the expected result before running.
2. Use RFC 5737 addresses and synthetic usernames only.
3. Record the seed and the command.
4. Keep the failed or surprising runs in the document.
