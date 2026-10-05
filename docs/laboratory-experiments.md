# Laboratory experiments

All experiments use synthetic data. No real system is attacked. The attacker and legitimate addresses come from RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), which are never routed on the internet.

## What was run

The script `scripts/lab/run_scenario.py` writes a fake `auth.log` in classic syslog format, then runs the real pipeline:

1. `sentinelbot-agent --once` with `SENTINEL_COLLECTORS=auth` reads the file and writes events as JSON Lines.
2. `sentinelbot-detect` runs the five rules on the events and writes detections.
3. `sentinelbot-correlate` groups the detections into incidents in a JSON store.

The script prints a summary and writes `.lab/runs/summary.json`.

### Environment

- Host: Windows 11, Python 3.12.10
- Packages: `sentinelbot-agent` and `sentinelbot-detection` installed in editable mode into `.lab/venv`
- Date of the recorded run: 2026-10-05
- Detection state: in memory (no Redis)

### Reproduce

From the repository root, after creating the venv and installing `agent` and `detection`:

```powershell
.lab\venv\Scripts\python.exe scripts\lab\run_scenario.py all --out .lab\runs
```

On Linux the same script works, with one caveat: the agent prefers the systemd journal when `journalctl` exists, so on a Linux host it reads the journal and ignores the synthetic file. Run the lab on Windows, or on a host without `journalctl`, until the file source can be forced explicitly (listed in `docs/simplification-report.md`).

### Verify

Check the printed `detections` and `incidents` fields against the expected results below. Each scenario directory also contains the raw `events.jsonl`, `detections.jsonl` and `incidents.json`, so the chain can be inspected one step at a time.

## Results

Every expected value below was derived from the rule definitions and thresholds before the run. The observed values come from the run above.

| # | Scenario | Input | Expected | Observed | Match |
| --- | --- | --- | --- | --- | --- |
| 1 | `normal` | 3 successful publickey logins by alice | No detections | 3 events, 0 detections, 0 incidents | yes |
| 2 | `bruteforce` | 8 failed logins for `admin` from one IP, 10 s apart | 1 `ssh_bruteforce` (cooldown suppresses the rest) | 8 events, 1 detection, 1 incident, risk 40, severity high | yes |
| 3 | `burst` | 35 failed logins from 35 IPs in 35 s | 1 `auth_burst` at the 30th attempt | 35 events, 1 detection, risk 20, severity medium | yes |
| 4 | `root` | 1 successful root login | 1 `root_login`, risk 50 | 1 detection, risk 50, severity high | yes |
| 5 | `combined` | Brute force, root login and normal logins from different IPs | 2 detections, 2 incidents (different sources) | 2 detections, 2 incidents | yes |
| 6 | `campaign` | 8 failures from one IP, then root login from the same IP 3 min later | 2 detections in 1 incident, risk 60 | 2 detections, 1 incident, `event_count` 2, risk 60, rules `ssh_bruteforce` and `root_login` | yes |

Risk 60 in scenario 6 comes from the root detection's factors: base 35 + combination 10 + privilege 15. The incident shows the maximum score, which is 60.

### Interpretation of the results

- Scenario 2 shows that the cooldown makes one incident out of eight raw failures. The incident's `event_count` counts detections, not failures. The analyst sees one detection, and the raw events remain in the event store.
- Scenario 3 shows the host-wide rule firing even though no single source reached the brute-force threshold. Each IP here had one failure.
- Scenario 6 is the only one of these runs that shows correlation merging two rules. It is the most important one to explain.

## Experiments not yet run

These experiments are in the plan, but they have not been run in this lab. Results are not reported.

| # | Scenario | Status | Reason |
| --- | --- | --- | --- |
| 4 | Unexpected listening service | **NOT YET RUN** | Needs `network_snapshot` events. The lab script only writes auth logs. Unit tests cover the rule. |
| 5 | Privileged process detection | **NOT YET RUN** | Needs `process_snapshot` events with root processes and a learned baseline. Unit tests cover the rule. |
| 6 | Docker security configuration detection | **NOT IMPLEMENTED** | No collector reads Docker state, and no rule checks Docker configuration. Do not present this as a working feature. |
| 8 | AI incident explanation | **PARTIALLY COVERED** | The analyst runs on the API endpoint and is tested with mocked model replies (`ai/tests/`, `backend/tests/test_analysis_api.py`). The lab script does not call it. Running the endpoint on a stack with a real API key is not done. |

Experiment 1 of the original plan (normal SSH activity) is scenario 1 above.

## Extending the lab

To add a scenario:

1. Add a function in `_build_scenarios` in `scripts/lab/run_scenario.py` that returns syslog lines built with `_sshd`.
2. Use only RFC 5737 addresses.
3. Write the expected result before running it, and add a row to the results table.
4. Run it and record the observed value. If the two differ, explain why in the document instead of changing the expected value.

For experiments 4 and 5, the script would also need to write `network_snapshot` and `process_snapshot` events. This is future work.

## Safety

- The lab writes only into `.lab/runs/` inside the repository.
- The script does not set `SENTINEL_API_URL`, so the agent writes to a file. It copies the rest of your environment, so unset `SENTINEL_API_URL` and `SENTINEL_REDIS_URL` in your shell before running, if they are set. Otherwise the lab could send synthetic events to a real API or read a real Redis.
- No credentials are used.
