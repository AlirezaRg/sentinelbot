# SentinelBot Detection (Phase 3)

Reads telemetry events (JSON Lines from `sentinelbot-agent`) and writes detection events.
Every rule is plain Python with explicit thresholds, so each alert can be traced to the
values that caused it.

## Rules

| Rule ID | Triggers on | Detection event | Severity |
|---|---|---|---|
| `ssh_bruteforce` | N failed SSH logins from one source within a window (default 5 in 300s) | `ssh_bruteforce_detected` | high |
| `root_login` | any successful direct root SSH login | `suspicious_root_login_detected` | high |
| `auth_burst` | many auth attempts on one host within a window (default 30 in 300s) | `auth_burst_detected` | medium |
| `privileged_process` | a root-owned process whose name/executable is not in the baseline | `privileged_process_detected` | medium |
| `unexpected_port` | a listening port not in the allowlist, or new since the baseline | `unexpected_listening_port_detected` | medium |

Each rule has a cooldown (default 900s) per key, so one ongoing attack does not produce
hundreds of identical detections.

## Install

The detection package depends on the agent package for the shared `Event` model. Install the
agent first, then detection.

```bash
cd sentinelbot/agent && python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cd ../detection
pip install -e ".[dev]"
```

## Run

Pipe the agent into the detector:

```bash
sentinelbot-agent --once --collectors auth,processes,network | sentinelbot-detect --input -
```

With a baseline file (process and port rules need this to learn what is normal):

```bash
sentinelbot-detect --input events.jsonl --baseline ~/.local/state/sentinelbot/baseline.json
```

The first run with a new baseline learns and alerts on nothing for those two rules. Later
runs alert on new root processes and new ports.

## Configuration

A TOML file with a `[detection]` table. Unknown keys are errors, so typos are caught.

```toml
[detection]
bruteforce_threshold = 5
bruteforce_window_seconds = 300
auth_burst_threshold = 30
auth_burst_window_seconds = 300
cooldown_seconds = 900
allowed_listening_ports = [22, 80, 443]
enabled_rules = ["ssh_bruteforce", "root_login", "auth_burst", "privileged_process", "unexpected_port"]
```

## Test

```bash
pytest
ruff check src tests
mypy
```

All test events are synthetic (documentation IP ranges). Nothing is sent to a real host.

## Limitations

- State (windows, cooldowns) is in memory for one run. Long-running streaming, and state that
  survives restarts beyond the baseline file, arrive with Redis in Phase 8.
- The process baseline comes from the top-N processes by CPU, so quiet root processes may be
  missing from it and alert later.
- If the first baseline run happens while an attacker's process is already running, that
  process becomes part of the baseline. Review the baseline file after the first run.
- Docker rules and process-anomaly rules (new executable for a user, resource spikes) are not
  included yet. They need Docker telemetry or more process history.
- Risk scoring and correlation into incidents are Phases 4 and 5.
