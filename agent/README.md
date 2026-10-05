# SentinelBot Agent (Phase 1)

Collects host telemetry and writes normalized events as JSON Lines.

Collected in Phase 1:

| Collector   | Event type         | Contents                                                            |
|-------------|--------------------|---------------------------------------------------------------------|
| `system`    | `system_info`      | hostname, OS, kernel version, machine, boot time, distribution      |
| `system`    | `system_metrics`   | CPU %, RAM, disk, load average (Unix only), uptime                  |
| `processes` | `process_snapshot` | PID, PPID, name, user, CPU %, memory %, RSS, executable, start time |
| `network`   | `network_snapshot` | listening TCP/UDP sockets, active connections, owning process name  |

Failures of a single collector produce a `collector_error` event and do not stop the agent.

## Run

```bash
cd sentinelbot/agent
python -m venv .venv
. .venv/bin/activate           # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
sentinelbot-agent --once       # one cycle to stdout
sentinelbot-agent --interval 30 --output events.jsonl
```

## Configuration

All settings are environment variables with the `SENTINEL_` prefix. CLI flags override them.

| Variable                      | Default                       | Meaning                              |
|-------------------------------|-------------------------------|--------------------------------------|
| `SENTINEL_HOST_ID`            | system hostname               | identifier stamped on every event    |
| `SENTINEL_INTERVAL_SECONDS`   | `60`                          | seconds between cycles               |
| `SENTINEL_CPU_SAMPLE_SECONDS` | `0.5`                         | CPU sampling window                  |
| `SENTINEL_MAX_PROCESSES`      | `200`                         | processes kept per snapshot          |
| `SENTINEL_MAX_CONNECTIONS`    | `500`                         | active connections kept per snapshot |
| `SENTINEL_COLLECTORS`         | `system,processes,network`    | collectors to run                    |
| `SENTINEL_OUTPUT_PATH`        | stdout                        | append events to this file           |
| `SENTINEL_AUTH_LOG_PATHS`     | `/var/log/auth.log,/var/log/secure` | file fallback when journalctl is absent |
| `SENTINEL_STATE_PATH`         | `~/.local/state/sentinelbot/agent-state.json` | resume state for the auth collector |
| `SENTINEL_JOURNAL_BOOTSTRAP_LINES` | `500`                    | auth entries read on the first run   |

Logs go to stderr as JSON; events go to stdout (or the output file), so the two can be separated.

## Privileges

The agent is read-only and needs no root for system and process data. Without root:

- Processes owned by other users report `null` for `exe` and similar fields.
- On Linux, sockets owned by other users appear with `pid: null`.

Running as root gives complete socket-to-process mapping. Prefer granting read access to a
dedicated group over running the agent as root. Phase 2 (auth logs) will document the
group-based approach for `/var/log/auth.log`.

## Test

```bash
pytest                 # unit + integration tests
ruff check src tests
mypy
```

The integration test runs the real collectors on the local host (read-only). No network
traffic is generated and no other machine is contacted.

## Limitations (Phase 1)

- Detection rules (brute force, bursts, etc.) are not implemented yet; Phase 3.
- Auth collection is opt-in: add `auth` to `SENTINEL_COLLECTORS` or `--collectors`.
- Auth events are emitted after each read; a crash in the middle of a cycle can lose that cycle.
- On file rotation, unread lines in the old file are not recovered.
- Process CPU is measured over one sampling window, so the first reading is approximate.
- Network snapshots use `psutil.net_connections`, which reflects a point-in-time table, not
  connection history.
- Windows is supported for development. The target platform is Linux.
