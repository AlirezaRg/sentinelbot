"""Run one synthetic SSH scenario through the real agent, detection and correlation code.

The script writes a fake ``auth.log`` with documentation-only IP addresses (RFC 5737), then runs:

    sentinelbot-agent --once      auth log lines -> events (JSON Lines)
    sentinelbot-detect            events -> detections (JSON Lines)
    sentinelbot-correlate         detections -> incidents (JSON file)

Nothing is sent over the network and no real host is touched. Only the stdlib is used here, so
the script runs with any Python 3.12 environment where the packages are installed.

Usage (from the repository root, with the lab venv active):

    python scripts/lab/run_scenario.py normal
    python scripts/lab/run_scenario.py all --out .lab/runs
"""

from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

# RFC 5737 documentation addresses. They are never routed on the internet.
LEGIT_IP = "192.0.2.10"
ATTACKER_IP = "198.51.100.23"
ROOT_IP = "203.0.113.5"
HOST = "lab-host"


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    lines: list[str]


def _stamp(moment: datetime) -> str:
    # Classic syslog format: "Oct  4 09:06:27". No year, local time.
    return moment.strftime("%b %e %H:%M:%S")


def _sshd(moment: datetime, message: str) -> str:
    return f"{_stamp(moment)} {HOST} sshd[1234]: {message}"


def _build_scenarios(start: datetime) -> dict[str, Scenario]:
    rng = random.Random(42)  # fixed seed so every run produces the same file

    normal = [
        _sshd(
            start + timedelta(minutes=i * 5),
            f"Accepted publickey for alice from {LEGIT_IP} port {50000 + i} ssh2",
        )
        for i in range(3)
    ]

    # One attacker, one failure every 10 seconds for 80 seconds (8 failures).
    bruteforce = [
        _sshd(
            start + timedelta(seconds=i * 10),
            f"Failed password for invalid user admin from {ATTACKER_IP} port {40000 + i} ssh2",
        )
        for i in range(8)
    ]

    # Many failures from rotating source addresses inside one minute. No single IP passes the
    # per-source threshold, but the host-wide count does.
    burst = [
        _sshd(
            start + timedelta(seconds=i * 1),
            f"Failed password for user{rng.randint(1, 99)} from 198.51.100.{i + 1} "
            f"port {41000 + i} ssh2",
        )
        for i in range(35)
    ]

    root = [
        _sshd(
            start + timedelta(minutes=1),
            f"Accepted password for root from {ROOT_IP} port 52000 ssh2",
        )
    ]

    combined = sorted(bruteforce + root + normal, key=lambda line: line[:15])

    # The same attacker brute-forces, then logs in as root three minutes later. Both detections
    # share a source address, so they should correlate into one incident.
    campaign = bruteforce + [
        _sshd(
            start + timedelta(minutes=3),
            f"Accepted password for root from {ATTACKER_IP} port 52001 ssh2",
        )
    ]
    scenarios = [
        Scenario("normal", "Three successful logins by one user. Expect no detections.", normal),
        Scenario(
            "bruteforce",
            "Eight failures from one source. Expect ssh_bruteforce.",
            bruteforce,
        ),
        Scenario(
            "burst",
            "Thirty-five failures from many sources in one minute. Expect auth_burst.",
            burst,
        ),
        Scenario("root", "One successful direct root login. Expect root_login.", root),
        Scenario(
            "combined",
            "Brute force, a root login and normal logins mixed together.",
            combined,
        ),
        Scenario(
            "campaign",
            "One source brute-forces, then logs in as root. Expect one correlated incident.",
            campaign,
        ),
    ]
    return {scenario.name: scenario for scenario in scenarios}


def _run(args: list[str], env: dict[str, str]) -> None:
    result = subprocess.run(args, env=env, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit(f"command failed: {' '.join(args)}")


def run_scenario(scenario: Scenario, out_dir: Path) -> dict[str, object]:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    auth_log = out_dir / "auth.log"
    auth_log.write_text("\n".join(scenario.lines) + "\n", encoding="utf-8")
    events = out_dir / "events.jsonl"
    detections = out_dir / "detections.jsonl"
    store = out_dir / "incidents.json"

    env = {
        **os.environ,
        "SENTINEL_HOST_ID": HOST,
        "SENTINEL_COLLECTORS": "auth",
        "SENTINEL_AUTH_LOG_PATHS": str(auth_log),
        "SENTINEL_STATE_PATH": str(out_dir / "agent-state.json"),
        "SENTINEL_OUTPUT_PATH": str(events),
    }
    bin_dir = Path(sys.executable).parent
    started = time.perf_counter()
    _run([str(bin_dir / "sentinelbot-agent"), "--once"], env)
    agent_seconds = time.perf_counter() - started

    started = time.perf_counter()
    _run(
        [
            str(bin_dir / "sentinelbot-detect"),
            "--input",
            str(events),
            "--output",
            str(detections),
        ],
        env,
    )
    detect_seconds = time.perf_counter() - started

    _run(
        [
            str(bin_dir / "sentinelbot-correlate"),
            "--store",
            str(store),
            "--input",
            str(detections),
        ],
        env,
    )

    event_rows = _read_jsonl(events)
    detection_rows = _read_jsonl(detections)
    incidents = json.loads(store.read_text(encoding="utf-8"))["incidents"] if store.exists() else []
    return {
        "scenario": scenario.name,
        "log_lines": len(scenario.lines),
        "events": len(event_rows),
        "detections": sorted({row["metadata"]["rule_id"] for row in detection_rows if "rule_id" in row.get("metadata", {})}),
        "detection_count": len(detection_rows),
        "incidents": [
            {
                "title": incident["title"],
                "severity": incident["severity"],
                "risk_score": incident["risk_score"],
                "event_count": incident["event_count"],
                "rules": incident["rules"],
            }
            for incident in incidents
        ],
        "agent_seconds": round(agent_seconds, 3),
        "detect_seconds": round(detect_seconds, 3),
    }


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "scenario",
        choices=["normal", "bruteforce", "burst", "root", "combined", "campaign", "all"],
    )
    parser.add_argument("--out", type=Path, default=Path(".lab/runs"), help="output directory")
    args = parser.parse_args()

    # Start 30 minutes in the past so events are not in the future and the correlation gap
    # logic sees a realistic timeline.
    start = datetime.now().astimezone().replace(microsecond=0) - timedelta(minutes=30)
    scenarios = _build_scenarios(start)
    names = list(scenarios) if args.scenario == "all" else [args.scenario]

    results = []
    for name in names:
        result = run_scenario(scenarios[name], args.out / name)
        results.append(result)
        print(json.dumps(result, indent=2))

    (args.out / "summary.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
