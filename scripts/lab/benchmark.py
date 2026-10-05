"""Benchmark the offline pipeline: agent parsing, detection and correlation.

For each size the script writes a deterministic synthetic auth log, then runs the real CLIs
(``sentinelbot-agent --once``, ``sentinelbot-detect``, ``sentinelbot-correlate``) as child
processes. For each stage it records:

- wall-clock time
- CPU time (user + system) of the child process
- peak resident memory, sampled every 10 ms

Each size is repeated ``--repeats`` times and the median is reported.

What this does NOT measure: the API, PostgreSQL, network transfer, or Redis. Those need the
running stack and are listed as NOT YET MEASURED in ``docs/evaluation.md``.

Usage (from the repository root, with the lab venv active):

    python scripts/lab/benchmark.py --sizes 100 1000 10000 --repeats 3
"""

from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import statistics
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import psutil

HOST = "bench-host"
SAMPLE_SECONDS = 0.01
MAX_AGENT_CYCLES = 200
DETECT_CMD = [
    sys.executable,
    "-c",
    "import sys; from sentinelbot_detection.cli import main; sys.exit(main(sys.argv[1:]))",
]
CORRELATE_CMD = [
    sys.executable,
    "-c",
    "import sys; from sentinelbot_detection.correlate_cli import main; sys.exit(main(sys.argv[1:]))",
]


def make_log(lines: int, path: Path, seed: int = 7) -> None:
    """Write ``lines`` syslog sshd lines: 70% failures, 20% logins, 10% root logins."""
    rng = random.Random(seed)
    start = datetime.now().astimezone().replace(microsecond=0) - timedelta(hours=2)
    out: list[str] = []
    for i in range(lines):
        moment = start + timedelta(seconds=i * 0.5)
        stamp = moment.strftime("%b %e %H:%M:%S")
        ip = f"198.51.100.{rng.randint(1, 250)}"
        roll = rng.random()
        if roll < 0.7:
            message = f"Failed password for user{rng.randint(1, 50)} from {ip} port 40000 ssh2"
        elif roll < 0.9:
            message = f"Accepted publickey for alice from {ip} port 50000 ssh2"
        else:
            message = f"Accepted password for root from {ip} port 50001 ssh2"
        out.append(f"{stamp} {HOST} sshd[1234]: {message}")
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def run_measured(args: list[str], env: dict[str, str], log: Path) -> dict[str, float]:
    """Run a command, return wall seconds, CPU seconds and peak RSS in megabytes.

    Output goes to a file, not a pipe. A pipe is never drained while we sample, so a child that
    writes more than the pipe buffer would block forever.
    """
    started = time.perf_counter()
    with log.open("wb") as sink:
        proc = subprocess.Popen(
            args,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=sink,
            stderr=subprocess.STDOUT,
        )
        # On Windows the venv python.exe starts the base interpreter as a child, so the work is
        # done by a descendant. Sum the whole tree on every sample.
        peak = 0
        cpu_by_pid: dict[int, float] = {}
        root = psutil.Process(proc.pid)
        while proc.poll() is None:
            try:
                processes = [root, *root.children(recursive=True)]
                peak = max(peak, sum(_rss(p) for p in processes))
                for p in processes:
                    cpu = _cpu(p)
                    cpu_by_pid[p.pid] = max(cpu_by_pid.get(p.pid, 0.0), cpu)
            except psutil.Error:
                pass
            time.sleep(SAMPLE_SECONDS)
    wall = time.perf_counter() - started
    if proc.returncode != 0:
        sys.stderr.write(log.read_text(encoding="utf-8", errors="replace"))
        raise SystemExit(f"command failed: {' '.join(args)}")
    return {
        "wall_s": wall,
        "cpu_s": sum(cpu_by_pid.values()),
        "peak_rss_mb": peak / (1024 * 1024),
    }


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open(encoding="utf-8") as handle:
        return sum(1 for _ in handle)


def _rss(process: psutil.Process) -> int:
    try:
        return int(process.memory_info().rss)
    except psutil.Error:
        return 0


def _cpu(process: psutil.Process) -> float:
    try:
        times = process.cpu_times()
        return float(times.user + times.system)
    except psutil.Error:
        return 0.0


def bench_once(
    lines: int, work: Path, bin_dir: Path, base_env: dict[str, str]
) -> dict[str, object]:
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    log = work / "auth.log"
    make_log(lines, log)
    events = work / "events.jsonl"
    detections = work / "detections.jsonl"
    store = work / "incidents.json"
    env = {
        **base_env,
        "SENTINEL_HOST_ID": HOST,
        "SENTINEL_COLLECTORS": "auth",
        "SENTINEL_AUTH_LOG_PATHS": str(log),
        "SENTINEL_STATE_PATH": str(work / "agent-state.json"),
        "SENTINEL_OUTPUT_PATH": str(events),
    }
    # Run the modules directly. The sentinelbot-*.exe launchers on Windows start a second
    # Python process, and measuring the launcher would report its memory, not the pipeline's.
    python = sys.executable
    # The file source reads at most 1 MiB per collection cycle, so a large log needs several
    # cycles. Run cycles until every line has been read or a cycle makes no progress.
    agent = {"wall_s": 0.0, "cpu_s": 0.0, "peak_rss_mb": 0.0}
    cycles = 0
    while True:
        before = _count_lines(events)
        cycle = run_measured(
            [python, "-m", "sentinelbot_agent", "--once"],
            env,
            work / f"agent-{cycles}.log",
        )
        cycles += 1
        for key in ("wall_s", "cpu_s"):
            agent[key] += cycle[key]
        agent["peak_rss_mb"] = max(agent["peak_rss_mb"], cycle["peak_rss_mb"])
        after = _count_lines(events)
        if after >= lines or after == before or cycles > MAX_AGENT_CYCLES:
            break
    agent["cycles"] = cycles
    detect = run_measured(
        [*DETECT_CMD, "--input", str(events), "--output", str(detections)],
        env,
        work / "detect.log",
    )
    correlate = run_measured(
        [*CORRELATE_CMD, "--store", str(store), "--input", str(detections)],
        env,
        work / "correlate.log",
    )
    event_count = sum(1 for _ in events.open(encoding="utf-8"))
    detection_count = (
        sum(1 for _ in detections.open(encoding="utf-8")) if detections.exists() else 0
    )
    incidents = (
        len(json.loads(store.read_text(encoding="utf-8"))["incidents"])
        if store.exists()
        else 0
    )
    return {
        "log_lines": lines,
        "events": event_count,
        "detections": detection_count,
        "incidents": incidents,
        "agent": agent,
        "detect": detect,
        "correlate": correlate,
        "events_per_second_agent": event_count / agent["wall_s"]
        if agent["wall_s"]
        else None,
    }


def summarize(runs: list[dict[str, object]]) -> dict[str, object]:
    """Median of each measured number across repeats. Counts must match between repeats."""
    first = runs[0]
    summary: dict[str, object] = {
        "log_lines": first["log_lines"],
        "events": first["events"],
        "detections": first["detections"],
        "incidents": first["incidents"],
        "repeats": len(runs),
    }
    for stage in ("agent", "detect", "correlate"):
        summary[stage] = {
            key: round(statistics.median(float(run[stage][key]) for run in runs), 3)  # type: ignore[index]
            for key in ("wall_s", "cpu_s", "peak_rss_mb")
        }
    summary["events_per_second_agent"] = round(
        statistics.median(float(run["events_per_second_agent"]) for run in runs),
        1,  # type: ignore[arg-type]
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--sizes", type=int, nargs="+", default=[100, 1000, 10000, 50000]
    )
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--out", type=Path, default=Path(".lab/benchmark"))
    args = parser.parse_args()

    bin_dir = Path(sys.executable).parent
    base_env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("SENTINEL_")
    }
    results = []
    for size in args.sizes:
        runs = [
            bench_once(size, args.out / f"n{size}-r{repeat}", bin_dir, base_env)
            for repeat in range(args.repeats)
        ]
        summary = summarize(runs)
        results.append(summary)
        print(json.dumps(summary, indent=2))

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "benchmark.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
