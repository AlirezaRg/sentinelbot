# Detection rules

Each rule is a class in `detection/src/sentinelbot_detection/rules.py`. Each entry below gives the problem, input, algorithm, thresholds, output, severity, risk contribution, false positives, false negatives and a test case.

Thresholds are the defaults in `DetectionSettings` (`detection/src/sentinelbot_detection/settings.py`). They can be changed in the TOML config file.

## Rule 1: `ssh_bruteforce`

- **Problem:** one source address repeatedly guesses passwords.
- **Input:** `ssh_login_failed` events that have a `source_ip`.
- **Algorithm:** a sliding window of failure timestamps per source IP. Each new failure is added. Old entries are dropped. When the count reaches the threshold, the rule emits one detection and sets a cooldown for that IP.
- **Threshold:** 5 failures.
- **Time window:** 300 seconds.
- **Cooldown:** 900 seconds per source IP.
- **Output:** `ssh_bruteforce_detected`, with `failed_attempts`, `threshold`, `window_seconds`, `targeted_users` (up to a fixed maximum) and `targets_root`.
- **Severity:** HIGH.
- **Risk contribution:** base 40 points. See `docs/risk-scoring-explained.md`.
- **False positives:** a user with a broken SSH key or a script that retries. Five failures in five minutes is a reasonable first alarm, but it is not proof of an attack.
- **False negatives:** an attacker who spreads guesses over many IPs, or who stays under five failures per window. The `auth_burst` rule covers part of this. A slow attacker with a long gap between guesses is not caught.
- **Test case:** lab scenario `bruteforce` (8 failures from one IP). Expected: one detection, because of the cooldown. Observed in the lab run: one detection, risk score 40, severity high. See `docs/laboratory-experiments.md`.

**Important detail for a defense:** the cooldown means the rule emits one detection per 15 minutes per source, not one per failure. The incident therefore shows one detection even when eight failures happened. This is a design choice that keeps the dashboard readable, and it is also a limitation: the event count of the incident does not reflect the number of raw failures.

## Rule 2: `root_login`

- **Problem:** a successful direct login as root over SSH. Many hardening guides forbid it, so any occurrence deserves review.
- **Input:** `ssh_root_login` events, created by the parser when an `Accepted` line names user `root`.
- **Algorithm:** no threshold. Each event is checked against a cooldown keyed by `(source IP, username)`.
- **Threshold:** none. Any occurrence fires, unless it is inside the cooldown.
- **Cooldown:** 900 seconds.
- **Output:** `suspicious_root_login_detected`, with `auth_method`.
- **Severity:** HIGH.
- **Risk contribution:** base 35, plus 15 for privilege (the target is root). See the risk document.
- **False positives:** an administrator who logs in as root on purpose. The rule cannot tell an authorized administrator from an attacker.
- **False negatives:** root access through `sudo`, `su`, or a key that is not logged as root. Those do not produce `Accepted ... for root`.
- **Test case:** lab scenario `root`. Expected and observed: one `root_login` detection, risk 50, severity high.

## Rule 3: `auth_burst`

- **Problem:** many authentication attempts on one host in a short time, regardless of the source. Catches distributed attacks and mass credential stuffing.
- **Input:** `ssh_login_failed`, `ssh_login_success` and `ssh_root_login` events.
- **Algorithm:** one sliding window per host, containing every authentication attempt. The window stores whether each attempt failed. When the count reaches the threshold, the rule emits one detection for the host and sets a cooldown.
- **Threshold:** 30 attempts.
- **Time window:** 300 seconds.
- **Cooldown:** 900 seconds per host.
- **Output:** `auth_burst_detected`, with `attempts`, `failed_attempts`, `threshold` and `window_seconds`.
- **Severity:** MEDIUM.
- **Risk contribution:** base 20.
- **False positives:** a legitimate automation tool that logs in often, such as a backup job or a configuration management run.
- **False negatives:** a slow distributed attack that stays under 30 attempts in five minutes.
- **Test case:** lab scenario `burst` (35 failures from 35 addresses in 35 seconds). Observed: one `auth_burst` detection, risk 20, severity medium.

**Note:** the window stores successful attempts too, so a busy host with many successful logins can cross the threshold without any failures. The `failed_attempts` field in the output lets an analyst see which it was.

## Rule 4: `privileged_process`

- **Problem:** a process running as root that the host has not run before. This may be a persistence mechanism or a dropped tool.
- **Input:** `process_snapshot` events, which contain the top processes by CPU.
- **Algorithm:** set difference against a baseline. The first snapshot after the baseline file is empty is recorded as the baseline and does not alert. Later root processes whose `(name, executable)` pair is not in the baseline are reported, and then added to the baseline so each one alerts once.
- **Threshold:** none. Up to 20 detections per snapshot (`privileged_process_max_per_event`).
- **Kernel threads** (parent PID 2) are excluded.
- **Output:** `privileged_process_detected`, with `pid`, `ppid`, `name` and `exe`.
- **Severity:** MEDIUM.
- **Risk contribution:** base 25.
- **False positives:** a service that starts later, a package update, or a process that was quiet at baseline time. The baseline is capped to the top processes by CPU, so quiet root processes may be learned later and alert once.
- **False negatives:** a malicious process that copies the name and path of an existing process. A process that starts and exits between snapshots is not seen at all.
- **Known limitation:** the baseline is shared by all nodes in a deployment. A process that runs only on one node appears "new" on the other node. This is observed in the Kubernetes deployment and is the reason per-host baselines are listed as future work.
- **Test case:** not yet run in the lab. Needs a process snapshot with root processes. Tests in `detection/tests/test_rules.py` cover the baseline and kernel-thread logic.

## Rule 5: `unexpected_port`

- **Problem:** a service listens on a port that the operator did not expect.
- **Input:** `network_snapshot` events, which list listening TCP and UDP ports with their owning process.
- **Algorithm:** two modes.
  - **Allowlist mode** (when `allowed_listening_ports` is set): any observed port not in the list is a candidate.
  - **Baseline mode** (allowlist empty): the first snapshot is the baseline. Later ports not in the baseline are candidates.
  Each candidate has its own cooldown, keyed by protocol and port.
- **Threshold:** none.
- **Cooldown:** 900 seconds per `(protocol, port)`.
- **Output:** `unexpected_listening_port_detected`, with `protocol`, `port`, `process`, `pid` and `mode`.
- **Severity:** MEDIUM.
- **Risk contribution:** base 20.
- **False positives:** a port opened on purpose and missing from the allowlist, or a short-lived port (for example a package manager's temporary server).
- **False negatives:** a service that listens on an allowed port (for example 22 or 443). The rule cannot see that the service behind it is unexpected.
- **Known limitation:** the same shared-baseline issue as `privileged_process`.
- **Test case:** not yet run in the lab. Tests in `detection/tests/` cover both modes.

## Summary table

| Rule | Event input | Threshold | Window | Severity | Base points |
| --- | --- | --- | --- | --- | --- |
| `ssh_bruteforce` | `ssh_login_failed` per source IP | 5 | 300 s | high | 40 |
| `root_login` | `ssh_root_login` | every occurrence | none | high | 35 |
| `auth_burst` | auth events per host | 30 | 300 s | medium | 20 |
| `privileged_process` | process snapshot | new (name, exe) | baseline | medium | 25 |
| `unexpected_port` | network snapshot | not in allowlist or baseline | baseline | medium | 20 |

## How to add a rule

1. Write a class that inherits from `Rule` and defines `rule_id` and `event_types`.
2. Implement `evaluate(event)` so it returns a list of detection events.
3. Register the rule in `build_rules` and add its name to `ALL_RULES`.
4. Add thresholds to `DetectionSettings` if needed.
5. Add a base score to `DEFAULT_BASE_POINTS` in `scoring.py`.
6. Add a title and actions in `correlation.py`.
7. Write tests that feed events in and check the output, then add a lab scenario.
