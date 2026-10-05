# Detection rules

Each rule is a small class in `detection/src/sentinelbot_detection/rules.py` with explicit thresholds. Thresholds live in `DetectionSettings` (`settings.py`) and can be changed through configuration.

| Rule | Triggers when | Default |
| --- | --- | --- |
| `ssh_bruteforce` | Failed SSH logins from one source IP | 5 failures within 300 s |
| `root_login` | A successful login as root | Every occurrence |
| `auth_burst` | Many authentication attempts on one host | 30 attempts within 300 s |
| `privileged_process` | A root-owned process that is not in the learned baseline | Baseline learned from the first snapshot |
| `unexpected_port` | A listening port that is not allowed | Allowlist, or baseline mode when no allowlist is set |

## Details

**ssh_bruteforce** counts failed logins per source IP in a sliding window.

**root_login** fires on any successful root login. Its severity is high by default.

**auth_burst** is a host-wide rate check. It catches attacks that rotate source IPs, which `ssh_bruteforce` would miss.

**privileged_process** compares root-owned processes with a baseline. Kernel threads (parent PID 2) are excluded. The baseline is saved to `SENTINEL_BASELINE_PATH` so it survives restarts. It is currently shared across nodes, so a process that exists only on one node can raise a false alert on the other.

**unexpected_port** uses `SENTINEL_ALLOWED_PORTS` when it is set. Otherwise it uses the baseline.

## Cooldowns

After a rule fires for a key (for example, one source IP), it stays quiet for `cooldown_seconds` (default 900 s). This prevents one ongoing attack from creating hundreds of detections.

## Risk scoring

`RiskScorer` (`scoring.py`) gives each detection a score from 0 to 100 and a severity band, and records the factors that produced the score. The final severity is `max(rule severity, band)`, so scoring can raise severity but never lower it below the rule's own value.

## Incidents

Detections are grouped by `(host, source_ip)` with a gap-based window. A new detection that arrives within the gap joins the open incident. Each incident has a title and suggested actions per rule, defined in `correlation.py` (`RULE_TITLES`, `RULE_ACTIONS`).

## Adding a rule

1. Add a class that subclasses `Rule` in `rules.py`.
2. Add its name to `ALL_RULES` and to `build_rules`.
3. Add thresholds to `DetectionSettings` if needed.
4. Add a title and actions in `correlation.py`.
5. Add tests in `detection/tests/test_rules.py`.
