# Event, detection and incident

These three words mean different things in SentinelBot, and mixing them up is the most common confusion in a defense.

- **Event:** one fact the agent observed. Example: one failed SSH login. Events are stored, and most are never shown as alerts.
- **Detection:** one conclusion a rule drew from events. Example: "5 failed logins from this IP in 5 minutes." A detection is an event of type `*_detected`.
- **Incident:** a group of detections that belong to the same story. Example: "possible SSH brute force from 198.51.100.23 on lab-host." Incidents are what analysts act on.

```
Event 1: failed SSH login  ┐
Event 2: failed SSH login  │
Event 3: failed SSH login  ├─ rule ssh_bruteforce ─► Detection
Event 4: failed SSH login  │                          │
Event 5: failed SSH login  ┘                          ▼ correlation
                                                 Incident INC-…
```

## Grouping

Detections are grouped by the pair `(host, source IP)`. A detection without a source IP, for example a new root process, is grouped by host alone.

A detection joins an existing incident when all of the following hold:

1. The incident is for the same host and the same source.
2. The incident is in an active state (OPEN or INVESTIGATING).
3. The detection arrives within **1800 seconds** of the incident's last activity.

If no incident matches, a new one starts. The gap is the key choice: an attack that pauses for half an hour starts a second incident. That is intentional, because a long pause usually means the attacker stopped, and a new incident gives the analyst a clean view.

Implementation: `Correlator._find_active` in `detection/src/sentinelbot_detection/correlation.py`.

## Time windows

There are two different windows in the system. Do not mix them up:

| Window | Where | Length | Purpose |
| --- | --- | --- | --- |
| Rule window | `ssh_bruteforce`, `auth_burst` | 300 s | Decides when a detection happens |
| Correlation gap | `Correlator` | 1800 s | Decides which detections belong together |

## Duplicate handling

- **Duplicate events:** the agent does not re-read a log line, because the read cursor moves forward. If the same batch is sent twice (a retry after a network error), the server rejects the duplicate `event_id` with HTTP 409, and the agent treats 409 as success.
- **Duplicate detections:** the cooldown stops a rule from emitting a detection for the same key again within 900 seconds.
- **Duplicate incidents:** the same `(host, source)` pair joins the existing incident while it is active.

Duplicate handling is by ID and by cooldown, not by comparing content. Two different events with identical text are both kept.

## Severity escalation

An incident's severity is the **maximum** severity of its detections. An incident that starts as MEDIUM becomes HIGH if a HIGH detection joins it. Severity never decreases automatically.

Its risk score is the **maximum** risk score of its detections, for the same reason. Scores are not summed.

## Lifecycle

```
            new detection in the gap
   OPEN ◄────────────────────────────┐
    │                                 │
    ├──► INVESTIGATING (analyst)      │
    │        │                        │
    ├────────┴──► RESOLVED (analyst) ─┘ a later attack starts a new incident
    │
    └──► FALSE_POSITIVE (analyst)
```

- **OPEN:** created by correlation. Active.
- **INVESTIGATING:** an analyst is looking at it. Still active, so new detections still join it.
- **RESOLVED:** the analyst closed it. Not active, so a later attack from the same source starts a new incident. This is deliberate: a closed case should not absorb new evidence silently.
- **FALSE_POSITIVE:** the analyst decided it was not an attack. Also inactive.

The API has a `POST /api/v1/incidents/{id}/resolve` endpoint, which sets RESOLVED and requires the analyst role. The CLI (`sentinelbot-correlate --set-status`) can set any of the four statuses. Moving an incident to INVESTIGATING or FALSE_POSITIVE through the API is not implemented, so the CLI is the only path for those states. This is a gap to mention in a defense.

## Example from the lab

Scenario `campaign`: 8 failed logins from 198.51.100.23, then a root login from the same address three minutes later.

1. The eighth failure triggers `ssh_bruteforce`, a detection with score 40. A new incident starts.
2. The root login triggers `root_login`, a detection with score 60 (35 base, 10 combination, 15 privilege). It is from the same source, within the gap, and the incident is OPEN, so it joins.
3. The incident has two detections, two rules, severity HIGH, risk score 60, and a title from the highest-priority rule (`ssh_bruteforce`).

Observed output: one incident, `event_count` 2, rules `ssh_bruteforce` and `root_login`.

## Recommended actions

Each rule has fixed recommended actions in `RULE_ACTIONS`. The incident combines the actions of all its rules, in priority order, without duplicates. These are checklists for an analyst, not automated responses.

## Storage

The incident store keeps related event IDs, capped at the most recent 200, and usernames, capped at 50. This keeps each incident a bounded size.

## Questions this design does not answer

- It does not link incidents across different source IPs, even if they come from the same network. Subnet grouping is future work.
- It does not link incidents across hosts. A campaign that hits ten servers produces ten incidents.
