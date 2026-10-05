# Risk scoring explained

SentinelBot's risk score is a **heuristic**. It is a set of hand-chosen weights that rank detections. It has not been validated against labeled attack data, and it should not be described as a measure of probability. The score answers one question: given what the rules saw and the context they had, how urgently should an analyst look at this?

Implementation: `detection/src/sentinelbot_detection/scoring.py`.

## Formula

For one detection:

```
raw   = base + repetition + combination + privilege + reputation
score = clamp(raw, 0, 100)
```

Each term is a named factor, and the list of factors is stored with the detection, so the score can be reproduced by hand.

| Variable | Meaning | Default | Cap |
| --- | --- | --- | --- |
| `base` | Points for the rule that fired | ssh_bruteforce 40, root_login 35, auth_burst 20, privileged_process 25, unexpected_port 20 | none |
| `repetition` | `repeat_points × (number of earlier detections of the same rule from the same source in the window)` | 10 per repeat | 30 |
| `combination` | `combination_points × (number of other rules that fired from the same source in the window)` | 10 per other rule | 20 |
| `privilege` | Added when the detection targets or is root | 15 | none |
| `reputation` | `−trusted_penalty` for a trusted address, `+known_bad_bonus` for a known-bad address | −30 and +25 | none |

The window for repetition and combination is 900 seconds, per source (source IP, or host if there is no IP).

## Severity mapping

The score maps to a band. The rule's own severity is a floor, so the final severity is the higher of the two.

| Score | Band |
| --- | --- |
| 0-19 | info |
| 20-39 | low |
| 40-59 | medium |
| 60-79 | high |
| 80-100 | critical |

Band edges are `(20, 40, 60, 80)`.

Final severity = `max(rule severity, band)`. For example, `ssh_bruteforce` has rule severity HIGH. A score of 40 maps to MEDIUM, but the final severity stays HIGH, because a rule's own judgment is not lowered by the score.

## Worked examples

These values come from the lab runs (see `docs/laboratory-experiments.md`).

**Example 1: brute force, eight failures.** The rule fires once.
- base `ssh_bruteforce` = 40
- repetition: no earlier detection of this rule = 0
- combination: no other rule = 0
- privilege: target is not root = 0
- score = 40, band MEDIUM, final severity HIGH (rule floor)

**Example 2: root login, one event.**
- base `root_login` = 35
- privilege: target is root = 15
- score = 50, band MEDIUM, final severity HIGH (rule floor)

**Example 3: brute force followed by root login from the same IP (campaign).** The root login detection is the second detection for this source.
- base `root_login` = 35
- combination: one other rule (`ssh_bruteforce`) seen from this source = 10
- privilege = 15
- score = 60, band HIGH

The incident takes the **maximum** score of its detections, so the incident shows 60. The factors for the root detection are `base:root_login` 35, `combination` 10 and `privilege` 15.

**Example 4: a trusted address.** A detection with base 40 from an address on the trusted list:
- score = 40 − 30 = 10, band INFO. The rule's HIGH severity still applies.

## Why the weights were chosen

- Base points are ordered by how directly the rule shows an attack. A successful root login is a more direct sign than a burst of failed attempts, so its base is slightly lower (35) than a brute force (40), but the privilege bonus brings it higher in practice.
- Repetition and combination add points only when there is more evidence from the same source. This rewards persistence and multi-stage behavior.
- Caps stop one noisy source from reaching 100 by repetition alone.
- Trusted and known-bad lists let an operator encode knowledge the rules cannot see. The lists are operator-supplied and are not learned.

These weights are **not validated**. A defense should say so. What can be argued is that the ordering is consistent with common practice and that each point is traceable.

## Normalization

The score is clamped to 0-100. It is not normalized to a distribution, because there is no population of past attacks to normalize against. The incident keeps the maximum detection score, not a sum, so a long campaign with many detections does not drift toward 100 just by being long.

## Limitations

- The score cannot tell an authorized administrator from an attacker. `root_login` is HIGH for everyone.
- Repetition counts detections, not raw events. A brute force of 500 failures produces one detection because of the cooldown, so it scores the same as one of 8 failures. This is documented in `docs/detection-rules.md`.
- There is no learning and no feedback loop. Analysts can mark incidents as false positives, but the weights do not change.
- Reputation lists are static files.

## How to explain it in one sentence

"The score is a sum of named, hand-chosen points for how the detection was triggered, how often and by how many rules the same source triggered, and whether root was involved, capped at 100 and mapped to a severity band, with the rule's own severity kept as a minimum."
