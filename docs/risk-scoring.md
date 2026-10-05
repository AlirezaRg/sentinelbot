# Risk scoring

This document is the formal description and critical review of the risk score. The worked examples and the step-by-step explanation are in `docs/risk-scoring-explained.md`.

## What the score is

The risk score is a **heuristic risk score** on a 0 to 100 scale. It orders detections by urgency using named, configurable factors. It is **not** a probability of attack, and it has not been validated against labeled data. It must not be described as one.

## Formula

For a detection `d` from source `s` at time `t`:

```
raw(d)   = base(rule(d)) + repetition(d) + combination(d) + privilege(d) + reputation(s)
score(d) = clamp(raw(d), 0, 100)
```

| Term | Definition | Default |
| --- | --- | --- |
| `base` | Points per rule | ssh_bruteforce 40, root_login 35, privileged_process 25, auth_burst 20, unexpected_port 20 |
| `repetition` | `min(10 × (k − 1), 30)`, where `k` is the number of earlier detections of the same rule from `s` in the last 900 s, plus this one | cap 30 |
| `combination` | `min(10 × m, 20)`, where `m` is the number of other rules that fired from `s` in the window | cap 20 |
| `privilege` | 15 if the detection targets root | 15 |
| `reputation` | −30 for a trusted address, +25 for a known-bad address | from operator lists |

Band edges (exclusive upper bounds): 20, 40, 60, 80, giving INFO, LOW, MEDIUM, HIGH and CRITICAL.

Final severity: `max(rule severity, band(score))`. A rule's own severity is a floor.

Incident score: the maximum `score(d)` over the detections in the incident.

## Properties

| Property | Assessment |
| --- | --- |
| Mathematically reasonable | Partly. The formula is additive with caps, which is simple and bounded. The weights are not derived from any model. |
| Explainable | Yes. Each detection stores its factors with their points. The sum can be checked by hand. |
| Configurable | Yes. Weights, caps, band edges and reputation lists are in the `[risk]` section of the TOML configuration. Unknown keys are rejected. |
| Deterministic | Yes. The same detection history gives the same score. |
| Testable | Yes. `detection/tests/test_scoring.py` tests each factor and the clamp. |
| Validated | No. |

## Critical review

### Weakness 1: repetition is almost dead for the main rule

Repetition counts earlier **detections** of the same rule, not failed attempts. The brute-force rule has a 15-minute cooldown per source, so a second detection from the same source within the window is suppressed. In the lab, eight failures produced one detection and a score of 40. The repetition factor never applies to `ssh_bruteforce` inside a 900-second window.

Severity impact: a brute force of 8 failures and a brute force of 800 failures from the same source receive the same score. This is the most important weakness.

### Weakness 2: the incident score does not grow with the attack

The incident takes the maximum detection score, so a long campaign scores the same as its worst single detection. This prevents score inflation, but it also means the score does not describe how large the attack was.

### Weakness 3: no outcome factor

The score does not change when a later **successful** login follows failures from the same source, unless the successful login is a root login. A successful login after a brute force is the most serious outcome, and the current design cannot express it. The scorer receives only detections, and successful logins are not detections, so the information is not available to the scorer at all.

### Weakness 4: no asset context

Every host is scored the same way. A database server and a test virtual machine receive the same points. The configuration has no per-host criticality.

### Weakness 5: weights are hand-chosen

The base points and caps are plausible but unvalidated. The ordering (brute force above root login above burst) is a judgment. It should be presented as a design decision, with the reasoning in `risk-scoring-explained.md`.

### Weakness 6: the score mixes two ideas

The score combines how certain a rule is, how serious the target is, and how persistent the source is. A single number hides which one drove the result. The factor list shows them, but the severity band does not separate them.

## Proposed redesign (not implemented)

Separate the score into four named components, each with its own cap, and keep the final number as their sum:

| Component | Meaning | Proposed input |
| --- | --- | --- |
| Confidence | How specific the rule is | Rule base points |
| Persistence | How much activity the source produced | Count of raw failed attempts in the window, scaled with `log2` and capped |
| Outcome | Whether the attack succeeded | +25 if a successful login from the source follows failures in the window |
| Exposure | How important the target is | Configurable per host, default 0 |

Implementing this needs two changes:

1. The scorer must receive authentication events in addition to detections, so it can count attempts and see outcomes. The current `Correlator` and `RiskScorer` receive detections only.
2. The cooldown must not hide counts: a suppressed detection should still update the incident's attempt count.

These change the ingest contract and need new labeled tests. They were not implemented in this review, and the reason is that a change of this size needs its own review and a benchmark run to confirm it does not slow ingest. It is the first item in `future-work.md`.

## What the score can and cannot claim

It can claim: a detection with more points has more of the configured risk factors present.

It cannot claim: that a detection with score 60 is more likely to be an attack than one with score 40. That would need validation data.

## Terminology

Use "risk score" and "heuristic". Do not use "probability", "likelihood" or "confidence" for the score. The AI confidence field is a separate thing and is also not a probability; see `ai-analysis.md`.
