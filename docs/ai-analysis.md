# AI analysis

This document states the boundary of the AI component, reviews its design, and lists its safeguards. The detailed explanation with the prompt and examples is in `docs/ai-analyst-explained.md`.

## The pipeline

```
Evidence (events from the host)
   ↓
Rule-based detection          (deterministic, tested)
   ↓
Correlation into an incident  (deterministic, tested)
   ↓
Risk score                    (heuristic, explainable)
   ↓
AI interpretation             (optional; text only; validated; falls back to rules)
```

The AI reads the output of the four deterministic steps. It cannot create detections, change severity, change status, or run anything on a host. Removing it leaves detection, scoring, correlation and alerting unchanged.

## Input

The model receives one JSON object built by `build_user_prompt`: title, description, severity, risk score, host, source address, usernames, rules triggered, detection count, first and last seen times, and status. It does not receive raw log lines, event identifiers or the metadata of individual events.

Reason for the restriction: raw lines contain attacker-controlled text in more places, and identifiers add nothing to an explanation. The restriction also bounds what a fabricated explanation can refer to.

## Output

The model must return one JSON object with these keys:

| Requested field | Implemented key |
| --- | --- |
| Summary | `summary` |
| Evidence | `evidence` |
| Severity assessment | `severity_assessment` |
| Possible explanations | `why_suspicious` |
| False-positive considerations | `false_positive_explanations` |
| Recommended investigation | `investigation_steps` |
| Recommended defensive remediation | `remediation` |
| Confidence | `confidence` and `confidence_note` |

The output is validated with pydantic (`AnalysisDraft`). Unknown or missing keys are rejected.

## Safeguards

| Risk | Safeguard | Residual risk |
| --- | --- | --- |
| Model returns text outside the JSON | Parser extracts the outermost braces and validates; anything else falls back | Low |
| Fabricated evidence | Prompt forbids statements the input does not show; the evidence field lists claims for an analyst to check | Medium: nothing verifies the claims automatically |
| Overconfidence | Confidence capped at 0.5 with fewer than three detections; the note explains the cap | Medium: the confidence value is the model's own estimate, not calibrated |
| Unsafe advice | Prompt limits advice to investigation and conservative remediation; output is text only | Medium: a human must read the advice |
| Prompt injection through usernames | Usernames are length-limited (255 characters); the model cannot change state; the prompt treats the input as data | Medium: the explanation can still be misled |
| Leaking sensitive data | Raw logs and identifiers are not sent; the provider is off by default | Medium when enabled: the summary leaves the host |
| Provider failure | Any exception falls back to the rule-based text, with `fallback_reason` set | Low |
| Credentials | The provider key is excluded from `repr()` and read from configuration | Low |

## Rule-based fallback

The default provider is `rules`. It builds the explanation from fixed text per rule, so it cannot invent evidence. It is less fluent than a model but reproducible.

## Limitations

- The explanation quality has not been measured. The procedure is in `evaluation.md`.
- The live model call has been tested only with mocked responses in `ai/tests/`.
- The model name default must be checked against the provider's current model list before use.
- Confidence values are not probabilities.
- The AI cannot see the raw evidence, so it cannot judge the content of commands or messages.

## Position for a defense

The AI is an explanation layer. Its value must be shown by measurement (explanation accuracy and analyst usefulness), not by assertion. Until those measurements exist, the honest claim is: the component is validated, bounded and optional, and its usefulness is unknown.
