# Objectives

Each objective has a measurable success criterion and the evidence that shows whether it is met.

| # | Objective | Success criterion | Evidence | Status |
| --- | --- | --- | --- | --- |
| O1 | Turn Linux authentication logs into typed, validated events | Parser extracts user, source address and result for sshd and sudo messages; invalid input is rejected | Agent tests (85 pass); lab scenarios | Met |
| O2 | Detect five suspicious authentication and host patterns with explicit thresholds | Each rule fires on its scenario and does not fire on the normal scenario | Detection tests (89 pass); lab results | Met for the lab; not measured on real traffic |
| O3 | Score each detection with a transparent, configurable formula | Each score can be reproduced from its stored factors | Scoring tests; campaign example (60 = 35 + 10 + 15) | Met; the formula is heuristic and not validated |
| O4 | Group related detections into one incident | The campaign scenario yields one incident with two rules; unrelated sources yield separate incidents | Lab results; correlation tests | Met for the lab |
| O5 | Keep AI explanations separate from detection and measurable against their inputs | Detection works with the AI disabled; AI output is validated and falls back to rules | AI tests; analysis endpoint tests | Met for validation and fallback; explanation quality NOT YET MEASURED |
| O6 | Enforce access control on the API | Each role can perform only its routes; the agent key cannot change incident status | Authorization tests (role matrix and route checks) | Met after the fix in `security-analysis.md` F1 |
| O7 | Measure the pipeline reproducibly | Benchmark and lab scripts run from the repository, with raw results committed | `docs/results/`; `scripts/lab/` | Met for the offline pipeline; API and database NOT YET MEASURED |
| O8 | Deploy the system on one host and on a small cluster | Compose stack runs; Kubernetes DaemonSet runs on two nodes | Deployment logs from the development VM and k3s cluster | Met as a demonstration; no production hardening |
| O9 | Document the design, the threats and the limitations honestly | Documents cover each component, the threat model, the security findings and the limitations | `docs/` | Met in this revision |

## Non-objectives

These were deliberately not goals:

- Matching the detection coverage of a commercial product.
- Reaching a specific false-positive rate on real traffic. This needs labeled data that the project does not yet have.
- Automatic blocking or response.
- Support for Windows or macOS hosts.
- Maximising the number of rules. Five rules with clear behavior were preferred over a larger set that cannot be tested.
