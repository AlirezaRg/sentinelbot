# Future work

The roadmap is ordered by academic value and by risk reduction, not by feature count. Items marked **Priority 1** address a known defect or an evaluation gap. Items marked **Deferred** are listed so they are not forgotten, not because they should be built now.

## Priority 1: measurement and correctness

1. **Labeled evaluation dataset.** A generator with seeds and labels for attacks and normal sessions, then recall and false-positive rates with confidence intervals (method in `evaluation.md`).
2. **Measured API and database performance.** Response times and database impact on a seeded PostgreSQL with at least 100,000 events.
3. **Force the file source in the agent** (for example `SENTINEL_AUTH_SOURCE=file`), so the offline lab runs on Linux and in CI.
4. **Drain backlogs faster** in the file source, either by reading more per cycle or by continuing while data remains, and measure the change.

## Priority 1: security

5. **Per-agent keys** bound to `host_id`, stored in the database, revocable individually.
6. **TLS for agent to API** by default in Compose and Kubernetes, with certificates provided by the operator.
7. **Rate limit on ingest** per agent key.

## Priority 2: scoring and correlation

8. **Redesign the risk score** into confidence, persistence, outcome and exposure components, as described in `risk-scoring.md`. Requires scorer access to authentication events and tests for each component.
9. **Count suppressed attempts** in the incident without creating extra detections.
10. **Outcome rule**: a successful login from a source that had failures in the window. Needs labeled data to justify its threshold.
11. **Per-host baselines** for processes and ports, which removes the cross-node false positives.

## Priority 2: deployment and operations

12. **Ingress with TLS and NetworkPolicies** for Kubernetes, replacing NodePorts.
13. **Server-side session revocation** and an HttpOnly cookie for the dashboard, replacing local storage.
14. **Heartbeat check** for silent agents.
15. **Live dry run** of the Kubernetes manifests in CI against a disposable cluster.

## Deferred

These are plausible additions. Each one would enlarge the project without a clear academic result, so they are deferred until the items above are done.

- More Linux distributions. The parsers would need test fixtures from each.
- Additional rules. Only with a clear behavior, a test and an evaluation case.
- Anomaly detection or machine learning. Needs labeled data and an evaluation protocol that the project does not yet have.
- Multi-host correlation across incidents that share a network range.
- Threat-intelligence feeds. These add external dependencies and trust questions.
- Cloud deployment beyond the existing Kubernetes manifests.
- Docker-level security checks. Not implemented; the lab plan lists it as unimplemented.
