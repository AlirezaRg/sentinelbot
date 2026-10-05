# Limitations

These limitations are stated plainly. Each one says whether it is a design choice, a known defect, or something that needs measurement.

## Detection

1. **Rule-based detection cannot detect every attack.** It detects the five patterns it implements. Slow attacks, attacks through other services, and attacks that do not use authentication are outside it. *Design.*
2. **False positives are possible.** Automation, mistyped passwords and authorized root logins all fire rules. The rate is **NOT YET MEASURED** on realistic data. *Measurement needed.*
3. **False negatives are possible.** Each rule's known gaps are listed in `detection-rules.md`. The rate is **NOT YET MEASURED**. *Measurement needed.*
4. **Suppressed attempts are invisible.** The cooldown hides repeated attempts from the incident. *Design choice with a cost.*
5. **Detection quality depends on log availability.** If sshd logs are disabled, rotated without the agent's cursor being preserved, or written to a different file, events are missed. *Environment dependency.*
6. **Process and port rules see snapshots, not events.** A short-lived process or port can be missed between collection intervals. *Design.*

## Risk score

7. **The risk score is heuristic.** It is not validated and must not be described as a probability. *Design.*
8. **Repetition is nearly inactive for the brute-force rule** because of the cooldown (see `risk-scoring.md`). *Known defect.*
9. **The score has no asset context and no outcome factor.** *Known gap.*

## Correlation

10. **Incidents do not span hosts or source addresses.** A campaign from many addresses, or across ten servers, produces many incidents. *Design.*
11. **Related event identifiers are capped at 200 per incident.** Older identifiers are dropped from the incident (the event store keeps events up to its capacity). *Design.*
12. **Status transitions are partial through the API.** The API can resolve; INVESTIGATING and FALSE_POSITIVE are set through the CLI only. *Known gap.*

## Agent

13. **The file source reads at most 1 MiB per collection cycle.** A large backlog is drained over several cycles, so alert latency grows with backlog size. Measured in `evaluation.md`. *Known defect for large backlogs.*
14. **The agent needs elevated access to read the journal and, in the container, host PID namespace.** This is the most sensitive part of the system. *Design, documented.*
15. **Only sshd and sudo messages are parsed.** Other services are not covered. *Design.*
16. **Parser coverage depends on OpenSSH message formats.** A new wording is ignored silently until a test is added. *Design risk.*

## Platform

17. **Linux only.** Windows and macOS hosts are not supported. The offline lab runs on Windows, but only because it avoids `journalctl`. *Scope.*
18. **The journal is preferred when present.** The offline lab on a Linux host therefore reads the journal instead of the synthetic file. *Known lab defect.*

## Security

19. **One shared service key for all agents.** A leaked key impersonates any host. *Known risk; design change needed.*
20. **No TLS between agent and API in the default stack.** *Deployment guidance given; not enforced.*
21. **Tokens are stored in the browser's local storage.** *Known risk.*
22. **The per-address rate limit does not protect against distributed guessing**, and behind a proxy it affects all users together. *Known risk.*
23. **Ingest is not rate limited.** *Known risk.*
24. **Redis has no authentication.** It is reachable only inside the Compose network. *Known risk.*
25. **Secrets were pasted into a chat during development** and must be rotated by the owner. *Operational.*

For the full analysis, see `security-analysis.md`.

## Deployment

26. **Kubernetes manifests were validated with kustomize only**, not with a live server dry run. *Measurement and verification needed.*
27. **The Kubernetes NodePorts have no TLS.** *Lab configuration.*
28. **The baseline is shared across nodes**, which causes false process and port alerts across a cluster. *Known defect.*
29. **Images are not pushed to a registry by the manifests.** *Setup step.*

## Evaluation

30. **No measurement on real attack traffic.** All functional results are from synthetic input. *Scope of evidence.*
31. **The API and database performance are NOT YET MEASURED.** *Measurement needed.*
32. **The offline benchmark ran on one Windows machine.** Other hardware will give other numbers. *Scope of evidence.*
33. **The AI explanation quality is NOT YET MEASURED.** *Measurement needed.*

## Dashboard and product

34. **The Containers page is a placeholder.** Docker telemetry is not collected. *Known gap.*
35. **The dashboard has no automated UI tests.** It is covered by type checking and a production build. *Known gap.*
36. **Public API documentation is served without authentication.** This reveals the endpoint list, not data. *Low risk.*

## Relation to other products

37. **SentinelBot is not a SIEM.** It does not collect general logs, search them, or retain them for compliance. *Scope.*
38. **SentinelBot is not an EDR.** It does not observe process behavior in depth, cannot block, and cannot contain an attack. *Scope.*
39. **Results depend on the laboratory environment.** Synthetic generators encode the author's assumptions about attacks, which is why measured rates must be reported with their generator. *Scope of evidence.*
