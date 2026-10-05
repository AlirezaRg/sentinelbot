# Problem statement

## The problem

Linux servers exposed to the internet receive continuous SSH authentication attempts. Most are automated guessing from a small number of sources. Each attempt writes a line to the system's authentication log, and the same log records legitimate logins, sudo use and service restarts. An administrator who wants to know whether a host is being attacked, and whether an attack has succeeded, must find a few meaningful patterns among thousands of lines per day.

## Why host monitoring matters

- Authentication is the most common entry point for attacks on Linux servers that expose SSH. Monitoring it is a standard control in hardening guidance.
- A successful login after many failures, a root login, or a new privileged process are the points where an attack changes from noise to a compromise. Detecting them quickly limits damage.
- Small deployments (a handful of servers, a research lab, a university system) often cannot run a commercial SIEM or EDR. They need a transparent tool they can understand and audit.

## Why raw logs are hard to use

- Log lines are unstructured text, and their wording changes between distributions and software versions.
- A single meaningful event is spread over many lines. One attack produces hundreds of failures, and the important fact is the pattern, not any line.
- Lines from one attack are mixed with normal lines, and attacks come from many sources at the same time.
- Searching with `grep` answers a question once. It does not keep state, track time windows, or group related lines.

## Why event correlation is useful

A detection says that a pattern occurred. An analyst needs to know which detections belong to the same activity. Grouping detections by source address within a time window turns many alerts into one incident that can be investigated and closed. Without grouping, the same attack appears as many unrelated alerts, and a campaign with two stages (brute force, then login) appears as two unrelated events.

## Why risk scoring is useful

Different detections of the same kind differ in importance. A root login is more serious than a login to an unused account; a brute force that targets root is more serious than one that does not. A score lets an analyst order the queue. The score must be explainable to be useful. A score that cannot be explained is an opinion.

## Why AI-assisted analysis can be useful

An incident is a set of facts. Turning those facts into a short explanation, a list of plausible innocent causes and a list of checks takes time, and the wording is hard to standardize. A language model can draft that explanation from structured facts. Its usefulness depends on whether it stays within the facts it is given, which is a property that must be measured and cannot be assumed. Detection itself does not depend on it.

## Limitations of existing approaches

- **Manual log review** does not scale and does not remember state across days.
- **Simple alert rules** (for example "more than 10 failures in a minute") produce many duplicate alerts and no grouping.
- **Commercial SIEM and EDR products** are powerful but expensive, large, and opaque. Their detection logic is often not inspectable, which makes them hard to use for teaching or for independent evaluation.
- **Open-source host intrusion detection tools** cover many areas. A tool that does one thing with transparent logic is easier to explain and to test.
- **Machine learning approaches** need labeled data that small deployments do not have, and their decisions are harder to explain.

## The gap this project addresses

A transparent pipeline for Linux authentication telemetry that (1) turns log lines into typed events, (2) applies rules with explicit thresholds, (3) scores each detection with named, configurable factors, (4) groups related detections into incidents, and (5) keeps any AI explanation separate from the decision path and measurable against its inputs. The project is a research and teaching prototype. It is not a replacement for a production SIEM or EDR.

## Scope

In scope: Linux hosts, SSH and sudo authentication messages, listening ports, process snapshots, a central server, a dashboard, alerts, and a measured offline pipeline.

Out of scope: network traffic analysis, malware analysis, automatic response, cloud audit logs, Windows hosts, and any claim about detection on real attack traffic.
