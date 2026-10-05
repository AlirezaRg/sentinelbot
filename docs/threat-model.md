# Threat model

Methodology: STRIDE applied per trust boundary, after identifying assets and actors. STRIDE fits here because the system is a set of components exchanging messages across a few well-defined boundaries, and each boundary can be checked for spoofing, tampering, repudiation, information disclosure, denial of service and elevation of privilege.

Scope: the SentinelBot software as described in `docs/architecture.md`. The threat model does not cover the Linux host's own hardening, the network, or the hosting provider.

## Assets

| ID | Asset | Why it matters | Confidentiality | Integrity | Availability |
| --- | --- | --- | --- | --- | --- |
| A1 | Host authentication logs and telemetry | Source of every detection | Medium (usernames, source IPs) | High | Medium |
| A2 | Incidents and detections | What analysts act on | Medium | High | High |
| A3 | Service API key (`SENTINEL_API_KEY`) | Lets a caller ingest events | High | High | Medium |
| A4 | User accounts and password hashes | Dashboard access | High | High | Medium |
| A5 | Signing secret (`SENTINEL_AUTH_SECRET`) | Forging login tokens if leaked | Critical | Critical | High |
| A6 | Database (PostgreSQL) | Stores A1, A2, A4 | High | High | High |
| A7 | Learned baseline file | Decides which processes and ports are "new" | Low | High | Medium |
| A8 | SMTP and AI provider credentials | Sending mail, calling the model | High | Medium | Low |
| A9 | Monitored host itself | The thing the system protects | Critical | Critical | Critical |

## Actors

| ID | Actor | Capability | Motivation |
| --- | --- | --- | --- |
| T1 | Remote attacker on the internet | Sends SSH traffic to monitored hosts; may try the dashboard if exposed | Gain access to hosts |
| T2 | Attacker controlling a log field | Chooses usernames typed into SSH login attempts, which appear in logs | Inject misleading text, for example into the AI prompt |
| T3 | Compromised agent | Holds the service key and can send any events | Hide activity, flood the server, or fake detections |
| T4 | Network attacker on the agent-to-API path | Can observe or alter traffic if TLS is not used | Steal the key, change events |
| T5 | Malicious or curious dashboard user | Holds a viewer or analyst account | Read data beyond their role, or hide incidents |
| T6 | Local user on the monitored host | Can read files the agent writes | Read the baseline or state files |
| T7 | Supply-chain attacker | Compromises a dependency or base image | Run code in the pipeline or in images |

## Attack surface

- HTTP API on port 8000 (`/api/v1/*`, `/health`, `/metrics`, `/docs`).
- Login endpoint `/api/v1/auth/login`.
- Agent ingest endpoint `POST /api/v1/events`.
- Dashboard on port 3001, which forwards `/backend/*` to the API.
- Agent inputs: journal entries and log files. These are untrusted text.
- Grafana (3000) and Prometheus (9090), bound to localhost in Compose and NodePorts in Kubernetes.
- Email (SMTP) and the Anthropic HTTP API as outbound connections.
- Container images and Kubernetes manifests.

## Trust boundaries

```
 [internet / attacker T1]
         │  SSH to monitored host
 ┌───────▼────────────────────────── B1: host kernel and log writer ─────┐
 │  sshd writes auth log / journal                                       │
 │        │ read (B2: agent reads log files; untrusted text)             │
 │  ┌─────▼──────────┐                                                   │
 │  │ agent (T3 risk)│                                                   │
 │  └─────┬──────────┘                                                   │
 └────────│──── B3: agent → API, HTTP + service key (T4 risk) ────────────┘
          │
 ┌────────▼──────── B4: API process ─────────────────────────────────────┐
 │  auth, ingest, detection, scoring, correlation, alerts, AI           │
 └──┬──────────┬───────────────┬──────────────┬───────────────┬─────────┘
    │ B5 SQL   │ B6 Redis      │ B7 SMTP      │ B8 HTTPS      │ baseline file
 PostgreSQL   Redis          mail server   Anthropic API   (local disk, B9)

 Browser (T5) ──B10 HTTP + bearer token──► Next.js ──rewrite──► API (B4)
 Prometheus ──B11 scrape with key/token──► /metrics
```

Each boundary is discussed below. B2 is the boundary where attacker-controlled text enters the system.

## Threats and mitigations (STRIDE per boundary)

### B2: log text → parser (attacker-controlled input)

| STRIDE | Threat | Mitigation in code | Residual risk |
| --- | --- | --- | --- |
| Tampering | A username containing special text is stored and shown | Fields are length-limited (255 characters) and typed; the dashboard renders text as text, never as HTML | Low |
| Spoofing | A crafted log line claims a different source IP | Only the text matching a fixed pattern is parsed; the IP must pass `ipaddress` validation | Medium: anyone who can write to the log can forge a line. The threat model assumes the log is trustworthy on the host, which is the same assumption every host-based IDS makes |
| Denial of service | Very long lines or floods | Message length limit; batch size limit (200 events per request); bounded windows (`max_tracked_keys`) | Medium: a flood still consumes CPU and disk |
| Information disclosure | Passwords typed into a wrong field appear in logs | The parser never extracts passwords; sudo commands are reduced to the executable name | Low |
| Prompt injection (AI) | Usernames contain instructions for the model | The model's output cannot change status or severity; output is validated; the prompt tells the model to treat input as data | Medium: see `ai-analysis.md` |

### B3: agent → API

| STRIDE | Threat | Mitigation in code | Residual risk |
| --- | --- | --- | --- |
| Spoofing | Someone other than an agent sends events | Service key compared in constant time (`hmac.compare_digest`); key must be at least 24 characters | High without TLS: the key can be captured on the wire (T4). Compose runs HTTP on the internal network |
| Tampering | Events changed in transit | None beyond TLS, which is not configured | High on untrusted networks |
| Repudiation | Which agent sent an event | Events carry `host_id`; there is no per-agent key | Medium: any agent can claim any host |
| Elevation of privilege | Key used for something beyond ingest | Fixed in this review: the service key may read and ingest, but cannot change incident status (see `security-analysis.md`, F1) | Low after the fix |
| Denial of service | Flood of batches | Rate limit on login only; batch size limit per request | High: ingest is not rate limited |

### B4: API process (authentication and authorization)

| STRIDE | Threat | Mitigation in code | Residual risk |
| --- | --- | --- | --- |
| Spoofing | Forged bearer token | HMAC-SHA256 signature checked with `compare_digest`; expiry checked; secret must be at least 32 characters | Low |
| Spoofing | Guessing passwords | scrypt password hashing; login rate limit (10 per minute per client address) | Medium: the limit is per client address, so a distributed guesser is not limited |
| Tampering | Changing a token's role | The role is inside the signed payload | Low |
| Information disclosure | Errors leaking internals | Errors return generic messages | Low |
| Information disclosure | API schema published at `/docs` and `/openapi.json` | Not disabled | Low: lists endpoints, requires no login |
| Elevation of privilege | Viewer changes incidents | Role checks on each route (`require_viewer`, `require_analyst`, `require_ingest`) | Low, and tested (`backend/tests/test_authorization.py`) |
| Elevation of privilege | Service key bypasses role checks | Fixed in this review (F1) | Low after the fix |

### B5/B6: API → PostgreSQL and Redis

| STRIDE | Threat | Mitigation in code | Residual risk |
| --- | --- | --- | --- |
| Tampering / disclosure | SQL injection | SQLAlchemy parameters; no string-built SQL found in the source | Low |
| Information disclosure | Database password leaked | Passed through environment or Kubernetes Secret; never committed | Medium: the password was pasted in chat during development and must be rotated (operational) |
| Denial of service | Redis unavailable | Redis is optional; in-memory state is used when no URL is set | Medium when Redis is configured |
| Tampering | Unauthenticated Redis | Not published outside the Compose network; no password set | Medium: any container on the network can write to it |

### B7/B8: API → SMTP and Anthropic

| STRIDE | Threat | Mitigation in code | Residual risk |
| --- | --- | --- | --- |
| Information disclosure | Incident data sent to a third party | AI provider is off by default; prompt contains only summary fields, no raw logs | Medium when enabled: the summary leaves the host |
| Information disclosure | SMTP password in logs | Field excluded from `repr()` | Low |
| Denial of service | Mail server down | Notifier isolates channel failures | Low |

### B9: local files (baseline, state, incident store)

| STRIDE | Threat | Mitigation in code | Residual risk |
| --- | --- | --- | --- |
| Tampering | Attacker edits the baseline to hide a new process | Files are owned by the service user; containers mount them as volumes | Medium: a local root user can always do this |
| Information disclosure | Local user reads state | Container user is 10001; file permissions are the host's responsibility | Low |

### B10/B11: browser and Prometheus

| STRIDE | Threat | Mitigation in code | Residual risk |
| --- | --- | --- | --- |
| Information disclosure | Token stolen by script on the page | React escapes output; no `dangerouslySetInnerHTML` found; token in `localStorage` is readable by any script on the origin | Medium: a dependency with XSS would expose tokens |
| Spoofing | Session fixation or token reuse | Tokens expire (default in `ApiSettings.token_ttl_seconds`); no server-side revocation | Medium: a stolen token works until expiry |
| Information disclosure | `/metrics` read by anyone | Requires a viewer token or the service key | Low |

### Host (A9): the agent itself (T3 and T6)

| STRIDE | Threat | Mitigation in code | Residual risk |
| --- | --- | --- | --- |
| Elevation of privilege | Agent runs with host PID and journal access, so a compromised agent can read more of the host | Non-root user; no privileged mode; capabilities dropped in Kubernetes; read-only root filesystem | High: host PID visibility is the main reason. Accepted for the monitoring purpose and documented |
| Repudiation / tampering | Compromised agent hides or fakes activity | Detection runs on the server, so the agent cannot set conclusions; a silent agent is not detected | High: needs a heartbeat check, which is not implemented |

### Supply chain (T7)

| STRIDE | Threat | Mitigation in code | Residual risk |
| --- | --- | --- | --- |
| Tampering | Vulnerable dependency or base image | pip-audit and npm audit in CI; Trivy image scan with fail on fixable HIGH and CRITICAL; Dependabot weekly; OS upgrades in runtime stages | Medium: unfixed upstream issues are ignored by the scan (`--ignore-unfixed`) |

## Explicitly out of scope

- Attacks against the monitored host's kernel or sshd.
- Hosting-provider controls.
- Physical access.
- Offensive use of the system. The system does not contain attack tooling; the lab uses synthetic log lines only.
