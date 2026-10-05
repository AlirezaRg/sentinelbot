# SentinelBot Architecture

## Pipeline

```
Linux Host
  └─► SentinelBot Agent ──► Event Collector ──► Detection Engine ──► Risk Scoring
                                                                        │
                       AI Security Analyst ◄── Alerting ◄── Correlation ◄┘
                                │                 │             │
                                ▼                 ▼             ▼
                          Event/API Layer (FastAPI) ──► PostgreSQL / Redis
                                │
                       Prometheus ──► Grafana
                                │
                       Web Dashboard (Next.js)
```

## Components

| Component    | Responsibility                                          | Phase | Status      |
|--------------|---------------------------------------------------------|-------|-------------|
| `agent/`     | Collect host telemetry, emit normalized events          | 1     | Done        |
| `agent/`     | Log collection (journald, auth.log, secure) with state  | 2     | Planned     |
| `detection/` | Transparent rules that turn events into detections      | 3     | Planned     |
| `detection/` | Configurable risk scoring (0–100)                       | 4     | Planned     |
| `detection/` | Correlation into incidents with a status lifecycle      | 5     | Planned     |
| `backend/`   | FastAPI, validation, pagination, error handling         | 6     | Planned     |
| `database/`  | SQLAlchemy 2.x models and Alembic migrations            | 7     | Planned     |
| `backend/`   | Redis: aggregation windows, rate limits, temporary state| 8     | Planned     |
| `monitoring/`| Prometheus metrics                                      | 9     | Planned     |
| `monitoring/`| Grafana dashboards                                      | 10    | Planned     |
| `alerts/`    | Telegram, email, webhook; dedup and cooldown            | 11    | Planned     |
| `ai/`        | Analyst module with an abstract provider (no host access)| 12   | Planned     |
| `frontend/`  | Next.js dashboard with auth                             | 13    | Planned     |
| `docker/`    | Compose stack with health checks, non-root images       | 14    | Planned     |
| `k8s/`       | Manifests; agent as DaemonSet                           | 15    | Planned     |
| `tests/`     | pytest unit and integration suites                      | ongoing | Partial   |
| `.github/`   | Lint, types, tests, image build, dependency scan        | 16    | Planned     |

## Event flow (Phase 1)

1. `Agent.collect_once()` runs each enabled collector in order.
2. A collector returns `Event` objects (Pydantic, UTC timestamps, extra fields forbidden).
3. A raising collector yields a single `collector_error` event; other collectors still run.
4. Each event is written as one JSON line to stdout or a file. Logs go to stderr as JSON.

Later phases consume the same JSON Lines stream or the same `Event` model; the detection
engine does not need to know which collector produced an event.

## Technology decisions

| Area           | Choice                       | Reason                                                              |
|----------------|------------------------------|---------------------------------------------------------------------|
| Agent language | Python 3.12                  | Shared language with the backend; psutil and journald bindings exist |
| Host metrics   | psutil                       | Portable reads of `/proc`; also works on Windows for development    |
| Schemas        | Pydantic v2                  | Validation at every boundary; JSON round-trip for free              |
| Persistence    | PostgreSQL + SQLAlchemy 2 + Alembic | Relational incidents, indexes on time/type/host/IP/status      |
| Short-term     | Redis                        | Windows, rate limits, temp state; never the source of truth         |
| Metrics        | Prometheus + Grafana         | Standard exporter and dashboards; low-cardinality labels            |
| API            | FastAPI                      | Typed, dependency injection, OpenAPI for free                       |
| Frontend       | Next.js, TypeScript, Tailwind, shadcn/ui, TanStack Query | Modern, typed, near-real-time polling     |
| Packaging      | setuptools, src layout       | Standard, no build tool lock-in                                     |
| Quality        | ruff, mypy (strict), pytest  | Fast lint, strict types, markers separate unit from integration     |

## Repository structure

```
sentinelbot/
├── agent/          Phase 1: Python telemetry agent (this phase)
│   ├── src/sentinelbot_agent/
│   │   ├── collectors/   system, processes, network (+ base, registry)
│   │   ├── models.py     Event and enums
│   │   ├── config.py     SENTINEL_* environment settings
│   │   ├── agent.py      orchestration and failure isolation
│   │   ├── output.py     JSON Lines sink
│   │   ├── logging_setup.py
│   │   └── cli.py
│   └── tests/
├── docs/           architecture, roadmap (this file)
├── backend/ detection/ ai/ alerts/ database/ monitoring/ docker/ k8s/ frontend/ scripts/
└── .github/workflows/
```

Adjustment from the original layout: `models.py`, `config.py` and the collector registry
live inside `agent/` for now. They move to a shared package when the detection engine and
backend need the same `Event` model (Phase 3). Empty directories are created in the phase
that fills them, so the tree never lies about what exists.

## Security boundaries

- The agent is read-only. It runs no commands from the API and never writes to the host.
- No code path reads secrets, credentials, or private keys.
- Collectors degrade on permission errors instead of failing the agent.
- Events carry only what detection needs; process arguments are not collected in Phase 1.

## Roadmap

1. **Agent (done)** — system, process, network telemetry as JSON Lines.
2. **Log collection** — journald / auth.log / secure, cursor state, rotation, restart recovery.
3. **Detection rules** — SSH brute force, root login, auth bursts, privileged processes,
   unexpected ports, Docker misconfiguration, process anomalies. All thresholds configurable.
4. **Risk scoring** — additive, configurable weights, clamped 0–100, severity bands.
5. **Correlation** — incidents from related events, lifecycle OPEN → INVESTIGATING → RESOLVED / FALSE_POSITIVE.
6. **API** — FastAPI endpoints from the spec, pagination, filtering, sorting.
7. **PostgreSQL** — models, migrations, indexes.
8. **Redis** — sliding windows and rate limits.
9. **Prometheus metrics** — counters and gauges with controlled labels.
10. **Grafana** — provisioned dashboard.
11. **Alerting** — channels, dedup, cooldown.
12. **AI analyst** — structured input, schema-validated output, confidence stated.
13. **Frontend** — dashboard pages and auth.
14. **Docker Compose** — full stack with health checks.
15. **Kubernetes** — manifests; agent as DaemonSet.
16. **CI/CD** — ruff, mypy, pytest, Docker build, Trivy.
17. **Documentation** — README and the docs listed in the spec.

Each phase ends with a runnable, tested milestone. Work does not start on phase N+1 until
phase N is confirmed.
