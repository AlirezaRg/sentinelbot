# SentinelBot

SentinelBot is a host security monitoring platform for Linux servers. A lightweight agent on each host collects authentication, process, system and network telemetry. A central API stores the events, runs detection rules, scores the risk of each finding, groups related findings into incidents, and shows everything in a web dashboard. Email alerts, Prometheus metrics and Grafana dashboards are included.

## Features

- **Agent** (`agent/`): reads the systemd journal or auth log files, samples processes, listening sockets and system health, and ships events in batches over HTTP.
- **Detection** (`detection/`): transparent rules with explicit thresholds: SSH brute force, root login, authentication bursts, unexpected privileged processes, and unexpected listening ports.
- **Risk scoring**: each detection gets a 0-100 score and a severity band. A rule's own severity is a floor the score can raise but never lower.
- **Correlation**: findings from the same host and source IP are grouped into incidents. Incidents have a lifecycle: open, investigating, resolved, or false positive.
- **Analyst**: a rule-based analysis is always available offline. An optional LLM provider (Anthropic) can draft a more detailed explanation. Its output is validated against a strict schema, and confidence is capped at 0.5 when fewer than three detections support it.
- **API** (`backend/`): FastAPI with role-based access (viewer, analyst, admin), token login with rate limiting, and a service API key for agents.
- **Alerts** (`alerts/`): email over STARTTLS with a minimum severity, a per-incident cooldown, and an escalation path that bypasses the cooldown.
- **Dashboard** (`frontend/`): Next.js with pages for dashboard, incidents, events, hosts, network, and settings.
- **Monitoring**: Prometheus metrics at `/metrics` and a provisioned Grafana dashboard.
- **Deployment**: Docker Compose for a single host, and Kubernetes manifests (kustomize) for a cluster with a DaemonSet agent.

## Repository layout

| Path | Contents |
| --- | --- |
| `agent/` | Host agent and collectors |
| `detection/` | Rules, risk scoring, correlation, and the Redis state backend |
| `database/` | SQLAlchemy models and Alembic migrations |
| `alerts/` | Alert channels, policy, notifier |
| `ai/` | Analyst, rule-based analysis, LLM providers |
| `backend/` | FastAPI application |
| `frontend/` | Next.js dashboard |
| `docker/` | Dockerfiles for the API, agent and frontend |
| `k8s/` | Kubernetes manifests |
| `monitoring/` | Prometheus and Grafana configuration |
| `docs/` | Architecture, detection rules, development, deployment, security |

## Quick start

Docker Compose on a single Linux host:

```bash
cp .env.example .env        # then fill in the secrets
docker compose up -d --build
```

The dashboard is at http://127.0.0.1:3001 and the API at http://127.0.0.1:8000/health.

Create the first user:

```bash
docker compose exec sentinel-api sentinelbot-api create-user --username admin --role admin
```

See [docs/deployment.md](docs/deployment.md) for the full setup, including Kubernetes, and [docs/development.md](docs/development.md) for working on the code.

## Documentation

- [Architecture](docs/architecture.md)
- [Detection rules](docs/detection-rules.md)
- [Development](docs/development.md)
- [Deployment](docs/deployment.md)
- [Security](docs/security.md)

## License

MIT. See [LICENSE](LICENSE).
