# Technology decisions

For each technology: the alternative that was considered, the decision, and the reason. Keep answers short. Where a choice was a convenience rather than a requirement, the document says so.

## Python

- **Alternatives:** Go, Rust, Node.js.
- **Decision:** Python 3.12 for the agent, detection, API and AI module.
- **Reason:** the detection logic is the academic core and must be easy to read and test. Python is readable, has strong libraries for Linux telemetry (psutil) and web APIs (FastAPI), and the team (one student) can explain it line by line. The main cost is performance; that is measured in `docs/evaluation.md`, not assumed.

## FastAPI

- **Alternatives:** Flask, Django.
- **Decision:** FastAPI with pydantic models.
- **Reason:** request and response bodies are validated by the same models the agent uses (`Event`). Flask would need a separate validation layer. Django brings an admin, ORM and templates the project does not use.

## PostgreSQL

- **Alternatives:** SQLite, MySQL, a document database.
- **Decision:** PostgreSQL 16.
- **Reason:** concurrent writes from several API workers, JSON columns for event metadata, and mature migration tooling. SQLite would work for one host in the lab, but not for several workers writing at once.

## SQLAlchemy and Alembic

- **Alternatives:** raw SQL, an ORM with its own migrations.
- **Decision:** SQLAlchemy 2 models, Alembic migrations, and a test that checks migrations match the models.
- **Reason:** schema changes are versioned, and the drift test catches a model changed without a migration.

## Redis

- **Alternatives:** keep state in the API process, or in PostgreSQL.
- **Decision:** optional. Used for sliding windows, cooldowns and rate limits when `SENTINEL_REDIS_URL` is set.
- **Reason:** several API workers must see the same windows. Redis sorted sets fit a sliding window directly. Without Redis, the in-memory backend works for one worker.

## Prometheus

- **Alternatives:** push metrics to a time series database directly, or log-based metrics.
- **Decision:** the API exposes `/metrics`, and Prometheus scrapes it.
- **Reason:** the standard pull model needs no extra code in the pipeline, and `prometheus_client` makes the metrics easy to explain.

## Grafana

- **Alternatives:** build charts into the dashboard.
- **Decision:** Grafana with a provisioned dashboard file.
- **Reason:** operators expect time series charts from Grafana. Building them into the Next.js dashboard would duplicate Grafana's work. The dashboard shows incidents, which Grafana does not.

## Docker and Docker Compose

- **Alternatives:** install directly on the host, use systemd units.
- **Decision:** one image per component, and Compose for a single-host stack.
- **Reason:** reproducible setup, and a clear boundary between the agent and the server. The agent's container needs host PID and journal access, which is explicit in the Compose file.

## Kubernetes

- **Alternatives:** Docker Compose only, Nomad, a managed service.
- **Decision:** kustomize manifests, tested on k3s with two nodes.
- **Reason:** the agent is a per-node component, which maps directly to a DaemonSet. This shows the design works across hosts. It is not needed for a single host.

## Next.js

- **Alternatives:** a plain React single-page app, server-rendered templates, a Python-only UI.
- **Decision:** Next.js with the App Router and a rewrite to the API.
- **Reason:** the rewrite keeps one origin for the browser, so the API does not need CORS. The team (one student) already knows React. The framework is a convenience; the dashboard is thin.

## Email for alerts

- **Alternatives:** Slack, Telegram, webhooks, SMS.
- **Decision:** SMTP with STARTTLS.
- **Reason:** every environment can send email, and no chat bot token is needed. The alert channel is a small interface, so another channel can be added.

## Artificial intelligence (analyst)

- **Alternatives:** no AI, a local model, a hosted API.
- **Decision:** a rule-based analysis that always works, and an optional hosted model that is validated and capped.
- **Reason:** the analyst needs readable explanations, but detection must not depend on a model. The rule-based version keeps the system working offline, and the optional provider shows the boundary between evidence and interpretation.

## Python tooling

- **Choices:** ruff (format and lint), mypy in strict mode, pytest, pydantic v2.
- **Reason:** one tool for each job, all run in CI. mypy strict mode is the reason the type annotations are complete.

## GitHub Actions

- **Alternatives:** GitLab CI, Jenkins.
- **Decision:** GitHub Actions, because the repository is on GitHub.
- **Reason:** no separate CI server. The workflow file is part of the repository.
