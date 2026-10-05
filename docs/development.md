# Development

## Requirements

- Python 3.12
- Node.js 22 and npm
- Docker with Compose (for integration tests and the full stack)
- PostgreSQL 16 and Redis 7 (optional locally; integration tests need them)

## Python packages

The Python code is split into packages that depend on each other in this order: `agent`, `detection`, `database`, `alerts`, `ai`, `backend`. Install them in editable mode:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ./agent -e ./detection -e ./database -e ./alerts -e ./ai -e ./backend
pip install -e "./backend[dev]" -e "./detection[dev]" -e "./database[dev]"
```

## Checks

CI runs these for every Python package. Run them locally before pushing:

```bash
cd backend            # or any package
ruff format --check src tests
ruff check src tests
mypy
pytest -q
```

Integration tests need PostgreSQL and Redis:

```bash
export SENTINEL_TEST_DATABASE_URL=postgresql+psycopg://sentinel:<password>@127.0.0.1:5432/sentinel_test
export SENTINEL_TEST_REDIS_URL=redis://127.0.0.1:6379/15
cd database && alembic -c alembic.ini upgrade head && pytest -q
```

Without these variables the PostgreSQL and Redis tests are skipped.

## Database migrations

Migrations are in `database/migrations/versions/`. A test checks that the migrations match the SQLAlchemy models, so after changing a model, create a new migration:

```bash
cd database
SENTINEL_DATABASE_URL=... alembic -c alembic.ini revision --autogenerate -m "describe the change"
```

Review the generated file. Non-null JSON columns must match the model defaults.

## Frontend

```bash
cd frontend
npm ci
npx tsc --noEmit
npm run dev            # http://localhost:3000
```

The dev server forwards `/backend/*` to `SENTINEL_API_URL` (see `next.config.ts`).

## Running the agent on your machine

```bash
sentinelbot-agent --log-level INFO
```

Without `SENTINEL_API_URL` it writes JSON Lines to stdout. Set `SENTINEL_API_URL` and `SENTINEL_API_KEY` to send events to a running API.

## Conventions

- Keep configuration in `SENTINEL_*` environment variables. Each package's `config.py` or `settings.py` reads them.
- Secrets are wrapped in `repr=False` so they do not appear in logs.
- Line endings are LF (`.gitattributes`). Windows scripts are the only exception.
