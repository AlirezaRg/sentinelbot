# Contributing to SentinelBot

Thanks for your interest. Bug reports, fixes, new detection rules and documentation improvements are all welcome.

## Before you start

- Read [docs/architecture.md](docs/architecture.md) for how the packages fit together.
- For a larger change, open an issue first so we can agree on the approach.
- For a security problem, do not open a public issue. See [SECURITY.md](SECURITY.md).

## Development setup

See [docs/development.md](docs/development.md). In short: install the Python packages in editable mode, and run `npm ci` in `frontend/`.

## Checks

A pull request must pass CI. Run these locally first:

```bash
ruff format --check src tests
ruff check src tests
mypy
pytest -q
```

Run them inside each package you changed. For the frontend:

```bash
npx tsc --noEmit
npm run build
```

## Guidelines

- Match the style of the surrounding code: naming, comments and structure.
- Add tests for behavior changes. Detection rules need tests in `detection/tests/`.
- If you change a database model, add an Alembic migration. CI checks that the migrations match the models.
- Keep secrets out of the repository. Use `SENTINEL_*` environment variables and the `.env.example` template.
- Keep line endings LF. Windows `.bat` and `.ps1` files are the exception.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Make a focused change with a clear commit message.
3. Open a pull request that describes what changed and why, and how you tested it.
4. Wait for CI. Address review comments.

By contributing, you agree that your contributions are licensed under the MIT license in [LICENSE](LICENSE).
