# Troubleshooting

Each entry gives the symptom, the cause that was observed, and the check or fix. Causes come from problems that actually happened during development.

## Offline lab

**`ModuleNotFoundError` when running `run_scenario.py` or `benchmark.py`.**
The lab venv does not have the packages. Install them from the repository root:

```powershell
.lab\venv\Scripts\python.exe -m pip install -e .\agent -e .\detection
```

**The lab reports events from the journal instead of the synthetic file, or reports zero events on Linux.**
On a host where `journalctl` exists, the agent reads the systemd journal and ignores `SENTINEL_AUTH_LOG_PATHS`. Run the lab on Windows, or on a host without `journalctl`. A switch to force the file source is planned (`docs/future-work.md`).

**The benchmark stops making progress.**
An earlier version of the benchmark sent output to pipes that were not drained. A child process blocks when its output fills the pipe buffer. The current version writes output to files. If the problem returns, look at `.lab/benchmark/<run>/*.log`.

**The benchmark reports fewer events than lines.**
The file source reads at most 1 MiB per collection cycle. The benchmark runs cycles until the file is consumed. If the count is still short, check the `agent` entry's `cycles` value and the agent log for that run.

**The benchmark's memory looks like about 4 MB.**
That is the launcher, not the Python process. The benchmark sums the process tree. On Windows, the venv `python.exe` starts a second interpreter.

**A lab run sent events to a real API.**
The lab removes `SENTINEL_*` variables from its environment, so this should not happen. If it does, check whether the script was modified. The agent writes to a file unless `SENTINEL_API_URL` is set.

## Unit tests

**One detection test is skipped.**
`test_redis_state.py` needs a Redis server and the variable `SENTINEL_TEST_REDIS_URL`. It runs in CI.

**Backend PostgreSQL tests are skipped.**
They need `SENTINEL_TEST_DATABASE_URL`. They run in CI with a PostgreSQL service.

**`401` or `403` in an API test that used to pass.**
Since the authorization fix, the service key (`X-API-Key`) can read and ingest but cannot change incident status. Use a user token with the analyst role for status changes. See `docs/security-analysis.md`, F1.

## Compose stack

**The API container does not start, and the log says port 8000 is in use.**
A native process holds the port. Find it with `ss -ltnp | grep 8000` on Linux and stop it. In development this was a leftover native `sentinelbot-api` process.

**The dashboard shows "Internal Server Error", and the log shows it cannot resolve `sentinel-api`.**
The API container is not running, so the frontend cannot reach it. Check `docker compose ps` and `docker compose logs sentinel-api`.

**Open incidents are zero, and no SSH events arrive.**
The agent cannot read the journal. Check that `SENTINEL_JOURNAL_GID` matches the group that owns the journal on the host (`getent group systemd-journal`), and that the agent's state volume is writable.

**The agent logs `Permission denied: '/app/.local'`.**
The state file path points into the image's home directory, which the non-root user cannot write. Set `SENTINEL_STATE_PATH` to the writable volume (`/var/lib/sentinelbot/...`), as the Compose file does.

**Prometheus exits with "permission denied" on the secret file.**
The file is not readable by uid 65534. Run `sudo chown 65534:65534 secrets/sentinel_api_key` and then `sudo chmod 400 secrets/sentinel_api_key`.

**Duplicate "unexpected port" or "privileged process" incidents keep appearing.**
There is no port allowlist and no persisted baseline. Set `SENTINEL_ALLOWED_PORTS` to the expected ports and make sure `SENTINEL_BASELINE_PATH` is on a volume.

**Alembic reports `ImportError: UserRow`.**
The installed `sentinelbot-database` package is older than the code. Reinstall the package from the repository.

## Kubernetes

**Pods show `ImagePullBackOff`.**
The node cannot reach the registry. In the development cluster, the images were imported directly into each node with `docker save` and `k3s ctr images import`.

**The k3s agent node stays in `activating`.**
The control-plane server restarted. Wait, then check `sudo systemctl status k3s-agent`.

**`kubectl apply -k k8s/` fails because `secret.yaml` is missing.**
Create it from the template. It is ignored by git on purpose:

```bash
cp k8s/secret.example.yaml k8s/secret.yaml
```

Then replace every `CHANGE_ME` value.

**The baseline causes false alerts on one node.**
The baseline is shared by all nodes in the deployment. This is a known limitation (`docs/limitations.md`, item 28).

## CI

**The Trivy step fails with an empty image reference.**
The shell continuation lines had Windows (CRLF) line endings. `.gitattributes` now forces LF.

**The Trivy step reports a HIGH vulnerability in a base image package.**
Check whether a fix exists (the scan ignores unfixed issues). Upgrade base packages in the runtime stage of the Dockerfile. For npm's bundled packages in the frontend, remove npm from the runtime image, as was done.

**The `dependency-audit` job fails on npm.**
`npm audit --omit=dev --audit-level=high` reports high-severity issues in production dependencies. Update the dependency, or record the exception with a reason.

**A Dependabot pull request conflicts.**
Comment `@dependabot rebase` on the pull request, or close it if it is no longer needed.

## Documentation

**A Mermaid diagram does not render on GitHub.**
GitHub renders Mermaid in Markdown files. Check the block starts with a valid diagram type (`flowchart`, `sequenceDiagram`). Diagram syntax was not checked with the Mermaid CLI in this review.
