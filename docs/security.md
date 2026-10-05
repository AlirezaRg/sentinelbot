# Security

## Reporting a vulnerability

Please do not open a public issue for security problems. Contact the maintainer privately through GitHub (use the "Report a vulnerability" option on the repository's Security tab once it is enabled).

## Authentication and authorization

- **Users** log in with a username and password. Passwords are hashed with scrypt.
- **Tokens** are HMAC-SHA256 signed (`payload.signature`) and expire after `SENTINEL_TOKEN_TTL_SECONDS`. The signing key is `SENTINEL_AUTH_SECRET`, which must be at least 32 characters.
- **Roles**: `viewer` can read, `analyst` can change incident status and run analysis, and `admin` has everything else. The service API key (`X-API-Key`) is used by agents and is treated as admin.
- **Login is rate limited** to 10 attempts per minute.

## Secrets

- Keep secrets in `.env` (Compose) or Kubernetes Secrets. Neither is committed. `.gitignore` excludes `.env`, `secrets/`, and `k8s/secret.yaml`.
- Secret settings are excluded from `repr()` so they do not appear in logs or tracebacks.
- Rotate any secret that was ever pasted into a chat, ticket, or log. This includes database passwords, SMTP app passwords, API keys, and the Kubernetes join token.

## Containers

- All images run as non-root user 10001.
- The Kubernetes API pod uses a read-only root filesystem.
- The agent needs `hostPID` and read access to the journal. Those are the only host privileges it uses. The agent does not run privileged.
- Images are scanned with Trivy in CI. CI fails on fixable CRITICAL or HIGH findings. Runtime stages apply OS security upgrades. The frontend runtime image has npm removed because the dashboard does not need it.
- Dependencies are audited in CI with pip-audit and `npm audit --omit=dev`. Dependabot opens weekly update PRs.

## Network exposure

- Compose binds the API, Prometheus and Grafana to 127.0.0.1 by default.
- The Kubernetes NodePorts (30300, 30301) and Grafana/dashboard do not have TLS. Do not expose them to untrusted networks without a TLS-terminating proxy.
- `/metrics` requires a viewer token or the API key.

## Known limitations

- The learned baseline is shared between nodes in the same deployment. This can cause false `privileged_process` findings. Per-host baselines are planned.
- The Containers page is a placeholder. Docker telemetry is not collected yet.
- Frontend unit tests are not implemented. The frontend is covered by type checking and the production build only.
- Kubernetes manifests are validated with kustomize, not against a live API server with dry-run.
- Detection output depends on the host's logging. If sshd logs are missing or rotated without the agent's cursor, events can be missed.
