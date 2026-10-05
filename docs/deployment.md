# Deployment

## Docker Compose (single host)

Compose runs PostgreSQL, Redis, the API, the agent, the dashboard, Prometheus and Grafana.

1. Copy the example environment file and fill in the secrets:

   ```bash
   cp .env.example .env
   ```

   Generate random values for `POSTGRES_PASSWORD`, `SENTINEL_API_KEY`, `SENTINEL_AUTH_SECRET` (at least 32 characters) and `GRAFANA_ADMIN_PASSWORD`.

2. Find the group ID that owns the journal on the host. The agent needs it to read the journal:

   ```bash
   getent group systemd-journal | cut -d: -f3
   ```

   Put it in `SENTINEL_JOURNAL_GID` in `.env`.

3. Create the Prometheus secret file, readable by the Prometheus user (uid 65534):

   ```bash
   mkdir -p secrets
   printf '%s' "<the same value as SENTINEL_API_KEY>" > secrets/sentinel_api_key
   sudo chown 65534:65534 secrets/sentinel_api_key
   sudo chmod 400 secrets/sentinel_api_key
   ```

4. Start the stack:

   ```bash
   docker compose up -d --build
   docker compose ps
   ```

5. Create a user:

   ```bash
   docker compose exec sentinel-api sentinelbot-api create-user --username <name> --role admin
   ```

Ports are bound to 127.0.0.1 by default: API 8000, Prometheus 9090, and Grafana 3000. The dashboard is on 3001. Put a reverse proxy with TLS in front of anything reachable from outside the host.

### Email alerts

Set `SENTINEL_SMTP_*` in `.env`. For Gmail, use an App Password, not the account password. The alert channel sends only incidents at or above `SENTINEL_ALERT_MIN_SEVERITY`.

### AI analyst (optional)

The analyst works offline by default. To enable Anthropic, set `SENTINEL_AI_PROVIDER=anthropic`, `SENTINEL_AI_API_KEY` and `SENTINEL_AI_MODEL`.

## Kubernetes

The manifests in `k8s/` are a kustomize base. They were tested on a two-node k3s cluster (one control-plane node, one worker).

1. Create the secret from the template. Do not commit the result:

   ```bash
   cp k8s/secret.example.yaml k8s/secret.yaml
   # edit k8s/secret.yaml with real values
   ```

2. Apply:

   ```bash
   kubectl apply -k k8s/
   kubectl -n sentinelbot get pods
   ```

The API image runs `alembic upgrade head` in an init container before it starts. The agent runs as a DaemonSet on every node with `hostPID` and read-only journal mounts. The dashboard is exposed on NodePort 30301 and Grafana on 30300. Neither has TLS. Add an ingress with TLS before exposing them outside the cluster. See `k8s/README.md`.

Images are not pushed to a registry by these manifests. Build them, push them to a registry your cluster can reach, and set the image names in `k8s/` accordingly.

## Upgrading

1. Pull the new code and rebuild the images.
2. Recreate the API container. Its init step runs the new migrations.
3. Check `/health` and the agent status on the dashboard.

## Backups

Back up the PostgreSQL volume (`pgdata`) and the API state volume (`apistate`, which holds the learned baseline). The agent state volume only holds the journal cursor, so losing it means re-reading recent journal entries once.
