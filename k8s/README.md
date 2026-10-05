# Kubernetes deployment

These manifests run the same stack as `docker-compose.yml`. They assume a cluster where you
can load or pull the images (`sentinelbot-api:local`, `sentinelbot-agent:local`,
`sentinelbot-frontend:local`). For a real cluster, push the images to a registry you control
and change the `image:` fields.

## Layout

| Path | Contents |
|---|---|
| `namespace.yaml`, `configmap.yaml` | namespace and non-secret settings |
| `secret.example.yaml` | template for secrets (copy to `secret.yaml`, never commit it) |
| `postgres/`, `redis/` | stateful dependencies with persistent volumes |
| `api/` | API with a migration init container; ClusterIP only |
| `frontend/` | dashboard (NodePort 30301) |
| `prometheus/`, `grafana/` | monitoring, reading config from ConfigMaps |
| `agent/daemonset.yaml` | agent on every node, with read-only access to the host journal |

## Deploy

```bash
# 1. secrets (fill in every CHANGE_ME)
cp k8s/secret.example.yaml k8s/secret.yaml
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secret.yaml

# 2. Grafana dashboards from the monitoring folder
kubectl -n sentinelbot create configmap grafana-dashboards \
  --from-file=monitoring/grafana/dashboards/sentinelbot.json

# 3. everything else
kubectl apply -k k8s/
kubectl -n sentinelbot get pods -w
```

Before step 3, set the agent's journal group id in `agent/daemonset.yaml`
(`supplementalGroups`). On the node, run `getent group systemd-journal | cut -d: -f3`.

## Check

```bash
kubectl -n sentinelbot port-forward svc/sentinel-api 8000:8000   # then curl http://127.0.0.1:8000/health
kubectl -n sentinelbot get daemonset sentinel-agent
```

## Create the first dashboard user

```bash
kubectl -n sentinelbot exec -it deploy/sentinel-api -- sentinelbot-api create-user --username admin --role admin
```

## Limits of this version

- The API runs as one replica. Its correlation state, rate limits and detection baseline are per
  process; the baseline is persisted to a volume, the rest is in memory or in Redis.
- No Ingress or TLS. Put an Ingress with a certificate in front of the dashboard before exposing it.
- Images are not pushed to a registry by these files.
- The agent DaemonSet needs host access (host PID, journal). Restrict it to nodes you trust.
