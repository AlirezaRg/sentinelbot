# SentinelBot agent. Build from the repository root:
#   docker build -f docker/agent.Dockerfile -t sentinelbot-agent .
# Runs as a non-root user. For host-level telemetry, the compose file starts it with the host
# PID namespace, so process and socket data describe the host rather than the container.

FROM python:3.12-slim AS build
WORKDIR /src
COPY agent /src/agent
RUN pip install --no-cache-dir --prefix=/install /src/agent

FROM python:3.12-slim
# journalctl reads the host's authentication journal (read-only mount, see docker-compose.yml).
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends systemd \
 && rm -rf /var/lib/apt/lists/*
RUN groupadd --system --gid 10001 sentinel \
 && useradd --system --uid 10001 --gid sentinel --home-dir /app --shell /usr/sbin/nologin sentinel
COPY --from=build /install /usr/local
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
# Writable state directory (the log-read cursor survives restarts through a named volume).
RUN mkdir -p /var/lib/sentinelbot && chown sentinel:sentinel /var/lib/sentinelbot
USER sentinel
CMD ["sentinelbot-agent", "--log-level", "INFO"]
