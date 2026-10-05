# SentinelBot API. Build from the repository root:
#   docker build -f docker/api.Dockerfile -t sentinelbot-api .
# The image runs database migrations, then serves the API as a non-root user.

FROM python:3.12-slim AS build
WORKDIR /src
COPY agent /src/agent
COPY detection /src/detection
COPY database /src/database
COPY alerts /src/alerts
COPY ai /src/ai
COPY backend /src/backend
RUN pip install --no-cache-dir --prefix=/install \
      /src/agent /src/detection /src/database /src/alerts /src/ai /src/backend

FROM python:3.12-slim
# Pick up security fixes for the base system packages.
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/*
RUN groupadd --system --gid 10001 sentinel \
 && useradd --system --uid 10001 --gid sentinel --home-dir /app --shell /usr/sbin/nologin sentinel
COPY --from=build /install /usr/local
WORKDIR /app
COPY database/alembic.ini /app/alembic.ini
COPY database/migrations /app/migrations
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
# Writable state directory: the learned baseline is kept here (named volume in docker-compose.yml).
RUN mkdir -p /var/lib/sentinelbot && chown sentinel:sentinel /var/lib/sentinelbot
USER sentinel
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"
CMD ["sh", "-c", "alembic -c alembic.ini upgrade head && exec sentinelbot-api --host 0.0.0.0 --port 8000"]
