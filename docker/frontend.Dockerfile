# SentinelBot dashboard. Build from the repository root:
#   docker build -f docker/frontend.Dockerfile -t sentinelbot-frontend .
# SENTINEL_API_URL is read at build time (it sets where /backend/... is forwarded).

FROM node:22-alpine AS deps
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM deps AS build
ARG SENTINEL_API_URL=http://sentinel-api:8000
ENV SENTINEL_API_URL=${SENTINEL_API_URL} \
    NEXT_TELEMETRY_DISABLED=1
COPY frontend ./
RUN npm run build

FROM node:22-alpine
RUN apk upgrade --no-cache \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack
RUN addgroup -S -g 10001 sentinel && adduser -S -u 10001 -G sentinel sentinel
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public
USER sentinel
EXPOSE 3000
HEALTHCHECK --interval=20s --timeout=3s --start-period=15s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:3000/login || exit 1
CMD ["node", "server.js"]
