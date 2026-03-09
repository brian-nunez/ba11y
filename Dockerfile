FROM golang:1.25-bookworm AS builder

WORKDIR /src

ARG PLAYWRIGHT_GO_MODULE_VERSION=v0.5700.1

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
  --mount=type=cache,target=/root/.cache/go-build \
  go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN --mount=type=cache,target=/go/pkg/mod \
  --mount=type=cache,target=/root/.cache/go-build \
  CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go build -trimpath -ldflags='-s -w' -o /out/ba11y ./cmd/main.go

# Download only the pinned Playwright driver bundle (no browser binaries).
RUN --mount=type=cache,target=/go/pkg/mod \
  --mount=type=cache,target=/root/.cache/go-build \
  go run github.com/playwright-community/playwright-go/cmd/playwright@${PLAYWRIGHT_GO_MODULE_VERSION} --version

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  tzdata \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --gid 10001 app \
  && useradd --uid 10001 --gid app --shell /usr/sbin/nologin --create-home app

WORKDIR /app

COPY --from=builder /out/ba11y /usr/local/bin/ba11y
COPY --from=builder /src/assets ./assets
COPY --from=builder /root/.cache/ms-playwright-go /home/app/.cache/ms-playwright-go

RUN mkdir -p /data/logs /home/app/.cache && chown -R app:app /app /data /home/app

ENV HOME=/home/app \
  PORT=8090 \
  APP_DATABASE_PATH=/data/ba11y.db \
  SCAN_WORKER_DB_PATH=/data/ba11y.db \
  SCAN_WORKER_LOG_PATH=/data/logs \
  SCAN_WORKER_CONCURRENCY=3 \
  BBAAS_BASE_URL=http://127.0.0.1:8080 \
  BBAAS_API_TOKEN= \
  BBAAS_API_KEY= \
  PLAYWRIGHT_DRIVER_PATH=/home/app/.cache/ms-playwright-go/1.57.0 \
  PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

VOLUME ["/data"]

EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${PORT}/api/v1/health" || exit 1

USER app

ENTRYPOINT ["/usr/local/bin/ba11y"]
