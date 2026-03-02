FROM golang:1.25-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
  --mount=type=cache,target=/root/.cache/go-build \
  go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
  --mount=type=cache,target=/root/.cache/go-build \
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags='-s -w' -o /out/ba11y ./cmd/main.go

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --gid 10001 app \
  && useradd --uid 10001 --gid app --shell /usr/sbin/nologin --create-home app

WORKDIR /app

COPY --from=builder /out/ba11y /usr/local/bin/ba11y
COPY --from=builder /src/assets ./assets

RUN mkdir -p /data && chown -R app:app /app /data

ENV PORT=8080
ENV DB_DRIVER=sqlite
ENV DB_DSN=file:/data/ba11y.db?_pragma=foreign_keys(1)

EXPOSE 8080

USER app

ENTRYPOINT ["/usr/local/bin/ba11y"]
