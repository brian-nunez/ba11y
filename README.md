# ba11y

`ba11y` is a server-rendered accessibility scanning application built with Go, Echo, Templ, and Tailwind.

It supports scans for:
- Web pages
- Emails
- PDF documents
- Multi-step user journeys

## Core Stack

- [Go](https://go.dev/)
- [Echo](https://echo.labstack.com/)
- [Templ](https://templ.guide/)
- [TailwindCSS](https://tailwindcss.com/)

## Required Integrations

This app is intentionally wired to your libraries:

- `bbaas-api` SDK for browser provisioning and lifecycle operations
  - Import: `github.com/brian-nunez/bbaas-api/sdk/go/bbaas`
- `task-orchestration` for async scan orchestration and worker state
  - Import: `github.com/brian-nunez/task-orchestration`
- `baccess` for RBAC/ABAC authorization checks
  - Import: `github.com/brian-nunez/baccess`

## Auth Flow

The auth/session flow follows the `bbaas-api` web flow pattern:

- `GET /register`, `POST /register`
- `GET /login`, `POST /login`
- `POST /logout`
- Session middleware reads cookie `bbaas_session`
- `RequireAuth` / `RequireGuest` route guards

## Scan Flow

1. User submits a scan from `/scans/new`
2. A scan task is queued via `task-orchestration`
3. Worker task uses `bbaas` SDK to:
   - Spawn a browser (`SpawnBrowser`)
   - Keep session alive (`KeepAliveBrowser`)
   - Close browser (`CloseBrowser`)
4. Progress is polled from `/api/v1/scans/:scanId/status`
5. Completed scans render detailed reports at `/scans/:scanId/report`

## Environment Variables

- `PORT` (default: `8090`)
- `BBAAS_BASE_URL` (default: `http://127.0.0.1:8080`)
- `BBAAS_API_TOKEN` (required to run scans successfully)
- `SCAN_WORKER_CONCURRENCY` (default: `3`)
- `SCAN_WORKER_LOG_PATH` (default: `./data/logs`)
- `SCAN_WORKER_DB_PATH` (default: `./data/tasks.db`)

## Local Development

### Prereqs

- Go 1.25+
- `templ`
- `tailwindcss`
- `air` (optional, for hot reload)

### Install dependencies

```bash
go mod tidy
```

### Run

```bash
make dev
```

### Build/test

```bash
make deps
go test ./...
```

## Key Routes

UI routes:
- `/`
- `/register`
- `/login`
- `/scans`
- `/scans/new`
- `/scans/:scanId/progress`
- `/scans/:scanId/report`

API routes:
- `/api/v1/health`
- `/api/v1/scans/:scanId/status`

