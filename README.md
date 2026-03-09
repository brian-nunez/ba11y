# ba11y

`ba11y` is a server-rendered accessibility scanning application built with Go, Echo, Templ, and Tailwind.

It supports scans for:
- Web pages

Currently disabled:
- Emails
- PDF documents
- Multi-step user journeys

## Core Stack

- [Go](https://go.dev/)
- [Echo](https://echo.labstack.com/)
- [Templ](https://templ.guide/)
- [TailwindCSS](https://tailwindcss.com/)

## Required Integrations

This app is intentionally wired to my libraries:

- `bbaas-api` SDK for browser provisioning and lifecycle operations
  - Import: `github.com/brian-nunez/bbaas-api/sdk/go/bbaas`
- `task-orchestration` for async scan orchestration and worker state
  - Import: `github.com/brian-nunez/task-orchestration`
- `baccess` for RBAC/ABAC authorization checks
  - Import: `github.com/brian-nunez/baccess`
- `btick` Scheduler SDK for recurring cron registration
  - Import: `github.com/brian-nunez/go-echo-starter-template/sdk/go/scheduler`

## Auth Flow

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
4. Worker connects to the spawned browser over CDP using `playwright-go`
5. Worker injects and runs `axe-core` in-page and maps violations into findings
6. Progress is polled from `/api/v1/scans/:scanId/status`
7. Completed scans render detailed reports at `/scans/:scanId/report`

## Recurring Scan Flow

1. User creates a recurring scan from `/scans/new`
2. App validates UI-limited frequency (`hourly`, `daily`, `weekly`, `monthly`) and builds a cron expression
3. App registers a btick job that `POST`s to `/api/v1/recurring-scans/webhook`
4. btick triggers webhook on schedule with recurring scan metadata
5. Webhook handler verifies optional secret (`X-BA11Y-WEBHOOK-SECRET`) and queues a normal scan
6. User can enable/disable/stop recurring schedules from `/scans/new`

## Environment Variables

- `PORT` (default: `8090`)
- `APP_DATABASE_PATH` (default: `./data/ba11y.db`)
- `BBAAS_BASE_URL` (default: `http://127.0.0.1:8080`)
- `BBAAS_API_TOKEN` (preferred) or `BBAAS_API_KEY` (fallback; required to run scans)
- `BTICK_BASE_URL` (default: empty; required for recurring scans)
- `BTICK_API_KEY` (preferred) or `BTICK_API_TOKEN` (fallback; required for recurring scans)
- `BTICK_WEBHOOK_URL` (required for recurring scans; btick callback URL to this app)
- `BTICK_WEBHOOK_SECRET` (optional; validated against request header `X-BA11Y-WEBHOOK-SECRET`)
- `SCAN_WORKER_CONCURRENCY` (default: `3`)
- `SCAN_WORKER_LOG_PATH` (default: `./data/logs`)
- `SCAN_WORKER_DB_PATH` (default: same as `APP_DATABASE_PATH`)
- `PLAYWRIGHT_DRIVER_PATH` (optional, custom driver path)

All app state is persisted in SQLite:
- users and password hashes
- session tokens
- scan requests and scan progress metadata
- scan evidence metadata
- full scan findings/results
- recurring scan schedules and lifecycle metadata

## Local Development

### Prereqs

- Go 1.25+
- `templ`
- `tailwindcss`
- `air` (optional, for hot reload)

Notes:
- The app installs the Playwright driver automatically with `SkipInstallBrowsers=true`.
- Browser binaries are not installed locally; scans run in your spawned BaaS browser via CDP.

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
- `/api/v1/recurring-scans/webhook`
