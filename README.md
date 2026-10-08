# KangPaket-server

Cloud sync backend for the KangPaket desktop app. Go + MySQL.

Phase 1 (this state): config, `/healthz`, auto-migrations, Docker. Auth and sync come later.

## Run

```
cp .env.example .env   # fill DB_PASSWORD and JWT_SECRET
docker compose up -d --build
curl localhost:8095/healthz   # {"status":"ok"}
```

The compose project is `kangpaket-server`; the DB host must be reachable on the
`kangpaket-server_default` network (the homelab attaches `consolidated-mysql` to it).

Local without Docker: `go run ./cmd/server` with the env vars below exported.

## Environment

| Var | Default | Notes |
|---|---|---|
| `PORT` | `8080` | container listen port (host port: `HTTP_PORT`, default 8095) |
| `DB_HOST` / `DB_PORT` | `127.0.0.1` / `3306` | compose sets `consolidated-mysql` |
| `DB_NAME` / `DB_USER` | `kangpaket` | |
| `DB_PASSWORD` | required | |
| `JWT_SECRET` | required, >= 32 chars | server refuses to start otherwise |
| `REGISTRATION_ENABLED` | `false` | used from Phase 2 |

## Migrations

SQL files in `migrations/` are embedded in the binary and applied in filename
order at startup; applied versions are tracked in `schema_migrations`. Add new
changes as new files (`0002_*.sql`); never edit applied ones.

## Test

```
go vet ./... && go test ./...
```
