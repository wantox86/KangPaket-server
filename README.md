# KangPaket-server

Cloud sync backend for the KangPaket desktop app. Go + MySQL.

Phase 1: config, `/healthz`, auto-migrations, Docker. Phase 2: authentication (this state). Sync comes later.

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
| `REGISTRATION_ENABLED` | `false` | `true` opens `POST /auth/register` |
| `ACCESS_TOKEN_TTL` | `15m` | JWT lifetime |
| `REFRESH_TOKEN_TTL` | `720h` | refresh token lifetime (30 days) |
| `TRUST_PROXY_HEADERS` | `false` | trust `CF-Connecting-IP` for rate limiting; enable only behind Cloudflare Tunnel |
| `CORS_ALLOWED_ORIGINS` | empty | comma-separated; empty = CORS off |
| `RATE_LIMIT_PER_MIN` / `RATE_LIMIT_USER_PER_MIN` | `5` / `5` | attempts per minute per IP / per username (login) |

## Auth

JSON API, errors are `{"error":"<code>"}`.

| Endpoint | Body | Result |
|---|---|---|
| `POST /auth/login` | `{username,password}` | 200 `{access_token,refresh_token,expires_in,user}`; 401 on bad credentials or disabled user |
| `POST /auth/refresh` | `{refresh_token}` | new token pair; the old refresh token is revoked (rotation) |
| `POST /auth/logout` | `{refresh_token}` | 204, idempotent |
| `GET /auth/me` | header `Authorization: Bearer <access_token>` | `{id,username,is_admin}` |
| `POST /auth/register` | `{username,password}` | 403 `registration_disabled` unless `REGISTRATION_ENABLED=true`, then 201 |

- Passwords: argon2id (m=32MiB, t=3, p=2), minimum 10 characters. Usernames: 3-32 chars of `a-z 0-9 . _ -`, case-insensitive.
- Access token: JWT HS256, 15 min. Refresh token: random, stored only as a sha256 hash. Presenting an already-revoked refresh token revokes its whole token family.
- `/auth/login`, `/auth/refresh`, `/auth/register` are rate limited (429 + `Retry-After`).
- Handlers for Phase 3 wrap routes with `httpapi.RequireAuth` and read the user via `httpapi.UserID(ctx)`.

### Managing users (CLI)

Passwords are read from stdin (hidden prompt on a TTY, one line when piped), never from arguments:

```
docker exec -it kangpaket-server-kangpaket-api-1 kangpaket-server create-user --username alice --admin
docker exec -i  kangpaket-server-kangpaket-api-1 kangpaket-server create-user --username bob < pw.txt
docker exec -it kangpaket-server-kangpaket-api-1 kangpaket-server set-password --username alice
docker exec kangpaket-server-kangpaket-api-1 kangpaket-server disable-user --username bob   # or enable-user / delete-user
docker exec kangpaket-server-kangpaket-api-1 kangpaket-server list-users
```

`set-password` and `disable-user` revoke the user's refresh tokens.

## Migrations

SQL files in `migrations/` are embedded in the binary and applied in filename
order at startup; applied versions are tracked in `schema_migrations`. Add new
changes as new files (`0002_*.sql`); never edit applied ones.

## Test

```
go vet ./... && go test ./...
```
