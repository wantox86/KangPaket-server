# KangPaket-server

Cloud sync backend for the KangPaket desktop app. Go + MySQL.

Phase 1: config, `/healthz`, auto-migrations, Docker. Phase 2: authentication. Phase 3: Sync API (this state).

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
- Sync handlers wrap routes with `httpapi.RequireAuth` and read the user via `httpapi.UserID(ctx)`.

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

## Sync API

Two resources per user: **profiles** (KangPaket request profiles) and **environments**. The client
sends the whole record as a JSON object in `payload` (stored as sent, compacted, plaintext
including auth fields). Everything requires `Authorization: Bearer <access_token>`; data is
strictly per user (every query is keyed by `user_id`; the same client `id` under two users are
unrelated records). Deleting a user removes their sync data (FK cascade). Sync routes are rate
limited to 120 requests/min per user.

### `GET /sync/pull?since=<cursor>&limit=<n>`

Returns every change (including tombstones) with `server_version > since`, in version order.
`since` defaults to 0, `limit` to 500 (max 1000). The page is also cut at ~4 MiB of payload so
responses stay small in the 128m container; follow `has_more`.

```json
{"items":[
  {"kind":"profile","id":"1111...","label":"c1","payload":{...},"client_updated_at":1000,"deleted":false,"server_version":1},
  {"kind":"environment","id":"3333...","label":"prod","payload":{...},"client_updated_at":1000,"deleted":false,"server_version":2},
  {"kind":"profile","id":"4444...","client_updated_at":2000,"deleted":true,"server_version":3}],
 "cursor":3,"has_more":false}
```

`label` is the profile's `collection` or the environment's `name`. Tombstones have no payload.
Store `cursor`, pass it as `since` next time; keep pulling while `has_more` is true.

### `POST /sync/push`

```json
{"profiles":[{"id":"<uuid>","collection":"c1","client_updated_at":1000,"payload":{...}},
             {"id":"<uuid>","deleted":true,"client_updated_at":2000}],
 "environments":[{"id":"<uuid>","name":"prod","client_updated_at":1000,"payload":{...}}]}
```

Response: `{"results":[{"kind","id","status","server_version","server"?}],"cursor":N}`; `status` is
- `applied`: written, got a new `server_version`;
- `skipped`: server already holds identical data (re-pushing is idempotent, no version bump);
- `conflict`: server copy is newer/wins; the winning copy is returned in `server`. Not an error (HTTP 200).

The whole request is one transaction (all or nothing on server errors). Deletes are tombstones
(`deleted:true`, payload dropped) so they propagate; a later push with a newer
`client_updated_at` resurrects the record.

Limits (errors are `{"error":"<code>"}`): body 5 MiB (413 `payload_too_large`), 500 items per push
(413 `too_many_items`), 256 KiB per payload (413 `item_too_large`), `id` must be a UUID
(`invalid_id`, ids are lowercased, duplicates in one push -> `duplicate_id`), `client_updated_at`
positive unix ms (`invalid_client_updated_at`), payload must be a JSON object (`invalid_payload`),
`collection`/`name` max 255 chars (`invalid_label`), bad `since`/`limit` -> 400.

### Design notes

- **server_version**: one monotonic counter per user (`sync_counters`), shared by profiles and
  environments. A push locks the user's counter row (`SELECT ... FOR UPDATE`), assigns
  `++counter` to every applied item and writes the counter back before commit. Pushes of one user
  are thus serialised and versions become visible in commit order, so a client holding cursor N can
  never miss a lower version that commits later (which can happen with a global AUTO_INCREMENT
  or a timestamp cursor). It does not depend on any clock. Pulls read both tables in one
  read-only snapshot. Different users never contend.
- **Conflicts (LWW)**: compare `client_updated_at` (client clock, ms). Newer wins; older gets
  `conflict`. On equal timestamps: identical content -> `skipped`; otherwise a tombstone beats a
  live record, and between two live records the byte-wise larger `label + "\0" + payload` wins, so
  the result is the same whichever device pushes first. Client clock skew can make an old edit
  win; that is the accepted LWW trade-off.
- Cursors only advance through **pull**. The `cursor` in a push response is the user's latest
  version, which may include other devices' changes you have not pulled; do not store it as the
  pull cursor.

### Recommended client flow

First login on a device (two-way merge): `pull` from `since=0` until `has_more` is false and merge
into local data (per `id`, keep the record with the larger `client_updated_at`; tombstones delete);
then `push` every local record that is newer than, or missing from, the server copy; handle
`conflict` results by adopting `server`; then `pull` again from the stored cursor and save the
returned `cursor`. Afterwards sync = `push` local changes (with deletes as tombstones, batches of
<= 500) then `pull` from the stored cursor. Refresh the access token (15 min) on 401.

## Migrations

SQL files in `migrations/` are embedded in the binary and applied in filename
order at startup; applied versions are tracked in `schema_migrations`. Add new
changes as new files (`0002_*.sql`); never edit applied ones.

## Test

```
go vet ./... && go test ./...
```
