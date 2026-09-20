# Go application template

A Go starting point for single-tenant backends: one installation, many users.
Accounts, global roles, permissions, sessions, API keys, invitations, and an
audit log — all working, all tested — plus the Postgres, Docker, and
configuration plumbing you would otherwise rewrite for the fifth time.

There is no Redis and no cache tier. Postgres is the only source of truth, so
there is nothing to invalidate and no second system to keep consistent.

There is also no tenant boundary. If you need one — customers each getting
their own isolated account, with per-tenant roles and membership — that is a
materially different shape (see `internal/identity`'s doc comment for exactly
what would have to change), and worth starting from a multi-tenant template
instead.

## Start a project with it

```sh
cp -r go-template my-project && cd my-project
make rename m=github.com/you/my-project   # rewrite the module path everywhere
make env                                  # .env from .env.example
make up                                   # Postgres + migrations + app on :8080
```

Then delete this README and write your own.

If 5432 or 8080 is already taken by another project's stack, edit the `ports:`
lines in `docker-compose.yml` — only the host side needs to move, since inside
the compose network Postgres is always 5432 and the app always 8080.

Once it's up, register an account and bootstrap your first administrator:

```sh
curl -s -X POST localhost:8080/api/v1/auth/register \
  -d '{"email":"you@example.com","password":"correct-horse-battery-staple"}'
docker compose exec app /app/server grant-role you@example.com admin
```

## What you get

| Concern | Where | Notes |
| --- | --- | --- |
| Config | `internal/settings` | One typed struct from env vars. Nothing else reads `os.Getenv`. |
| Database | `internal/database` | pgx pool, embedded goose migrations, `InTx` helper. |
| Passwords & tokens | `internal/auth` | argon2id hashing; opaque bearer tokens stored as SHA-256. |
| Identity | `internal/identity` | Users, sessions, API keys, invitations, email verification, password reset. |
| **RBAC** | `internal/identity` | `permissions.go` (the code-owned catalog), `roles_service.go` (the escalation guard). |
| Audit | `internal/audit` | Append-only (enforced by a DB trigger), records denials, searchable, keyset-paginated. |
| Mail | `internal/mail` | One `Mailer` interface; `log` and `smtp` backends. Every token is emailed, never returned. |
| HTTP | `internal/server` | chi router, auth + permission middleware, in-memory rate limiter, handlers. |

## Users

A user is **one account** — a single email and password. There is no separate
"admin user" or "staff user" account type: what a user may do is decided
entirely by which **roles** they hold, plus one special case (the superuser,
below).

**There is no membership to accept and no organization to join.** Everyone
with an account is, simply, in the installation. Two ways to get an account:

- **Register**, and hold whatever roles an admin later assigns you (none, by
  default).
- **Accept an invitation**, and the account is created already holding the
  role the inviter chose.

**Three things are properties of the account itself:**

| Attribute | What it means |
| --- | --- |
| `is_active` | A deactivated account is locked out on its **next request** — deactivating revokes every session in the same transaction, rather than waiting for a 30-day token to expire. Toggled via `PATCH /users/{id}`, gated by `users.update`. |
| `email_verified_at` | Proof the account controls its address. Not required for anything the template itself enforces — it is a signal your own product code can gate whatever it likes on. |
| `is_superuser` | The one privilege that outranks RBAC entirely. Not a role, and grantable only from the CLI. See [The superuser](#the-superuser). |

So there are really just **two tiers of access**: an ordinary user, whose
reach is exactly the roles they hold; and the **superuser**, an unconditional
bypass reserved for the installation's operator.

## RBAC

**Permissions come from code. Roles are data.**

That split is the load-bearing idea, so it's worth being precise about it. A
permission like `users.update` means something *only because* a route is
guarded with `requirePermission(PermUsersUpdate)`. If an admin could invent a
permission name at runtime, they'd create `billing.refund`, assign it to a
role, and see it rendered with a checkbox — while it enforced **nothing**. It
would look like it worked and grant zero.

So the **catalog** lives in `internal/identity/permissions.go`, one entry per
enforcement point, served read-only at `GET /api/v1/permissions` for your role
editor to render. A `permissions` table mirrors it, and `role_permissions` has
a **foreign key** into that table — so the database itself refuses to store a
grant for a permission no code checks. What's configurable is **which
permissions a role bundles**.

```
permissions       users.read  users.update
                  invitations.read  invitations.create  invitations.delete
                  roles.read  roles.create  roles.update  roles.delete
                  audit.read
                  apikeys.read  apikeys.create  apikeys.delete
                  ↑ from the Go Catalog. Not user-authored.

roles             is_system true  → admin / member, immutable, seeded by the migration
                  is_system false → a custom role someone built at runtime
role_permissions  which permissions a role grants   ← THE CONFIGURABLE PART
user_roles        which roles a user holds          ← many; permissions are the union
```

The naming is `<resource>.<action>` with CRUD verbs, and it has **no
exceptions**. Add a queue, add `queues.create/read/update/delete` — a
developer never invents a verb, and an admin building a role never guesses
what a word like "manage" covers.

One absence is deliberate: there is no **`users.create`**. An account is
created by registering or by accepting an invitation, never by an admin
conjuring one directly — those routes are guarded by rate limiting alone.

**A user may hold several roles**, and their permissions are the **union**.
That's what lets you give someone billing powers without cloning `member` into
a `member_who_also_does_billing` role — the combinatorial explosion that
one-role systems produce.

| | |
| --- | --- |
| `admin` | Every permission in the catalog. The last user holding it cannot be stripped of it or deactivated through the ordinary API. |
| `member` | `users.read`. Nothing else, by default — but it is an ordinary role, and its permissions can be changed like any other. |
| *custom* | Whatever you compose, e.g. "Billing Manager". |
| `is_superuser` | Not a role — a flag on the user. Outranks every role. See below. |

The two system roles are **immutable**, even to an admin. Otherwise the
installation could strip every permission from `admin` and lock itself out
permanently through the HTTP API, with no way back short of a database
console (the superuser CLI is exactly that way back).

### The escalation guard

A role editor is, by construction, a machine for handing out permissions. Give
a member `roles.create` with no guard and they'll simply build a role holding
`users.update`, assign it to themselves, and walk straight out through every
limit you placed on them. RBAC would be decoration.

One rule prevents it:

> **You may only grant permissions you yourself hold.**

`checkEscalation` in `internal/identity/roles_service.go` enforces it on
*every* path a permission can travel: creating a role, editing a role,
deleting a role, assigning roles to a user, issuing an invitation (which
carries a role), and minting an API key (which carries a permission set).

The elegance is that "only an admin may create an admin" then falls out **for
free** — the `admin` role carries permissions a member doesn't hold, so a
member assigning it fails with no special-casing for admins anywhere.

One rule can't be expressed as a permission and lives alongside it: an
ordinary member may not demote or deactivate an **admin** (they'd be
neutering someone strictly more powerful, while granting nothing), and the
**last admin** can't be stripped of the role or deactivated. Both are checked
in the service, where the data is — see `ErrForbidden` and `ErrLastAdmin` in
`internal/identity/errors.go`.

### Adding a permission

1. Add the constant and a `Catalog` entry in `internal/identity/permissions.go`.
2. Guard a route with `requirePermission(PermYourThing)` in `server.go`.
3. Restart. `SyncPermissions` upserts the catalog at startup — no migration.

Forget step 1 and the FK makes it impossible to grant, so the route becomes
unreachable by anyone but a superuser. That's a loud failure, by design.

### The superuser

`is_superuser` is the one privilege that outranks RBAC entirely: it holds
every permission in the catalog regardless of which roles the account holds,
and it cannot be locked out by any role change.

**It cannot be granted over HTTP.** There is no route for it, by design — if
there were, one stolen superuser token could mint permanent backdoor accounts.
It requires the CLI, and therefore database access:

```sh
server grant-superuser alice@example.com
server revoke-superuser alice@example.com
# in compose:  docker compose exec app /app/server grant-superuser you@example.com
```

For the ordinary case — standing up your **first** administrator — reach for
the friendlier bootstrap instead, which assigns the `admin` role without
touching the superuser flag:

```sh
server grant-role alice@example.com admin
```

Deactivating a user (`PATCH /api/v1/users/{id}` with `{"is_active": false}`)
revokes all their sessions in the same transaction, so the lockout lands on
their very next request rather than whenever their 30-day token happens to
expire.

## The audit log

Not a change-history — a security trail. Four properties, in order of how
much they matter:

**It records denials, not just successes.** Failed logins (with *why*: wrong
password vs. unknown email vs. deactivated — indistinguishable to the caller,
but recorded), permission denials, escalation attempts, and rejected
invitation tokens. Without these, someone working through a password list or
systematically probing which permissions they hold produces **no record at
all** — and an empty audit log reads exactly like "nothing happened".

Denials are written in the HTTP **error handler**, not the service, and
that's load-bearing: a refusal aborts its transaction, so an audit entry
written *inside* that transaction would be rolled back along with the very
failure it was recording.

**It resists accidents — and be clear that's all.** A database trigger
refuses `UPDATE`, `DELETE`, and `TRUNCATE` on `audit_log`. That catches a
careless query, a bad migration, and an injected `DELETE FROM audit_log`. All
worth catching.

**It does NOT make the log tamper-proof against a compromised app**, and the
code says so rather than implying otherwise. The trigger permits a `DELETE` to
anything that sets the `app.audit_purge` GUC — and *any* role can set that
GUC, no privilege required. So code already running as the application can do
this:

```sql
BEGIN;
SET LOCAL app.audit_purge = 'on';
DELETE FROM audit_log;   -- succeeds
COMMIT;
```

This falls out of a deliberate choice: **one database user, owning one
database** (see below). Real tamper-resistance needs *two* identities — a
privileged one for migrations and `server purge`, and a restricted one the app
connects as, holding no `DELETE` on `audit_log`. Then the **`GRANT`** does the
work, not the trigger. If you need that guarantee, it's a small change; the
seam is there.

One narrow exception is genuinely narrow: the update that anonymizes
`actor_user_id` to NULL when a user is hard-deleted. The trigger permits that
single update *only* if every other column is byte-for-byte identical — so a
GDPR erasure stays possible without opening a hole.

## The database

**One user, owning one database.** `POSTGRES_USER=app` owns `POSTGRES_DB=app`,
and that's the whole story — the official Postgres image creates the database
and makes the user its owner, so there's no bootstrap SQL and no second role.
Migrations, the app, and `server purge` all use it.

The app never connects as the cluster superuser and never touches another
database. One secret, one connection string.

The cost is stated above: no tamper-proof audit log. That's the trade, taken
knowingly.

**Every entry carries `request_id`, IP, and user agent**, so an entry ties
back to the exact request and its application logs. They ride the context
(`audit.WithRequestMeta`) rather than being threaded through a dozen service
signatures.

**It's searchable.** `?action=`, `?actor=`, `?from=`/`?to=`, keyset `?before=`.
Pagination alone is useless at 100k rows: an audit log you can't query is an
audit log nobody reads.

`AUDIT_RETENTION` defaults to **0 = keep forever**. Destroying your
compliance evidence because a config value had a tidy default is not a
decision this template makes for you.

## Sessions, not JWTs

Login issues a random 256-bit token. The database stores only its SHA-256
hash, so a leak of the `sessions` table hands an attacker nothing usable.

The payoff is revocation. A logout, a password change, or a deactivation
takes effect on the **very next request**, everywhere — where a stateless JWT
would stay valid until it expired. The cost is one indexed lookup per
request, which is the right trade for almost every application that isn't
Google.

Passwords use **argon2id** (OWASP's first choice — memory-hard, so GPUs help
an attacker far less than against bcrypt). The cost parameters live inside
each hash, so you can raise them later: existing passwords keep verifying and
are transparently upgraded on the owner's next login.

## API keys

Sessions are for people; **API keys** are the same idea for machines. A key
is an opaque `mtt_key_…` bearer token — shown **once** at creation, stored
only as its SHA-256 hash, exactly like a session — that a script puts in
`Authorization: Bearer`. Managed at `/api/v1/api-keys`.

Three properties are the whole design:

- **A key is owned by the user who minted it and carries a frozen permission
  set.** Not that user's roles — an explicit list chosen at creation
  (`users.read`, `invitations.create`, …), stored with the same foreign key
  into the catalog that `role_permissions` uses. Editing a role later never
  silently changes what a key can do.
- **You can't mint a key more powerful than yourself.** Creating one runs the
  same escalation guard as creating a role: the caller must already hold
  every permission they put in the key. So `apikeys.create` lets someone
  issue keys, not manufacture authority they lack.
- **A key acts as its creating user, and dies with them.** The audit log
  attributes a key's actions to the person who made it, tagged with
  `api_key_id` so automation is distinguishable from the human. Deactivating
  that person disables their keys on the next request.

Keys work only on the permission-gated part of the API — never account
management (change password, list sessions) — and revoking one takes effect
on its very next request, the same immediate revocation a session gets.
`apikeys.read` sees every key in the installation, not only your own; scope it
to `member` if you want keys to stay private to their owner and admins.

## Migrations

Plain SQL in `migrations/`, run by [goose](https://github.com/pressly/goose),
**compiled into the binary** with `//go:embed`. The same image is the app and
its own migrator:

```sh
make migrate          # apply
make migrate-status   # what's applied
make migrate-down     # roll back one
make migrate-reset    # roll back every migration (destroys all data)
```

In `docker-compose.yml` a one-shot `migrate` service runs `server migrate up`
and exits; `app` waits on `service_completed_successfully`, so it can never
start against an unmigrated database. In Kubernetes that identical container
is an init container or a Job.

To add one: create `migrations/00002_widgets.sql` with `-- +goose Up` and
`-- +goose Down` sections. Goose tracks what's applied in a table it owns. CI
runs a full migrate down-to-zero-and-back, so a missing `Down` section fails
the build rather than being discovered the day you need to roll back.

> **Postgres 18+ is required.** Every primary key defaults to the built-in
> `uuidv7()`. v7 IDs are time-ordered, so index inserts append to the
> rightmost leaf instead of scattering random v4s across the B-tree and
> splitting pages — and `ORDER BY id DESC` is a free, stable pagination
> cursor.
>
> **Every `TEST_POSTGRES_DSN` you point this at must be a database you can
> afford to lose.** The integration tests, `make migrate-reset`, and
> `make test-integration` all run destructive schema operations against
> whatever `POSTGRES_HOST`/`POSTGRES_PORT` resolve to — including the
> defaults, if you forget to set them. Never point this template at a shared
> or production database, and double-check the target before running a
> `migrate` or `test-integration` command against anything other than the
> throwaway container `make up` gives you.

## Configuration

All of it, in `internal/settings`, loaded once at startup from environment
variables — optionally seeded from `.env`, which real env vars always
override. See `.env.example`.

Startup **refuses to boot** on a configuration that is unsafe rather than
merely odd — a warning in a log nobody reads is not a control. When
`APP_ENV=production`:

- `APP_DEBUG=true` — it would echo internal error strings to callers.
- `POSTGRES_SSLMODE=disable`.
- `MAIL_BACKEND=log` — invitation and reset links are working credentials, and
  this would print them into your log aggregator.
- `CORS_ALLOWED_ORIGINS` containing `*` — this API authenticates with bearer
  tokens, and a wildcard origin would expose them to every site on the
  internet.
- `APP_BASE_URL` still pointing at `localhost` — the links in your emails
  would too.

And in any environment, a **zero TTL** for an invitation, a password reset,
or an email verification: it would mint links that are expired the instant
they're created.

## The API

```
POST   /api/v1/auth/register              create an account          (rate limited)
POST   /api/v1/auth/login                 -> {token, user}           (rate limited)
POST   /api/v1/auth/password/reset        email a reset link — ALWAYS 204     (rate limited)
POST   /api/v1/auth/password/reset/confirm   spend the token; revokes every session
POST   /api/v1/auth/email/verify          spend a verification token (rate limited)
POST   /api/v1/invitations/accept         redeem a token; CREATES the account (rate limited)
GET    /api/v1/permissions                the catalog (public; render your role editor from it)

POST   /api/v1/auth/logout                revoke this session
GET    /api/v1/auth/me
POST   /api/v1/auth/password              change password (revokes all sessions)
GET    /api/v1/auth/sessions              your live sessions
DELETE /api/v1/auth/sessions/{sessionID}  revoke one of them
POST   /api/v1/auth/email/verify/resend   re-send your verification email (rate limited)

                                            ── required permission ──
GET    /api/v1/users                              users.read
PUT    /api/v1/users/{userID}/roles               users.update   (complete set, not a delta)
PATCH  /api/v1/users/{userID}                     users.update   (activate / deactivate)

GET    /api/v1/invitations                        invitations.read
POST   /api/v1/invitations                        invitations.create
DELETE /api/v1/invitations/{id}                   invitations.delete

GET    /api/v1/roles                              roles.read
POST   /api/v1/roles                              roles.create
PUT    /api/v1/roles/{id}                         roles.update
DELETE /api/v1/roles/{id}                         roles.delete

GET    /api/v1/audit                              audit.read
       ?action=roles.created &actor=<uuid> &from=/&to=<RFC3339> &before=<cursor>

GET    /api/v1/api-keys                           apikeys.read
POST   /api/v1/api-keys                           apikeys.create  (token shown ONCE)
DELETE /api/v1/api-keys/{id}                      apikeys.delete

GET    /healthz                           liveness  (never touches the database)
GET    /readyz                            readiness (pings the database)
```

Every permission-gated route names the **one** permission it needs, right in
`server.go`'s routing table. Read it top to bottom and you have the entire
authorization policy — which is the point of putting it there instead of
scattering checks through handlers.

The `roles.*` routes — and `invitations.create`, which hands out a role — are
additionally subject to the escalation guard in the service: the permission
lets you *operate* the role editor, it does not let you hand out authority you
don't have.

`/healthz` deliberately does not check the database: if it did, a brief
Postgres blip would make Kubernetes kill every replica, turning a recoverable
outage into a total one. `/readyz` does check, because a replica that can't
reach Postgres should leave the load balancer, not restart.

## Adding your own resource

1. **Migration** — `migrations/00002_widgets.sql`.
2. **Permissions** — add `widgets.create/read/update/delete` to the `Catalog`
   in `internal/identity/permissions.go`. `SyncPermissions` upserts them at
   startup.
3. **Package** — `internal/widgets`, following `internal/identity`: a
   `Repository` taking `database.DB` (so it works with both a pool and a
   transaction), and a `Service` holding the rules.
4. **Routes** — inside the permission-gated group in
   `internal/server/server.go`. Handlers get the caller from `userFrom(ctx)`
   and their authority from `accessFrom(ctx)`, both guaranteed present by the
   middleware. Guard each route with the one permission it needs:
   `r.With(s.requirePermission(identity.PermWidgetsCreate)).Post("/widgets", …)`.
5. **Audit** — call `audit.NewRecorder(tx).Record(...)` inside the same
   transaction as the write, so an action can never happen without being
   logged.

## Testing

```sh
make test              # unit tests; integration tests SKIP without a database
make test-integration  # starts a throwaway Postgres, runs everything
make test-e2e          # drives the running stack over real HTTP (needs `make up`)
make cover             # same, plus an HTML coverage report
```

Integration tests run against a **real Postgres**, because what they're
checking *is* the SQL: the append-only audit trigger, uuidv7 defaults, partial
unique indexes, the RBAC escalation guard. A mocked database would happily
"prove" queries correct that a real constraint would reject. They apply the
same embedded migrations the app ships, so they can't drift from production's
schema.

CI (`.github/workflows/ci.yml`) runs five jobs on every push: static checks
(`vet`, `gofmt`, `go mod tidy` freshness, `shellcheck`), lint
(`golangci-lint` + `govulncheck`), tests against a real Postgres with the race
detector **plus a full migrate down-to-zero-and-back**, the e2e suites against
a real running server, and a Docker image build.

Linting is deliberately tuned for **signal over volume** — `golangci-lint`
runs the bug-catching linters (`staticcheck`, `errcheck`, `gosec`,
`bodyclose`, `errorlint`, …), not stylistic nitpicks; the set and the few
documented exclusions live in `.golangci.yml`. Run it locally with
`make lint`, and `make vulncheck` for the dependency scan.

Two CI details worth copying if you fork the pattern:

- **It asserts the integration tests didn't silently skip.** They skip
  without `TEST_POSTGRES_DSN`, which is what keeps `go test ./...` working on
  a laptop with no database — and which would otherwise let a broken DSN turn
  the whole job green while proving nothing.
- **Each e2e suite gets a fresh database.** They each assume they're the only
  users in the installation, and a leftover row from the previous suite reads
  as a bug that isn't there.

Using Podman? Every compose target takes an override:
`make test-integration COMPOSE="podman compose"`. (A `docker` shell *alias*
won't work — make runs recipes in `/bin/sh`, which doesn't see your aliases.)

## Email, invitations, verification, and password reset

**Tokens are emailed, never returned by the API.** `POST /invitations` does
not hand the plaintext token back in the response — that would let any admin
mint a working invitation link for `carol@example.com`, keep it, and redeem it
themselves before she ever sees it. The only copy goes to the invitee's inbox.

With `MAIL_BACKEND=log` (the default) that "inbox" is the application log, so
the link is right there in `docker compose logs app`. That's what keeps the
template runnable with zero setup — and it's exactly why startup **refuses**
that backend when `APP_ENV=production`: those links are working credentials,
and this would put them in your log aggregator.

**An invitation creates the account.** Unlike a multi-tenant "join an
organization" flow, there's no pre-existing membership for the invitee to
accept into — so `POST /invitations/accept` takes a password and a name
alongside the token, and *that* call is what creates the user, already
holding the invited role. Inviting an email that already has an account is
refused (`409`); assign the role directly with `PUT /users/{id}/roles`
instead.

**Password reset** is the invitation pattern again — a random token, stored
only as its SHA-256 digest, single-use, short TTL (1h; a zero TTL is refused
at startup, because it would mint links that are expired the instant they're
created).

### Email verification

`users.email` was always unique, but nothing checked that the person who
typed it **controls** it. That was tolerable until there was a password
reset: a reset is only ever as trustworthy as the mailbox it's sent to.

The token is the same pattern once more — random, stored as its SHA-256
digest, single-use, `AUTH_EMAIL_VERIFY_TTL` (24h). It's minted at
registration and on demand via `POST /auth/email/verify/resend`.

**It gates nothing the template itself enforces.** Locking somebody out of
their own account because a verification mail landed in spam is a support
nightmare for very little gain, so login works whether or not the address is
confirmed. `User.EmailVerifiedAt` is exposed precisely so your own product
code can require it for whatever *you* consider sensitive.

**Accepting an invitation verifies the address too**, and that isn't a
shortcut — it's the same proof by a different route. The invitation token
went to that mailbox and nowhere else, so holding it *is* control of the
mailbox; demanding a second email afterwards would be theatre.

Two properties are load-bearing:

- **`POST /auth/password/reset` ALWAYS returns 204.** Unknown address,
  deactivated account, SSO-only user, database failure — all identical.
  Anything else is a free account-enumeration oracle on an unauthenticated
  endpoint. Which case it *really* was gets recorded in the audit log, where
  the attacker can't see it and you can.
- **Completing a reset revokes every session.** If someone is resetting
  because they were compromised, leaving the attacker's session alive
  achieves nothing.

## Rate limiting

Guards every unauthenticated or token-spending route: `/auth/login`,
`/auth/register`, `/auth/password/reset`, `/auth/password/reset/confirm`,
`/auth/email/verify`, `/auth/email/verify/resend`, and `/invitations/accept`.

Login, register, and reset are keyed by **IP *and* email**, and both must
pass — IP alone lets one attacker spray a thousand accounts at one attempt
each and never trip a counter; email alone lets a botnet hammer one account
from a thousand addresses. The token-spending routes are keyed by IP: there's
no email in the request, just a bearer credential somebody might be guessing
at.

Trips return **429** with `Retry-After`, and are **audited**
(`access.rate_limited`): one is noise, a stream from one IP is an attack, and
the audit log is the only place you'd see the difference.

**Know what it is.** It's in-memory, therefore **per-replica**, and a restart
forgets everything. It's a speed bump so an unprotected deployment isn't
trivially brute-forceable — not a wall. The real limiter belongs at your
proxy.

## Before you take this to production

The template stops at the point where every project diverges. You need to add:

- **Alerting.** The audit log records the events that matter — but nothing
  *reads* it, so right now they only make rows. Every denial is also emitted
  as a `WARN` log line with a stable `security_event` field, because your
  alerting can already match on a log field and nobody wants to point it at
  a Postgres table. Wire rules to at least: `access.escalation_denied`
  (rarely innocent), and a burst of `users.login_failed` or
  `users.password_reset_rejected` from one IP (enumeration in progress).
- **A cron for `server purge`,** if you set `AUDIT_RETENTION`. It defaults to
  0 — keep forever — and does not take effect until something runs the
  command. Nothing in the app runs it for you, by design.
- **A real mail provider.** `MAIL_BACKEND=log` prints emails (links and all)
  to the application log — which is what makes this runnable with zero setup,
  and why startup *refuses* it when `APP_ENV=production`. `MAIL_BACKEND=smtp`
  works, but most projects will swap in their provider's SDK. The
  `mail.Mailer` interface is the one seam you need to touch.
- **A real rate limiter.** The built-in one is in-memory and therefore
  **per-replica** — three replicas means three times the allowance, and a
  restart forgets everything. It's a speed bump so an unprotected deployment
  isn't trivially brute-forceable. Put the real one at your proxy or WAF,
  where it sees every replica's traffic.
- **A real password for the `app` database user.** It ships as `app`.
- **A second database identity, IF you need a tamper-proof audit log.** Today
  one user owns the database and holds `DELETE` on every table in it, so code
  running as the app can erase its own audit trail — the trigger stops
  accidents, not an attacker. See "The audit log". Splitting into a
  privileged migration/purge identity and a restricted runtime one that holds
  no `DELETE` on `audit_log` closes it, and then the `GRANT` does the work
  rather than the trigger.
- **TLS**, terminated at your proxy. Set `SERVER_TRUST_PROXY_HEADERS=true`
  only once a proxy you control is guaranteed to overwrite
  `X-Forwarded-For` — otherwise callers can forge the IPs written into your
  audit log.
