#!/usr/bin/env bash
# Drive the real HTTP API end to end: register -> login -> me -> sessions ->
# invite -> accept (which CREATES the invitee's account) -> logout.
#
# Overridable so these run against compose OR a plain binary (see .github/workflows):
#   API_BASE    where the API is            (default http://localhost:8080)
#   SERVER_CMD  how to run the server CLI   (default: docker compose exec -T app /app/server)
#   DB_EXEC     how to reach psql           (default: docker compose exec -T postgres)
#   APP_LOGS    how to read the app's log   (default: docker compose logs app)
#               -- the log IS the inbox when MAIL_BACKEND=log
set -uo pipefail
API="${API_BASE:-http://localhost:8080}/api/v1"
pass=0; fail=0

check() { # check <label> <expected> <actual>
  if [ "$2" = "$3" ]; then echo "  PASS  $1 ($3)"; pass=$((pass+1));
  else echo "  FAIL  $1: expected $2, got $3"; fail=$((fail+1)); fi
}

# Returns the HTTP status; writes body to /tmp/body
req() { # req <method> <path> <token|-> [json]
  local m=$1 p=$2 t=$3 d=${4:-}
  local args=(-s -o /tmp/body -w '%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json')
  [ "$t" != "-" ] && args+=(-H "Authorization: Bearer $t")
  [ -n "$d" ] && args+=(-d "$d")
  curl "${args[@]}"
}
jqr() { jq -r "$1" /tmp/body; }
logs() { ${APP_LOGS:-docker compose logs app} 2>&1; }

# Tokens are EMAILED, never returned. With MAIL_BACKEND=log the "inbox" is the
# application log -- so that is where we read them, exactly as a real user reads
# them out of their mail.
invite_token() { logs | grep -o 'token=mtt_inv_[A-Za-z0-9_-]*' | tail -1 | cut -d= -f2; }

echo "== register =="
code=$(req POST /auth/register - '{"email":"alice@example.com","password":"correct-horse-battery","full_name":"Alice"}')
check "register alice" 201 "$code"
check "no password hash leaked" "null" "$(jq -r '.password_hash // "null"' /tmp/body)"
check "not verified yet" "null" "$(jq -r '.email_verified_at // "null"' /tmp/body)"

code=$(req POST /auth/register - '{"email":"alice@example.com","password":"correct-horse-battery"}')
check "duplicate email -> 409" 409 "$code"
code=$(req POST /auth/register - '{"email":"x@example.com","password":"short"}')
check "short password -> 400" 400 "$code"

code=$(req POST /auth/register - '{"email":"bob@example.com","password":"correct-horse-battery","full_name":"Bob"}')
check "register bob" 201 "$code"

echo "== login =="
code=$(req POST /auth/login - '{"email":"alice@example.com","password":"correct-horse-battery"}')
check "login alice" 200 "$code"
ALICE=$(jqr .token)
[ -n "$ALICE" ] && [ "$ALICE" != null ] && echo "  PASS  got a token: ${ALICE:0:16}..." && pass=$((pass+1))

code=$(req POST /auth/login - '{"email":"alice@example.com","password":"wrong-password"}')
check "wrong password -> 401" 401 "$code"
code=$(req POST /auth/login - '{"email":"nobody@example.com","password":"correct-horse-battery"}')
check "unknown email -> 401 (same as wrong password)" 401 "$code"

code=$(req POST /auth/login - '{"email":"bob@example.com","password":"correct-horse-battery"}')
BOB=$(jqr .token)

echo "== auth guards =="
code=$(req GET /auth/me -)
check "no token -> 401" 401 "$code"
code=$(req GET /auth/me "garbage-token")
check "bad token -> 401" 401 "$code"
code=$(req GET /auth/me "$ALICE")
check "me with a good token" 200 "$code"
check "me is alice" "alice@example.com" "$(jqr .email)"

echo "== a bare, unrouted account can do nothing else =="
code=$(req GET /users "$ALICE")
check "no role yet -> 403 on users.read" 403 "$code"

echo "== invitations create the account (no pre-registration needed) =="
${SERVER_CMD:-docker compose exec -T app /app/server} grant-role alice@example.com admin >/dev/null 2>&1
ALICE=$(req POST /auth/login - '{"email":"alice@example.com","password":"correct-horse-battery"}' >/dev/null; jqr .token)

req GET /roles "$ALICE" >/dev/null
MEMBER_ID=$(jq -r '.roles[]|select(.key=="member").id' /tmp/body)

code=$(req POST /invitations "$ALICE" "{\"email\":\"carol@example.com\",\"role_id\":\"$MEMBER_ID\"}")
check "alice invites carol" 201 "$code"
check "  ...response has NO token" "null" "$(jq -r '.token // "null"' /tmp/body)"
INV=$(invite_token)
[ -n "$INV" ] && { echo "  PASS  ...but it WAS emailed (found in the log)"; pass=$((pass+1)); } \
             || { echo "  FAIL  no invitation email was sent"; fail=$((fail+1)); }

code=$(req POST /invitations/accept - "{\"token\":\"$INV\",\"password\":\"correct-horse-battery\",\"full_name\":\"Carol\"}")
check "carol accepts and her account is created" 201 "$code"
check "carol's email arrived pre-verified (the token proved control)" \
  "not-null" "$([ "$(jq -r '.email_verified_at' /tmp/body)" != "null" ] && echo not-null || echo null)"

code=$(req POST /invitations/accept - "{\"token\":\"$INV\",\"password\":\"correct-horse-battery\"}")
check "replaying a spent invite -> 400" 400 "$code"

code=$(req POST /auth/login - '{"email":"carol@example.com","password":"correct-horse-battery"}')
check "carol logs in with the password she set" 200 "$code"
CAROL=$(jqr .token)
code=$(req GET /users "$CAROL")
check "carol has the invited (member) role" 200 "$code"

echo "== inviting an already-registered email is refused =="
code=$(req POST /invitations "$ALICE" "{\"email\":\"bob@example.com\",\"role_id\":\"$MEMBER_ID\"}")
check "inviting an existing account -> 409" 409 "$code"

echo "== sessions =="
code=$(req GET /auth/sessions "$ALICE")
check "list sessions" 200 "$code"
code=$(req POST /auth/logout "$ALICE")
check "logout" 204 "$code"
code=$(req GET /auth/me "$ALICE")
check "revoked token -> 401 immediately" 401 "$code"
code=$(req GET /auth/me "$BOB")
check "bob's session unaffected" 200 "$code"

echo
echo "======================================"
echo "  PASSED: $pass   FAILED: $fail"
echo "======================================"
[ "$fail" -eq 0 ]
