#!/usr/bin/env bash
# Exercise the superuser bypass over the real HTTP API + the real CLI, and the
# CLI's ordinary bootstrap path (grant-role) alongside it.
#
# Overridable so these run against compose OR a plain binary (see .github/workflows):
#   API_BASE    where the API is            (default http://localhost:8080)
#   SERVER_CMD  how to run the server CLI   (default: docker compose exec -T app /app/server)
set -uo pipefail
API="${API_BASE:-http://localhost:8080}/api/v1"
pass=0; fail=0

check() { if [ "$2" = "$3" ]; then echo "  PASS  $1 ($3)"; pass=$((pass+1));
          else echo "  FAIL  $1: expected $2, got $3"; fail=$((fail+1)); fi; }
req() {
  local m=$1 p=$2 t=$3 d=${4:-}
  local args=(-s -o /tmp/body -w '%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json')
  [ "$t" != "-" ] && args+=(-H "Authorization: Bearer $t")
  [ -n "$d" ] && args+=(-d "$d")
  curl "${args[@]}"
}
jqr() { jq -r "$1" /tmp/body; }
reg() { req POST /auth/register - "{\"email\":\"$1\",\"password\":\"correct-horse-battery\"}" >/dev/null; }
login() { req POST /auth/login - "{\"email\":\"$1\",\"password\":\"correct-horse-battery\"}" >/dev/null; jqr .token; }

echo "== setup: alice is a plain account, root will become superuser =="
reg alice@example.com
reg root@example.com
ALICE=$(login alice@example.com)
ROOT=$(login root@example.com)

echo "== before the grant, root is nobody special =="
code=$(req GET /users "$ROOT")
check "plain user cannot list users -> 403" 403 "$code"

echo "== grant-role: the ordinary bootstrap path (no HTTP route can do this either) =="
OUT=$(${SERVER_CMD:-docker compose exec -T app /app/server} grant-role alice@example.com admin 2>&1)
echo "  CLI: $OUT"
echo "$OUT" | grep -q 'granted "admin" to alice@example.com' \
  && { echo "  PASS  CLI granted the admin role"; pass=$((pass+1)); } \
  || { echo "  FAIL  CLI did not grant"; fail=$((fail+1)); }
ALICE=$(login alice@example.com)
code=$(req GET /users "$ALICE")
check "alice (now admin) can list users" 200 "$code"

echo "== grant-superuser via CLI =="
OUT=$(${SERVER_CMD:-docker compose exec -T app /app/server} grant-superuser root@example.com 2>&1)
echo "  CLI: $OUT"
echo "$OUT" | grep -q 'granted superuser to root@example.com' \
  && { echo "  PASS  CLI granted superuser"; pass=$((pass+1)); } \
  || { echo "  FAIL  CLI did not grant"; fail=$((fail+1)); }

# The flag is read per-request from the DB, so the existing token picks it up.
echo "== after the grant =="
code=$(req GET /auth/me "$ROOT")
check "me reports is_superuser" "true" "$(jqr .is_superuser)"

code=$(req GET /users "$ROOT")
check "superuser can list users despite holding no role" 200 "$code"

code=$(req GET /roles "$ROOT")
check "  ...and read roles too" 200 "$code"

echo "== deactivation is immediate =="
ALICE_ID=$(req GET /auth/me "$ALICE" >/dev/null; jqr .id)
code=$(req PATCH "/users/$ALICE_ID" "$ROOT" '{"is_active":false}')
check "superuser deactivates alice" 200 "$code"
code=$(req GET /auth/me "$ALICE")
check "alice's live token dies at once -> 401" 401 "$code"
code=$(req POST /auth/login - '{"email":"alice@example.com","password":"correct-horse-battery"}')
check "alice cannot log back in -> 401" 401 "$code"

code=$(req PATCH "/users/$ALICE_ID" "$ROOT" '{"is_active":true}')
check "superuser reactivates alice" 200 "$code"
code=$(req POST /auth/login - '{"email":"alice@example.com","password":"correct-horse-battery"}')
check "alice can log in again" 200 "$code"

ROOT_ID=$(req GET /auth/me "$ROOT" >/dev/null; jqr .id)
code=$(req PATCH "/users/$ROOT_ID" "$ROOT" '{"is_active":false}')
check "superuser cannot deactivate itself -> 400" 400 "$code"

echo "== no HTTP route can grant superuser =="
code=$(req PATCH "/users/$ALICE_ID" "$ROOT" '{"is_superuser":true}')
check "trying to set is_superuser over HTTP -> 400 (unknown field)" 400 "$code"
ALICE=$(login alice@example.com)
code=$(req GET /auth/me "$ALICE")
check "alice is still not a superuser" "false" "$(jqr .is_superuser)"

echo "== revoke via CLI =="
${SERVER_CMD:-docker compose exec -T app /app/server} revoke-superuser root@example.com >/dev/null 2>&1
code=$(req GET /audit "$ROOT")
check "revoked: bypass gone, root has no roles either -> 403" 403 "$code"

echo
echo "======================================"
echo "  PASSED: $pass   FAILED: $fail"
echo "======================================"
[ "$fail" -eq 0 ]
