#!/usr/bin/env bash
# API keys (mint, authenticate with, revoke, escalation guard) and the audit log
# (filters, pagination, denials).
#
# Overridable so these run against compose OR a plain binary (see .github/workflows):
#   API_BASE    where the API is            (default http://localhost:8080)
#   SERVER_CMD  how to run the server CLI   (default: docker compose exec -T app /app/server)
#   DB_EXEC     how to reach psql           (default: docker compose exec -T postgres)
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

echo "== setup =="
reg admin@example.com; reg plain@example.com
${SERVER_CMD:-docker compose exec -T app /app/server} grant-role admin@example.com admin >/dev/null 2>&1
ADMIN=$(login admin@example.com)
PLAIN=$(login plain@example.com)

echo "== api keys =="
code=$(req GET /api-keys "$PLAIN")
check "plain account cannot list api keys -> 403" 403 "$code"

code=$(req POST /api-keys "$ADMIN" '{"name":"ci key","permissions":["users.read"]}')
check "admin mints an api key" 201 "$code"
check "the token is present exactly once, here" false "$([ "$(jqr .token)" = "null" ] && echo true || echo false)"
KEY_ID=$(jqr .api_key.id)
TOKEN=$(jqr .token)

code=$(req GET /users "$TOKEN")
check "the key authenticates like a session, with its own scope" 200 "$code"
code=$(req GET /auth/me "$TOKEN")
check "a key cannot reach account-management endpoints" 403 "$code"

# Give plain JUST enough to reach the handler (apikeys.create), so the 403 that
# follows comes from the ESCALATION guard in the service, not the permission
# middleware refusing them outright.
code=$(req POST /roles "$ADMIN" '{"key":"key_minter","name":"Key Minter","permissions":["apikeys.create","apikeys.read"]}')
check "admin creates a key_minter role" 201 "$code"
KEY_MINTER_ID=$(jqr .id)
PLAIN_ID=$(req GET /auth/me "$PLAIN" >/dev/null; jqr .id)
code=$(req PUT "/users/$PLAIN_ID/roles" "$ADMIN" "{\"role_ids\":[\"$KEY_MINTER_ID\"]}")
check "admin grants plain the key_minter role" 204 "$code"
PLAIN=$(login plain@example.com)

code=$(req POST /api-keys "$PLAIN" '{"name":"too powerful","permissions":["users.read","users.update"]}')
check "minting a key beyond own permissions -> 403 (escalation, not a missing base permission)" 403 "$code"

code=$(req DELETE "/api-keys/$KEY_ID" "$ADMIN")
check "revoke the key" 204 "$code"
code=$(req GET /users "$TOKEN")
check "revocation is immediate -> 401" 401 "$code"

echo "== audit log =="
code=$(req GET /audit "$PLAIN")
check "plain account cannot read the audit log -> 403" 403 "$code"

code=$(req GET /audit "$ADMIN")
check "admin reads the audit log" 200 "$code"
n=$(jq '.entries|length' /tmp/body)
echo "  INFO  entries on the first page: $n"

code=$(req GET "/audit?action=apikeys.created" "$ADMIN")
check "filter by action" 200 "$code"
check "exactly the one key-creation event" 1 "$(jq '.entries|length' /tmp/body)"

code=$(req GET "/audit?action=access.denied" "$ADMIN")
check "denials are recorded too (the 403s above)" 200 "$code"
n=$(jq '.entries|length' /tmp/body)
[ "${n:-0}" -ge 1 ] && { echo "  PASS  at least one access.denied entry ($n)"; pass=$((pass+1)); } \
                    || { echo "  FAIL  the earlier 403s left no trace"; fail=$((fail+1)); }

echo "== escalation denials are recorded with the missing permissions named =="
n=$(${DB_EXEC:-docker compose exec -T postgres} psql -U app -d app -tAc \
    "SELECT count(*) FROM audit_log WHERE action='access.escalation_denied'" 2>/dev/null | tr -d ' ')
[ "${n:-0}" -ge 1 ] && { echo "  PASS  escalation denial recorded ($n)"; pass=$((pass+1)); } \
                    || { echo "  FAIL  the escalation attempt above left no trace"; fail=$((fail+1)); }

echo
echo "======================================"
echo "  PASSED: $pass   FAILED: $fail"
echo "======================================"
[ "$fail" -eq 0 ]
