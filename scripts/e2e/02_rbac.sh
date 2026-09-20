#!/usr/bin/env bash
# RBAC over the real HTTP API: the permission catalog, custom roles, the
# escalation guard, and the last-admin protection.
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
roleid() { req GET /roles "$1" >/dev/null; jq -r ".roles[]|select(.key==\"$2\").id" /tmp/body; }

echo "== permission catalog is public =="
code=$(req GET /permissions -)
check "GET /permissions" 200 "$code"
NPERMS=$(jq '.permissions|length' /tmp/body)
echo "  INFO  catalog has $NPERMS permissions"

echo "== setup: alice is admin, bob and carol are plain accounts =="
reg alice@example.com; reg bob@example.com; reg carol@example.com
${SERVER_CMD:-docker compose exec -T app /app/server} grant-role alice@example.com admin >/dev/null 2>&1
ALICE=$(login alice@example.com); BOB=$(login bob@example.com); CAROL=$(login carol@example.com)

code=$(req GET /users "$BOB")
check "a bare account cannot list users" 403 "$code"

MEMBER_ID=$(roleid "$ALICE" member)
BOB_ID=$(req GET /auth/me "$BOB" >/dev/null; jqr .id)
code=$(req PUT "/users/$BOB_ID/roles" "$ALICE" "{\"role_ids\":[\"$MEMBER_ID\"]}")
check "admin grants bob the member role" 204 "$code"
code=$(req GET /users "$BOB")
check "bob can now list users (member holds users.read)" 200 "$code"

echo "== custom roles =="
code=$(req POST /roles "$ALICE" '{"key":"auditor","name":"Auditor","permissions":["audit.read"]}')
check "admin creates a custom role" 201 "$code"
AUDITOR_ID=$(jqr .id)

# To exercise the ESCALATION guard specifically (as opposed to a plain missing-
# permission 403), bob first needs roles.create himself -- otherwise the
# permission middleware rejects him before the service ever runs
# checkEscalation.
code=$(req POST /roles "$ALICE" '{"key":"role_editor","name":"Role Editor","permissions":["roles.create","roles.read"]}')
check "admin creates a role_editor role" 201 "$code"
ROLE_EDITOR_ID=$(jqr .id)
code=$(req PUT "/users/$BOB_ID/roles" "$ALICE" "{\"role_ids\":[\"$MEMBER_ID\",\"$ROLE_EDITOR_ID\"]}")
check "admin grants bob member + role_editor" 204 "$code"
BOB=$(login bob@example.com)

code=$(req POST /roles "$BOB" '{"key":"sneaky","name":"Sneaky","permissions":["users.read","users.update"]}')
check "bob (holds roles.create, not users.update) minting a role beyond his own permissions -> 403" 403 "$code"
echo "  INFO  $(jqr .error)"

code=$(req PUT "/users/$BOB_ID/roles" "$ALICE" "{\"role_ids\":[\"$MEMBER_ID\",\"$AUDITOR_ID\"]}")
check "admin grants bob member + auditor instead" 204 "$code"
code=$(req GET /audit "$BOB")
check "bob (member+auditor) can now read the audit log" 200 "$code"

echo "== system roles are immutable =="
ADMIN_ID=$(roleid "$ALICE" admin)
code=$(req PUT "/roles/$ADMIN_ID" "$ALICE" '{"name":"Not Admin","permissions":["users.read"]}')
check "editing the system admin role -> 403" 403 "$code"
code=$(req DELETE "/roles/$ADMIN_ID" "$ALICE")
check "deleting the system admin role -> 403" 403 "$code"

echo "== deleting a role in use is refused =="
code=$(req DELETE "/roles/$AUDITOR_ID" "$ALICE")
check "deleting auditor while bob holds it -> 409" 409 "$code"
req PUT "/users/$BOB_ID/roles" "$ALICE" "{\"role_ids\":[\"$MEMBER_ID\"]}" >/dev/null
code=$(req DELETE "/roles/$AUDITOR_ID" "$ALICE")
check "deleting auditor after reassignment" 204 "$code"

echo "== only an admin may demote an admin, even holding every permission =="
${SERVER_CMD:-docker compose exec -T app /app/server} grant-role carol@example.com admin >/dev/null 2>&1
CAROL=$(login carol@example.com)
ALICE_ID=$(req GET /auth/me "$ALICE" >/dev/null; jqr .id)

req GET /permissions - >/dev/null
ALL_PERMS=$(jq -c '[.permissions[].key]' /tmp/body)
req POST /roles "$ALICE" "{\"key\":\"god_mode\",\"name\":\"God Mode\",\"permissions\":$ALL_PERMS}" >/dev/null
GODMODE_ID=$(jqr .id)
code=$(req PUT "/users/$BOB_ID/roles" "$ALICE" "{\"role_ids\":[\"$MEMBER_ID\",\"$GODMODE_ID\"]}")
check "bob is granted every permission there is" 204 "$code"
BOB=$(login bob@example.com)

code=$(req PUT "/users/$ALICE_ID/roles" "$BOB" '{"role_ids":[]}')
check "bob (all permissions, but not admin) demoting an admin -> 403" 403 "$code"

echo "== last admin cannot be removed =="
code=$(req PUT "/users/$ALICE_ID/roles" "$ALICE" '{"role_ids":[]}')
check "alice steps down safely -- carol is still an admin" 204 "$code"
code=$(req PUT "/users/$(req GET /auth/me "$CAROL" >/dev/null; jqr .id)/roles" "$CAROL" '{"role_ids":[]}')
check "carol, now the LAST admin, cannot self-demote -> 409" 409 "$code"

echo
echo "======================================"
echo "  PASSED: $pass   FAILED: $fail"
echo "======================================"
[ "$fail" -eq 0 ]
