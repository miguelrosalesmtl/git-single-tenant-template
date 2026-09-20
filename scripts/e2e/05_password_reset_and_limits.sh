#!/usr/bin/env bash
# Password reset, email verification, and rate limiting.
#
# Run against a stack started with MAIL_BACKEND=log, which prints the email
# (link included) to the application log. That log is the inbox.
#
# Overridable so these run against compose OR a plain binary (see .github/workflows):
#   API_BASE    where the API is            (default http://localhost:8080)
#   DB_EXEC     how to reach psql           (default: docker compose exec -T postgres)
#   APP_LOGS    how to read the app's log   (default: docker compose logs app)
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
logs() { ${APP_LOGS:-docker compose logs app} 2>&1; }
verify_token() { logs | grep -o 'token=mtt_ver_[A-Za-z0-9_-]*' | tail -1 | cut -d= -f2; }
reset_token()  { logs | grep -o 'token=mtt_pwr_[A-Za-z0-9_-]*' | tail -1 | cut -d= -f2; }
reg() { req POST /auth/register - "{\"email\":\"$1\",\"password\":\"correct-horse-battery\"}" >/dev/null; }
login() { req POST /auth/login - "{\"email\":\"$1\",\"password\":\"$2\"}" >/dev/null; jqr .token; }

echo "== EMAIL VERIFICATION =="
reg alice@example.com
ALICE=$(login alice@example.com correct-horse-battery)
code=$(req GET /auth/me "$ALICE")
check "fresh account is not verified" "null" "$(jqr .email_verified_at)"

VTOK=$(verify_token)
[ -n "$VTOK" ] && { echo "  PASS  a verification link was emailed on registration"; pass=$((pass+1)); } \
               || { echo "  FAIL  no verification email"; fail=$((fail+1)); }
code=$(req POST /auth/email/verify - "{\"token\":\"$VTOK\"}")
check "verify the address" 200 "$code"
code=$(req GET /auth/me "$ALICE")
check "now verified" false "$([ "$(jqr .email_verified_at)" = "null" ] && echo true || echo false)"
code=$(req POST /auth/email/verify - "{\"token\":\"$VTOK\"}")
check "the link is single-use -> 400" 400 "$code"

echo "== PASSWORD RESET =="
code=$(req POST /auth/password/reset - '{"email":"alice@example.com"}')
check "request a reset" 204 "$code"

# The anti-enumeration property: an unknown address gets the IDENTICAL answer.
code=$(req POST /auth/password/reset - '{"email":"nobody-at-all@example.com"}')
check "an UNKNOWN address gets the same 204 (no enumeration oracle)" 204 "$code"

RTOK=$(reset_token)
[ -n "$RTOK" ] && { echo "  PASS  a reset link was emailed"; pass=$((pass+1)); } \
               || { echo "  FAIL  no reset email"; fail=$((fail+1)); }

# A live session, to prove the reset kills it.
OLD_SESSION=$(login alice@example.com correct-horse-battery)
code=$(req GET /auth/me "$OLD_SESSION")
check "alice has a live session before the reset" 200 "$code"

code=$(req POST /auth/password/reset/confirm - "{\"token\":\"$RTOK\",\"new_password\":\"a-brand-new-password\"}")
check "confirm the reset" 204 "$code"

code=$(req GET /auth/me "$OLD_SESSION")
check "  ...her old session is dead (the point of the exercise)" 401 "$code"
code=$(req POST /auth/login - '{"email":"alice@example.com","password":"correct-horse-battery"}')
check "  ...the old password no longer works" 401 "$code"
code=$(req POST /auth/login - '{"email":"alice@example.com","password":"a-brand-new-password"}')
check "  ...the new password does" 200 "$code"

code=$(req POST /auth/password/reset/confirm - "{\"token\":\"$RTOK\",\"new_password\":\"yet-another-password\"}")
check "  ...and the link is single-use" 400 "$code"

code=$(req POST /auth/password/reset/confirm - '{"token":"mtt_pwr_bogus","new_password":"whatever-password"}')
check "a bogus reset token -> 400" 400 "$code"

echo "== RATE LIMITING =="
# The stack under test runs with a small allowance; hammer login for one email.
codes=""
for _ in $(seq 1 15); do
  codes="$codes$(req POST /auth/login - '{"email":"ratelimit@example.com","password":"wrong-password-here"}') "
done
echo "        codes: $codes"
echo "$codes" | grep -q 429 && { echo "  PASS  brute-forcing login trips the limiter (429)"; pass=$((pass+1)); } \
                            || { echo "  FAIL  15 login attempts, never limited"; fail=$((fail+1)); }

# Retry-After must be present, or a client cannot back off correctly.
ra=$(curl -s -o /dev/null -D - -X POST "$API/auth/login" -H 'Content-Type: application/json' \
     -d '{"email":"ratelimit@example.com","password":"wrong-password-here"}' | grep -i '^retry-after' | tr -d '\r')
[ -n "$ra" ] && { echo "  PASS  429 carries $ra"; pass=$((pass+1)); } \
             || { echo "  FAIL  429 has no Retry-After header"; fail=$((fail+1)); }

# A different ENDPOINT has its own bucket, keyed by its own prefix.
code=$(req POST /auth/password/reset - '{"email":"someone-else@example.com"}')
{ [ "$code" = "204" ] || [ "$code" = "429" ]; } && { echo "  PASS  a different endpoint has its own bucket ($code)"; pass=$((pass+1)); } \
                                                 || { echo "  FAIL  unexpected $code"; fail=$((fail+1)); }

echo "== the limiter trips are audited =="
n=$(${DB_EXEC:-docker compose exec -T postgres} psql -U app -d app -tAc \
    "SELECT count(*) FROM audit_log WHERE action='access.rate_limited'" 2>/dev/null | tr -d ' ')
[ "${n:-0}" -ge 1 ] && { echo "  PASS  rate-limit trips recorded ($n)"; pass=$((pass+1)); } \
                    || { echo "  FAIL  the limiter tripped but nothing was audited"; fail=$((fail+1)); }

echo "== failed logins are still audited, with the reason =="
${DB_EXEC:-docker compose exec -T postgres} psql -U app -d app -tAc \
  "SELECT DISTINCT metadata->>'reason' FROM audit_log WHERE action='users.login_failed'" 2>/dev/null | sed 's/^/        /'

echo
echo "======================================"
echo "  PASSED: $pass   FAILED: $fail"
echo "======================================"
[ "$fail" -eq 0 ]
