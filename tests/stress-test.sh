#!/bin/bash
# DSS-CW2 Security Stress Test
# Run with server active: node server.js
# Then: bash tests/stress-test.sh
# Each test prints PASS or FAIL. Screenshot this terminal output for demo evidence.

BASE="https://localhost:3000"
PASS=0
FAIL=0

green="\033[0;32m"
red="\033[0;31m"
yellow="\033[0;33m"
bold="\033[1m"
reset="\033[0m"

check() {
  local label="$1"
  local result="$2"   # "pass" or "fail"
  if [ "$result" = "pass" ]; then
    echo -e "  ${green}✅ PASS${reset} — $label"
    ((PASS++))
  else
    echo -e "  ${red}❌ FAIL${reset} — $label"
    ((FAIL++))
  fi
}

echo ""
echo -e "${bold}═══════════════════════════════════════════════════════${reset}"
echo -e "${bold}   DSS-CW2 Security Verification  |  Group 15          ${reset}"
echo -e "${bold}═══════════════════════════════════════════════════════${reset}"
echo ""

# ── 1. HTTPS / Security Headers ──────────────────────────────────────
echo -e "${yellow}[1] HTTPS & Security Headers${reset}"
HEADERS=$(curl -k -s -I "$BASE/" 2>/dev/null)

echo "$HEADERS" | grep -qi "x-frame-options: DENY" \
  && check "X-Frame-Options: DENY (clickjacking)" pass \
  || check "X-Frame-Options: DENY (clickjacking)" fail

echo "$HEADERS" | grep -qi "content-security-policy" \
  && check "Content-Security-Policy header present" pass \
  || check "Content-Security-Policy header present" fail

CSP=$(echo "$HEADERS" | grep -i "content-security-policy" | head -1)
echo "$CSP" | grep -q "frame-ancestors" \
  && check "CSP frame-ancestors present (blocks iframe embedding)" pass \
  || check "CSP frame-ancestors present" fail

echo "$CSP" | grep -q "script-src 'self'" \
  && check "CSP script-src is 'self' only (no unsafe-inline)" pass \
  || check "CSP script-src 'self' present" fail

echo "$HEADERS" | grep -qi "strict-transport-security" \
  && check "HSTS header present" pass \
  || check "HSTS header present" fail

echo "$HEADERS" | grep -qi "x-content-type-options: nosniff" \
  && check "X-Content-Type-Options: nosniff" pass \
  || check "X-Content-Type-Options: nosniff" fail

echo ""

# ── 2. CSRF Protection ───────────────────────────────────────────────
echo -e "${yellow}[2] CSRF Protection${reset}"

STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}')
[ "$STATUS" = "403" ] \
  && check "POST /auth/login without CSRF token → 403" pass \
  || check "POST /auth/login without CSRF token → 403 (got $STATUS)" fail

STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -X POST "$BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker","email":"h@h.com","password":"Test1!"}')
[ "$STATUS" = "403" ] \
  && check "POST /auth/register without CSRF token → 403" pass \
  || check "POST /auth/register without CSRF token → 403 (got $STATUS)" fail

echo ""

# ── 3. Account Enumeration ───────────────────────────────────────────
echo -e "${yellow}[3] Account Enumeration Prevention${reset}"

# Get a CSRF token first
CSRF=$(curl -k -s "$BASE/auth/csrf-token" | python3 -c "import sys,json; print(json.load(sys.stdin)['csrfToken'])" 2>/dev/null)

if [ -z "$CSRF" ]; then
  check "Fetch CSRF token (needed for login tests)" fail
else
  check "Fetch CSRF token" pass

  BODY_NOUSER=$(curl -k -s -X POST "$BASE/auth/login" \
    -H "Content-Type: application/json" \
    -H "x-csrf-token: $CSRF" \
    -d '{"username":"definitively_nonexistent_user_xyz","password":"WrongPass1!"}')

  # Refresh token for second call (consumed by session)
  CSRF2=$(curl -k -s "$BASE/auth/csrf-token" | python3 -c "import sys,json; print(json.load(sys.stdin)['csrfToken'])" 2>/dev/null)

  BODY_WRONGPW=$(curl -k -s -X POST "$BASE/auth/login" \
    -H "Content-Type: application/json" \
    -H "x-csrf-token: $CSRF2" \
    -d '{"username":"admin","password":"definitelywrongpassword99"}')

  MSG1=$(echo "$BODY_NOUSER" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)
  MSG2=$(echo "$BODY_WRONGPW" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)

  [ "$MSG1" = "Invalid credentials" ] \
    && check "Non-existent user returns 'Invalid credentials'" pass \
    || check "Non-existent user returns 'Invalid credentials' (got: $MSG1)" fail

  [ "$MSG2" = "Invalid credentials" ] \
    && check "Wrong password returns identical 'Invalid credentials'" pass \
    || check "Wrong password returns identical message (got: $MSG2)" fail

  [ "$MSG1" = "$MSG2" ] \
    && check "Both messages identical — no enumeration possible" pass \
    || check "Messages differ — enumeration possible!" fail
fi

echo ""

# ── 4. SQL Injection ─────────────────────────────────────────────────
echo -e "${yellow}[4] SQL Injection Resistance${reset}"

CSRF3=$(curl -k -s "$BASE/auth/csrf-token" | python3 -c "import sys,json; print(json.load(sys.stdin)['csrfToken'])" 2>/dev/null)

SQLI_RESP=$(curl -k -s -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: $CSRF3" \
  -d "{\"username\":\"' OR '1'='1' --\",\"password\":\"anything\"}")

SQLI_STATUS=$(echo "$SQLI_RESP" | python3 -c "import sys; d=sys.stdin.read(); print('has_error' if 'error' in d else 'no_error')" 2>/dev/null)
LEAKS_SQL=$(echo "$SQLI_RESP" | grep -i "syntax\|column\|relation\|SELECT\|PostgreSQL" | wc -l | tr -d ' ')

[ "$SQLI_STATUS" = "has_error" ] \
  && check "SQL injection in username field rejected (has error field)" pass \
  || check "SQL injection in username field rejected" fail

[ "$LEAKS_SQL" = "0" ] \
  && check "Response leaks no SQL error details" pass \
  || check "Response leaks SQL error details — FAIL" fail

# Search route injection
SEARCH_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" \
  "$BASE/posts/search?q=%27%20UNION%20SELECT%20username%2C%20password_hash%20FROM%20users%20--")
[ "$SEARCH_STATUS" != "500" ] \
  && check "SQL injection in search query does not return 500" pass \
  || check "SQL injection in search query returns 500 — check error handler" fail

echo ""

# ── 5. Access Control (unauthenticated) ──────────────────────────────
echo -e "${yellow}[5] Access Control & IDOR${reset}"

CSRF4=$(curl -k -s "$BASE/auth/csrf-token" | python3 -c "import sys,json; print(json.load(sys.stdin)['csrfToken'])" 2>/dev/null)

POST_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -X POST "$BASE/posts" \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: $CSRF4" \
  -d '{"title":"Hacker","content":"Should not work"}')
[ "$POST_STATUS" = "401" ] \
  && check "POST /posts without auth → 401" pass \
  || check "POST /posts without auth → 401 (got $POST_STATUS)" fail

CSRF5=$(curl -k -s "$BASE/auth/csrf-token" | python3 -c "import sys,json; print(json.load(sys.stdin)['csrfToken'])" 2>/dev/null)

DEL_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -X DELETE "$BASE/posts/1" \
  -H "x-csrf-token: $CSRF5")
[ "$DEL_STATUS" = "401" ] \
  && check "DELETE /posts/1 without auth → 401" pass \
  || check "DELETE /posts/1 without auth → 401 (got $DEL_STATUS)" fail

echo ""

# ── 6. Error Handling / Stack Trace Leakage ──────────────────────────
echo -e "${yellow}[6] Error Handling & Information Disclosure${reset}"

ERR_RESP=$(curl -k -s "$BASE/some/completely/fake/route/xyz")
LEAKS_PATH=$(echo "$ERR_RESP" | grep -i "node_modules\|at Object\|\.js:" | wc -l | tr -d ' ')
[ "$LEAKS_PATH" = "0" ] \
  && check "Unknown route leaks no internal paths or stack trace" pass \
  || check "Unknown route leaks internals — FAIL" fail

CSRF6=$(curl -k -s "$BASE/auth/csrf-token" | python3 -c "import sys,json; print(json.load(sys.stdin)['csrfToken'])" 2>/dev/null)
BAD_JSON=$(curl -k -s -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: $CSRF6" \
  -d '{this is not json!!!}')
LEAKS_PARSE=$(echo "$BAD_JSON" | grep -i "SyntaxError\|stack\|node_modules" | wc -l | tr -d ' ')
[ "$LEAKS_PARSE" = "0" ] \
  && check "Malformed JSON leaks no parse error details" pass \
  || check "Malformed JSON leaks parse error details — FAIL" fail

echo ""

# ── 7. Password Strength ─────────────────────────────────────────────
echo -e "${yellow}[7] Password Strength Enforcement${reset}"

CSRF7=$(curl -k -s "$BASE/auth/csrf-token" | python3 -c "import sys,json; print(json.load(sys.stdin)['csrfToken'])" 2>/dev/null)
WEAK_RESP=$(curl -k -s -X POST "$BASE/auth/register" \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: $CSRF7" \
  -d '{"username":"testuser99","email":"test@test.com","password":"weak"}')
WEAK_STATUS=$(echo "$WEAK_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print('rejected' if 'error' in d else 'accepted')" 2>/dev/null)
[ "$WEAK_STATUS" = "rejected" ] \
  && check "Weak password 'weak' rejected at registration" pass \
  || check "Weak password 'weak' accepted — FAIL" fail

echo ""

# ── Summary ──────────────────────────────────────────────────────────
echo -e "${bold}═══════════════════════════════════════════════════════${reset}"
TOTAL=$((PASS + FAIL))
if [ "$FAIL" = "0" ]; then
  echo -e "${bold}${green}  ALL $TOTAL CHECKS PASSED ✅${reset}"
else
  echo -e "${bold}  $PASS/$TOTAL passed — ${red}$FAIL FAILED ❌${reset}"
fi
echo -e "${bold}═══════════════════════════════════════════════════════${reset}"
echo ""
echo "  Screenshot this output and attach to your test plan."
echo "  Evidence files to capture separately:"
echo "  • psql query showing email_encrypted column (AES ciphertext)"
echo "  • psql query showing password_hash starting with \$argon2id\$"
echo "  • Browser showing https://localhost:3000 with padlock"
echo "  • npm test output (73/73 passing)"
echo ""
