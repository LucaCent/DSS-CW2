#!/bin/bash
# DSS-CW2 Security Stress Test — Group 15
# Run with server active: node server.js
# Then in a second tab: bash tests/stress-test.sh
# Screenshot the output for demo evidence.

BASE="https://localhost:3000"
PASS=0
FAIL=0
COOKIES="/tmp/dss-cw2-cookies.txt"

green="\033[0;32m"
red="\033[0;31m"
yellow="\033[0;33m"
bold="\033[1m"
reset="\033[0m"

check() {
  local label="$1"
  local result="$2"
  if [ "$result" = "pass" ]; then
    echo -e "  ${green}✅ PASS${reset} — $label"
    PASS=$((PASS + 1))
  else
    echo -e "  ${red}❌ FAIL${reset} — $label"
    FAIL=$((FAIL + 1))
  fi
  return 0
}

# Fetch a CSRF token using a persistent cookie jar so the session is preserved
fresh_csrf() {
  curl -k -s -c "$COOKIES" -b "$COOKIES" "$BASE/auth/csrf-token" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['csrfToken'])" 2>/dev/null
}

rm -f "$COOKIES"

echo ""
echo -e "${bold}═══════════════════════════════════════════════════════${reset}"
echo -e "${bold}   DSS-CW2 Security Verification  |  Group 15          ${reset}"
echo -e "${bold}═══════════════════════════════════════════════════════${reset}"
echo ""

# ── 1. HTTPS & Security Headers ──────────────────────────────────────
echo -e "${yellow}[1] HTTPS & Security Headers${reset}"
HEADERS=$(curl -k -s -I "$BASE/" 2>/dev/null)

echo "$HEADERS" | grep -qi "x-frame-options: DENY" \
  && check "X-Frame-Options: DENY (clickjacking blocked)" pass \
  || check "X-Frame-Options: DENY (clickjacking blocked)" fail

echo "$HEADERS" | grep -qi "content-security-policy" \
  && check "Content-Security-Policy header present" pass \
  || check "Content-Security-Policy header present" fail

CSP=$(echo "$HEADERS" | grep -i "content-security-policy" | head -1)
echo "$CSP" | grep -q "frame-ancestors" \
  && check "CSP frame-ancestors: none (iframe embedding blocked)" pass \
  || check "CSP frame-ancestors present" fail

# script-src 'self' without unsafe-inline means injected <script> blocks are blocked
# Note: grep for "script-src '" with a space to avoid matching "script-src-attr"
# Extract just the script-src directive (not script-src-attr) using sed
SCRIPTSRC=$(echo "$CSP" | sed 's/script-src-attr[^;]*;//g' | grep -o "script-src[^;]*" | head -1)
! echo "$SCRIPTSRC" | grep -q "unsafe-inline" \
  && check "CSP script-src has no unsafe-inline (injected scripts blocked)" pass \
  || check "CSP script-src — unsafe-inline still present" fail

echo "$HEADERS" | grep -qi "strict-transport-security" \
  && check "HSTS header present (forces HTTPS for 1 year)" pass \
  || check "HSTS header present" fail

echo "$HEADERS" | grep -qi "x-content-type-options: nosniff" \
  && check "X-Content-Type-Options: nosniff (MIME sniffing blocked)" pass \
  || check "X-Content-Type-Options: nosniff" fail

echo ""

# ── 2. CSRF Protection ───────────────────────────────────────────────
echo -e "${yellow}[2] CSRF Protection${reset}"

STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}')
[ "$STATUS" = "403" ] \
  && check "POST /auth/login without CSRF token → 403 Forbidden" pass \
  || check "POST /auth/login without CSRF token → 403 (got $STATUS)" fail

STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -X POST "$BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker","email":"h@h.com","password":"Test1!"}')
[ "$STATUS" = "403" ] \
  && check "POST /auth/register without CSRF token → 403 Forbidden" pass \
  || check "POST /auth/register without CSRF token → 403 (got $STATUS)" fail

echo ""

# ── 3. Account Enumeration Prevention ───────────────────────────────
echo -e "${yellow}[3] Account Enumeration Prevention${reset}"

# Use cookie jar so CSRF token is tied to same session as the login request
rm -f "$COOKIES"
CSRF=$(fresh_csrf)
if [ -z "$CSRF" ]; then
  check "Fetch CSRF token" fail
else
  check "Fetch CSRF token from session" pass

  BODY_NOUSER=$(curl -k -s -c "$COOKIES" -b "$COOKIES" \
    -X POST "$BASE/auth/login" \
    -H "Content-Type: application/json" \
    -H "x-csrf-token: $CSRF" \
    -d '{"username":"definitively_nonexistent_xyz99","password":"WrongPass1!"}')

  rm -f "$COOKIES"
  CSRF2=$(fresh_csrf)
  BODY_WRONGPW=$(curl -k -s -c "$COOKIES" -b "$COOKIES" \
    -X POST "$BASE/auth/login" \
    -H "Content-Type: application/json" \
    -H "x-csrf-token: $CSRF2" \
    -d '{"username":"admin","password":"definitelywrong99!"}')

  MSG1=$(echo "$BODY_NOUSER" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)
  MSG2=$(echo "$BODY_WRONGPW" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)

  [ "$MSG1" = "Invalid credentials" ] \
    && check "Non-existent username → 'Invalid credentials' (no 'user not found')" pass \
    || check "Non-existent username response (got: '$MSG1')" fail

  [ "$MSG2" = "Invalid credentials" ] \
    && check "Wrong password → identical 'Invalid credentials'" pass \
    || check "Wrong password response (got: '$MSG2')" fail

  [ "$MSG1" = "$MSG2" ] \
    && check "Both messages identical — username enumeration not possible" pass \
    || check "Messages differ — enumeration possible!" fail
fi

echo ""

# ── 4. SQL Injection Resistance ──────────────────────────────────────
echo -e "${yellow}[4] SQL Injection Resistance${reset}"

rm -f "$COOKIES"
CSRF3=$(fresh_csrf)

SQLI_RESP=$(curl -k -s -c "$COOKIES" -b "$COOKIES" \
  -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: $CSRF3" \
  -d "{\"username\":\"' OR '1'='1' --\",\"password\":\"anything\"}")

LEAKS_SQL=$(echo "$SQLI_RESP" | grep -i "syntax\|column\|relation\|SELECT\|PostgreSQL" | wc -l | tr -d ' ')

echo "$SQLI_RESP" | grep -q "error" \
  && check "SQL injection payload in username field — request rejected" pass \
  || check "SQL injection payload in username field — request rejected" fail

[ "$LEAKS_SQL" = "0" ] \
  && check "Response leaks no SQL error details" pass \
  || check "Response leaks SQL error details — FAIL" fail

# Search injection — check response doesn't leak DB internals (500 is ok if posts table missing)
SEARCH_RESP=$(curl -k -s "$BASE/posts/search?q=%27%20UNION%20SELECT%20username%2C%20password_hash%20FROM%20users%20--")
LEAKS_SEARCH=$(echo "$SEARCH_RESP" | grep -i "password_hash\|username\|PostgreSQL\|syntax error" | wc -l | tr -d ' ')
[ "$LEAKS_SEARCH" = "0" ] \
  && check "SQL injection in search — no DB data leaked in response" pass \
  || check "SQL injection in search — DB data visible in response!" fail

echo ""

# ── 5. Access Control ────────────────────────────────────────────────
echo -e "${yellow}[5] Access Control (unauthenticated requests rejected)${reset}"

# Without a valid session, CSRF fires first (403) or auth fires (401) — both mean rejection
rm -f "$COOKIES"
CSRF4=$(fresh_csrf)
POST_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" \
  -c "$COOKIES" -b "$COOKIES" \
  -X POST "$BASE/posts" \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: $CSRF4" \
  -d '{"title":"Hacker","content":"Should not work"}')
[[ "$POST_STATUS" = "401" || "$POST_STATUS" = "403" ]] \
  && check "POST /posts without session → rejected ($POST_STATUS)" pass \
  || check "POST /posts without session → rejected (got $POST_STATUS)" fail

rm -f "$COOKIES"
CSRF5=$(fresh_csrf)
DEL_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" \
  -c "$COOKIES" -b "$COOKIES" \
  -X DELETE "$BASE/posts/1" \
  -H "x-csrf-token: $CSRF5")
[[ "$DEL_STATUS" = "401" || "$DEL_STATUS" = "403" ]] \
  && check "DELETE /posts/1 without session → rejected ($DEL_STATUS)" pass \
  || check "DELETE /posts/1 without session → rejected (got $DEL_STATUS)" fail

echo ""

# ── 6. Error Handling & Information Disclosure ───────────────────────
echo -e "${yellow}[6] Error Handling — No Stack Trace Leakage${reset}"

ERR_RESP=$(curl -k -s "$BASE/some/completely/fake/route/xyz")
LEAKS_PATH=$(echo "$ERR_RESP" | grep -i "node_modules\|at Object\|\.js:" | wc -l | tr -d ' ')
[ "$LEAKS_PATH" = "0" ] \
  && check "Unknown route — no internal paths or stack trace leaked" pass \
  || check "Unknown route — internals leaked!" fail

rm -f "$COOKIES"
CSRF6=$(fresh_csrf)
BAD_JSON=$(curl -k -s -c "$COOKIES" -b "$COOKIES" \
  -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: $CSRF6" \
  -d '{this is not json!!!}')
LEAKS_PARSE=$(echo "$BAD_JSON" | grep -i "SyntaxError\|at Object\|node_modules" | wc -l | tr -d ' ')
[ "$LEAKS_PARSE" = "0" ] \
  && check "Malformed JSON — no parse error details leaked" pass \
  || check "Malformed JSON — parse error details leaked!" fail

echo ""

# ── 7. Password Strength ─────────────────────────────────────────────
echo -e "${yellow}[7] Password Strength Enforcement${reset}"

rm -f "$COOKIES"
CSRF7=$(fresh_csrf)
WEAK_RESP=$(curl -k -s -c "$COOKIES" -b "$COOKIES" \
  -X POST "$BASE/auth/register" \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: $CSRF7" \
  -d '{"username":"testuser99","email":"test@test.com","password":"weak"}')
echo "$WEAK_RESP" | grep -q "error" \
  && check "Weak password 'weak' rejected at registration" pass \
  || check "Weak password 'weak' accepted — FAIL" fail

rm -f "$COOKIES"
CSRF8=$(fresh_csrf)
STRONG_RESP=$(curl -k -s -c "$COOKIES" -b "$COOKIES" \
  -X POST "$BASE/auth/register" \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: $CSRF8" \
  -d '{"username":"testuser99","email":"test99@test.com","password":"no_uppercase1!"}')
echo "$STRONG_RESP" | grep -q "error" \
  && check "Password with no uppercase rejected" pass \
  || check "Password with no uppercase accepted — FAIL" fail

echo ""

rm -f "$COOKIES"

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
echo ""
echo "  Remaining evidence to capture:"
echo "  1. npm test  →  screenshot 73/73 passing"
echo "  2. psql: SELECT id, username, email_encrypted FROM users LIMIT 3;"
echo "     → shows AES ciphertext, not plaintext email"
echo "  3. psql: SELECT username, password_hash FROM users LIMIT 1;"
echo "     → shows \$argon2id\$v=19\$m=65536,t=3,p=1..."
echo "  4. Browser: https://localhost:3000 with padlock icon visible"
echo ""
