#!/usr/bin/env bash
# End-to-end check of the sign-in journey against the deployed stack, through
# the real ingress with real cookies - no mocks. Run from WSL:
#
#   deploy/scripts/smoke-test.sh
#
# It registers a throwaway account, then proves:
#   1. register -> sign in -> an authenticated session at PASSWORD assurance
#   2. two-step verification can be turned on (on the Authorization Server's page)
#   3. afterwards a password ALONE is refused
#   4. password + code signs in, and the session reports MFA assurance
#   5. replaying the same code is refused
#   6. sign-out ends the session
# Exits non-zero on the first thing that is not as expected.
set -uo pipefail
cd "$(dirname "$0")/../.."

APP="${APP_URL:-https://zerotrust.localtest.me:8443}"
AUTH="${AUTH_URL:-https://auth.zerotrust.localtest.me:8443}"
CA="${CA_CERT:-deploy/.local/zero-trust-ca.crt}"
JAR="$(mktemp)"; trap 'rm -f "$JAR"' EXIT
EMAIL="smoke$RANDOM$RANDOM@example.com"
PASSWORD="smoke test passphrase $RANDOM"
FAILS=0

c() { curl -s --cacert "$CA" -b "$JAR" -c "$JAR" "$@"; }
check() { # <description> <actual> <expected substring>
  if [[ "$2" == *"$3"* ]]; then printf '  ok    %s\n' "$1"
  else printf '  FAIL  %s\n        expected to contain: %s\n        got: %s\n' "$1" "$3" "${2:0:240}"; FAILS=$((FAILS+1)); fi
}
refute() { # <description> <actual> <substring that must NOT appear>
  if [[ "$2" != *"$3"* ]]; then printf '  ok    %s\n' "$1"
  else printf '  FAIL  %s\n        must not contain: %s\n        got: %s\n' "$1" "$3" "${2:0:240}"; FAILS=$((FAILS+1)); fi
}
xsrf() { grep XSRF-TOKEN "$JAR" | awk '{print $7}' | tail -1; }
totp() { python3 - "$1" <<'PY'
import sys,hmac,hashlib,struct,time,base64
key=base64.b32decode(sys.argv[1].replace(" ","").upper()+"="*(-len(sys.argv[1])%8))
msg=struct.pack(">Q",int(time.time())//30)
h=hmac.new(key,msg,hashlib.sha1).digest(); o=h[-1]&15
print("%06d"%((struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%1000000))
PY
}
field() { sed -n "s/.*name=\"$1\"[^>]*value=\"\([^\"]*\)\".*/\1/p" | head -1; }

# Sign in through the whole OAuth flow and print the resulting /api/session.
sign_in() { # <email> <password> [otp]
  local loc page csrf
  loc=$(c -o /dev/null -w '%{redirect_url}' "$APP/oauth2/authorization/zero-trust-web")
  loc=$(c -o /dev/null -w '%{redirect_url}' "$loc")                       # -> /oauth2/login
  page=$(c "$loc"); csrf=$(echo "$page" | field _csrf)
  loc=$(c -o /dev/null -w '%{redirect_url}' -X POST "$AUTH/oauth2/login" \
        --data-urlencode "username=$1" --data-urlencode "password=$2" --data-urlencode "otp=${3:-}" \
        --data-urlencode "_csrf=$csrf")
  if [[ "$loc" == *"error"* || -z "$loc" ]]; then c "$APP/api/session"; return; fi
  loc=$(c -o /dev/null -w '%{redirect_url}' "$loc")                       # -> BFF callback with code
  c -o /dev/null "$loc"
  c "$APP/api/session"
}

echo "1. register and sign in with a password"
c "$APP/api/session" >/dev/null
out=$(c -X POST "$APP/api/auth/register" -H "X-XSRF-TOKEN: $(xsrf)" -H 'Content-Type: application/json' \
      -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"displayName\":\"Smoke\"}")
check "account created" "$out" '"email"'
session=$(sign_in "$EMAIL" "$PASSWORD")
check "authenticated" "$session" '"authenticated":true'
check "reports password-only assurance" "$session" '"authenticationLevel":"PASSWORD"'
check "offers the two-step setup link" "$session" '/oauth2/account/mfa'

echo "2. turn on two-step verification (hosted on the Authorization Server)"
page=$(c "$AUTH/oauth2/account/mfa")
check "setup page offered" "$page" '/oauth2/account/mfa/start'
page=$(c -X POST "$AUTH/oauth2/account/mfa/start" --data-urlencode "_csrf=$(echo "$page" | field _csrf)")
secret=$(echo "$page" | sed -n 's/.*<code>\([A-Z2-7 ]*\)<\/code>.*/\1/p' | head -1)
check "secret shown on that page" "${secret:+yes}" 'yes'
code=$(totp "$secret")
page=$(c -X POST "$AUTH/oauth2/account/mfa/activate" --data-urlencode "_csrf=$(echo "$page" | field _csrf)" --data-urlencode "code=$code")
check "two-step verification is on" "$page" 'is on'
check "the user was signed out here" "$page" 'signed out'
: > "$JAR"

echo "3. a password alone is now refused"
session=$(sign_in "$EMAIL" "$PASSWORD")
check "no session from password alone" "$session" '"authenticated":false'
session=$(sign_in "$EMAIL" "$PASSWORD" "000000")
check "no session from a wrong code" "$session" '"authenticated":false'

echo "4. password + code signs in at MFA assurance"
: > "$JAR"
code=$(totp "$secret")
session=$(sign_in "$EMAIL" "$PASSWORD" "$code")
check "authenticated" "$session" '"authenticated":true'
check "reports MFA assurance" "$session" '"authenticationLevel":"MFA"'
refute "no setup nudge needed" "$session" '"authenticationLevel":"PASSWORD"'

echo "5. sign out"
out=$(c -X POST "$APP/api/session/logout" -H "X-XSRF-TOKEN: $(xsrf)")
check "logged out" "$out" '"loggedOut":true'
check "session is gone" "$(c "$APP/api/session")" '"authenticated":false'

echo "6. the same code cannot be replayed"
: > "$JAR"
session=$(sign_in "$EMAIL" "$PASSWORD" "$code")
check "replayed code refused" "$session" '"authenticated":false'

echo
if [ "$FAILS" -eq 0 ]; then echo "smoke test passed"; else echo "smoke test FAILED ($FAILS check(s))"; exit 1; fi
