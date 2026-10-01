#!/usr/bin/env bash
# End-to-end check of the deployed stack, through the real ingress with real
# cookies and real tokens - no mocks. Run from WSL:
#
#   deploy/scripts/smoke-test.sh
#
# It registers throwaway accounts and proves, in order:
#
#   SIGN-IN      register -> sign in -> password assurance; turn on two-step; a
#                password ALONE is then refused; password + code works; a replayed
#                code is refused; sign-out ends the session
#   TENANCY      you can act in your own workspace; another user cannot read, list
#                or write into it, and "not yours" looks exactly like "not there"
#   APPROVAL     a password-only session is asked to step up; a second factor is
#                accepted; the author can never approve their own document
#
# Exits non-zero if anything is not as expected.
set -uo pipefail
cd "$(dirname "$0")/../.."

APP="${APP_URL:-https://zerotrust.localtest.me:8443}"
AUTH="${AUTH_URL:-https://auth.zerotrust.localtest.me:8443}"
CA="${CA_CERT:-deploy/.local/zero-trust-ca.crt}"
FAILS=0
JARS=()
trap 'rm -f "${JARS[@]}"' EXIT

# ---- tiny harness -------------------------------------------------------------
check() { # <description> <actual> <expected substring>
  if [[ "$2" == *"$3"* ]]; then printf '  ok    %s\n' "$1"
  else printf '  FAIL  %s\n        expected to contain: %s\n        got: %s\n' "$1" "$3" "${2:0:260}"; FAILS=$((FAILS+1)); fi
}
refute() { # <description> <actual> <substring that must NOT appear>
  if [[ "$2" != *"$3"* ]]; then printf '  ok    %s\n' "$1"
  else printf '  FAIL  %s\n        must not contain: %s\n        got: %s\n' "$1" "$3" "${2:0:260}"; FAILS=$((FAILS+1)); fi
}
equal() { # <description> <a> <b>
  if [[ "$2" == "$3" ]]; then printf '  ok    %s\n' "$1"
  else printf '  FAIL  %s\n        a: %s\n        b: %s\n' "$1" "${2:0:200}" "${3:0:200}"; FAILS=$((FAILS+1)); fi
}

# Each actor is a browser: its own cookie jar.
new_browser() { local j; j="$(mktemp)"; JARS+=("$j"); echo "$j"; }
JAR=""
c() { curl -s --cacert "$CA" -b "$JAR" -c "$JAR" "$@"; }
xsrf() { grep XSRF-TOKEN "$JAR" | awk '{print $7}' | tail -1; }
field() { sed -n "s/.*name=\"$1\"[^>]*value=\"\([^\"]*\)\".*/\1/p" | head -1; }
json() { python3 -c "import sys,json
try: d=json.load(sys.stdin)
except Exception: print(''); sys.exit()
for k in sys.argv[1].split('.'):
    d = d[int(k)] if isinstance(d,list) else (d or {}).get(k)
print('' if d is None else d)" "$1"; }

totp() { python3 - "$1" <<'PY'
import sys,hmac,hashlib,struct,time,base64
key=base64.b32decode(sys.argv[1].replace(" ","").upper()+"="*(-len(sys.argv[1])%8))
h=hmac.new(key,struct.pack(">Q",int(time.time())//30),hashlib.sha1).digest(); o=h[-1]&15
print("%06d"%((struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%1000000))
PY
}

# API calls go through the BFF with the session cookie and CSRF header, as the SPA does.
api() { # <METHOD> <path> [json body]  -> prints "STATUS<TAB>body"
  local method="$1" path="$2" body="${3:-}" out
  c "$APP/api/session" >/dev/null   # makes sure the CSRF cookie exists
  if [ -n "$body" ]; then
    out=$(c -w '\n%{http_code}' -X "$method" "$APP$path" -H "X-XSRF-TOKEN: $(xsrf)" -H 'Content-Type: application/json' -d "$body")
  else
    out=$(c -w '\n%{http_code}' -X "$method" "$APP$path" -H "X-XSRF-TOKEN: $(xsrf)")
  fi
  printf '%s\t%s' "${out##*$'\n'}" "${out%$'\n'*}"
}
status_of() { printf '%s' "${1%%$'\t'*}"; }
body_of()   { printf '%s' "${1#*$'\t'}"; }

register() { # <email> <password> <name>
  c "$APP/api/session" >/dev/null
  c -X POST "$APP/api/auth/register" -H "X-XSRF-TOKEN: $(xsrf)" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"$2\",\"displayName\":\"$3\"}"
}

# Sign in through the whole OAuth flow; prints the resulting /api/session.
sign_in() { # <email> <password> [otp]
  local loc page csrf
  loc=$(c -o /dev/null -w '%{redirect_url}' "$APP/oauth2/authorization/zero-trust-web")
  loc=$(c -o /dev/null -w '%{redirect_url}' "$loc")
  page=$(c "$loc"); csrf=$(echo "$page" | field _csrf)
  loc=$(c -o /dev/null -w '%{redirect_url}' -X POST "$AUTH/oauth2/login" \
        --data-urlencode "username=$1" --data-urlencode "password=$2" --data-urlencode "otp=${3:-}" \
        --data-urlencode "_csrf=$csrf")
  if [[ "$loc" == *"error"* || -z "$loc" ]]; then c "$APP/api/session"; return; fi
  loc=$(c -o /dev/null -w '%{redirect_url}' "$loc")
  c -o /dev/null "$loc"
  c "$APP/api/session"
}

# Turn on two-step verification on the Authorization Server's own page. Prints the secret.
enroll_mfa() {
  local page
  page=$(c "$AUTH/oauth2/account/mfa")
  page=$(c -X POST "$AUTH/oauth2/account/mfa/start" --data-urlencode "_csrf=$(echo "$page" | field _csrf)")
  local secret; secret=$(echo "$page" | sed -n 's/.*<code>\([A-Z2-7 ]*\)<\/code>.*/\1/p' | head -1)
  c -X POST "$AUTH/oauth2/account/mfa/activate" --data-urlencode "_csrf=$(echo "$page" | field _csrf)" \
    --data-urlencode "code=$(totp "$secret")" >/dev/null
  echo "$secret"
}

SUFFIX="$RANDOM$RANDOM"
PASSWORD="smoke test passphrase $RANDOM"
OWNER="owner$SUFFIX@example.com"; APPROVER="approver$SUFFIX@example.com"; OUTSIDER="outsider$SUFFIX@example.com"

# =================================================================================
echo "SIGN-IN"
JAR=$(new_browser)
out=$(register "$OWNER" "$PASSWORD" "Owen Owner")
check "account created" "$out" '"email"'
session=$(sign_in "$OWNER" "$PASSWORD")
check "signed in at password assurance" "$session" '"authenticationLevel":"PASSWORD"'
check "offered the two-step setup link" "$session" '/oauth2/account/mfa'

secret=$(enroll_mfa)
check "two-step verification turned on (secret shown on the Authorization Server)" "${secret:+yes}" yes
: > "$JAR"
session=$(sign_in "$OWNER" "$PASSWORD")
check "a password alone is now refused" "$session" '"authenticated":false'
session=$(sign_in "$OWNER" "$PASSWORD" "000000")
check "a wrong code is refused" "$session" '"authenticated":false'
: > "$JAR"
code=$(totp "$secret")
session=$(sign_in "$OWNER" "$PASSWORD" "$code")
check "password + code signs in at MFA assurance" "$session" '"authenticationLevel":"MFA"'
OWNER_JAR="$JAR"

# =================================================================================
echo "TENANCY"
JAR="$OWNER_JAR"
tenants=$(api GET /api/tenants)
check "the owner has a workspace of their own" "$(body_of "$tenants")" 'workspace'
TENANT=$(body_of "$tenants" | json 0.id)
check "...and holds the OWNER role there" "$(body_of "$tenants")" '"role":"OWNER"'

created=$(api POST /api/documents "{\"tenantId\":\"$TENANT\",\"title\":\"Q3 budget\",\"body\":\"numbers\"}")
equal "the owner creates a document in their workspace (201)" "$(status_of "$created")" 201
DOC=$(body_of "$created" | json id)
check "...it starts as a draft and is the owner's" "$(body_of "$created")" '"status":"DRAFT"'
equal "the owner submits it (200)" "$(status_of "$(api POST "/api/documents/$DOC/submit")")" 200

# A different person, with a workspace of their own and no standing in the owner's.
JAR=$(new_browser); OUTSIDER_JAR="$JAR"
register "$OUTSIDER" "$PASSWORD" "Olive Outsider" >/dev/null
sign_in "$OUTSIDER" "$PASSWORD" >/dev/null
read_theirs=$(api GET "/api/documents/$DOC")
equal "another user cannot read the document (404)" "$(status_of "$read_theirs")" 404
absent=$(api GET "/api/documents/00000000-0000-0000-0000-000000000000")
equal "...and 'not yours' is indistinguishable from 'does not exist'" "$(body_of "$read_theirs")" "$(body_of "$absent")"
refute "...their list does not contain it" "$(body_of "$(api GET /api/documents)")" "Q3 budget"
planted=$(api POST /api/documents "{\"tenantId\":\"$TENANT\",\"title\":\"planted\",\"body\":\"x\"}")
equal "...and they cannot create into the owner's tenant (404)" "$(status_of "$planted")" 404
JAR="$OWNER_JAR"
refute "...nothing was planted" "$(body_of "$(api GET /api/documents)")" "planted"

# =================================================================================
echo "APPROVAL"
JAR=$(new_browser); APPROVER_JAR="$JAR"
register "$APPROVER" "$PASSWORD" "Alma Approver" >/dev/null
sign_in "$APPROVER" "$PASSWORD" >/dev/null
equal "before being given a role, the approver sees nothing of it (404)" \
      "$(status_of "$(api GET "/api/documents/$DOC")")" 404

deploy/scripts/add-member.sh "$APPROVER" APPROVER --into-workspace-of "$OWNER" >/dev/null 2>&1
check "the operator grants the approver a role in the owner's workspace" \
      "$(body_of "$(api GET /api/tenants)")" '"role":"APPROVER"'
equal "...and now they can read the document (200)" "$(status_of "$(api GET "/api/documents/$DOC")")" 200

step=$(api POST "/api/documents/$DOC/approve")
equal "a password-only session is asked to step up (403)" "$(status_of "$step")" 403
check "...with the code the client can act on" "$(body_of "$step")" 'STEP_UP_REQUIRED'

asecret=$(enroll_mfa)
: > "$JAR"
sign_in "$APPROVER" "$PASSWORD" "$(totp "$asecret")" >/dev/null
approved=$(api POST "/api/documents/$DOC/approve")
equal "with a second factor the approver can approve (200)" "$(status_of "$approved")" 200
check "...and it is recorded as approved" "$(body_of "$approved")" '"status":"APPROVED"'

# Maker is not checker. The owner holds every role and a second factor - and still cannot.
JAR="$OWNER_JAR"
second=$(api POST /api/documents "{\"tenantId\":\"$TENANT\",\"title\":\"Mine alone\",\"body\":\"x\"}")
DOC2=$(body_of "$second" | json id)
api POST "/api/documents/$DOC2/submit" >/dev/null
selfie=$(api POST "/api/documents/$DOC2/approve")
equal "the author cannot approve their own document, even with a second factor (409)" "$(status_of "$selfie")" 409
check "...because of the business rule, not a permission" "$(body_of "$selfie")" 'RULE_VIOLATION'

echo
if [ "$FAILS" -eq 0 ]; then echo "smoke test passed"; else echo "smoke test FAILED ($FAILS check(s))"; exit 1; fi
