#!/usr/bin/env bash
# Grant a registered user a role in another user's workspace. Run from WSL:
#
#   deploy/scripts/add-member.sh <email> <ROLE> --into-workspace-of <owner-email>
#
#   ROLE is one of VIEWER, MEMBER, APPROVER, OWNER.
#
# This is an OPERATOR action. Everyone gets a workspace of their own on
# registration, and joining someone else's is a deliberate grant (ADR-SEC-015: no
# implicit membership). A tenant administrator API does not exist yet, so until it
# does this is the only way to put two people in one tenant - which is what
# maker-checker approval needs.
set -euo pipefail

usage() { echo "usage: $0 <email> <VIEWER|MEMBER|APPROVER|OWNER> --into-workspace-of <owner-email>" >&2; exit 2; }
[ "$#" -eq 4 ] && [ "$3" = "--into-workspace-of" ] || usage
EMAIL="$1"; ROLE="$2"; OWNER="$4"
case "$ROLE" in VIEWER|MEMBER|APPROVER|OWNER) ;; *) echo "unknown role: $ROLE" >&2; usage ;; esac

CONTEXT="k3d-${K3D_CLUSTER:-dev}"
K="kubectl --context ${CONTEXT} -n zero-trust"
ADMIN="$($K get secret zt-db -o jsonpath='{.data.username}' | base64 -d)"

# Variables, not string-built SQL: an email with a quote in it must not become SQL.
rows="$($K exec -i postgres-0 -- psql -v ON_ERROR_STOP=1 -U "$ADMIN" -d authdb -Atq \
        -v email="$EMAIL" -v owner="$OWNER" -v role="$ROLE" <<'SQL'
WITH granted AS (
  INSERT INTO subject_tenant_membership (user_id, tenant_id, role, granted_at)
  SELECT u.id, m.tenant_id, :'role', now()
  FROM users u,
       subject_tenant_membership m JOIN users o ON o.id = m.user_id
  WHERE lower(u.email) = lower(:'email')
    AND lower(o.email) = lower(:'owner')
    AND m.role = 'OWNER'
  ON CONFLICT (user_id, tenant_id) DO UPDATE SET role = EXCLUDED.role
  RETURNING 1)
SELECT count(*) FROM granted;
SQL
)"

if [ "$rows" = "0" ]; then
  echo "nothing granted: check that both emails are registered and the second has a workspace" >&2
  exit 1
fi
echo "granted $ROLE to $EMAIL in the workspace of $OWNER ($rows row)"
