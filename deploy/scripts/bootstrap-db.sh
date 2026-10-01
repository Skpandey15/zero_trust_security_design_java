#!/usr/bin/env bash
# Create the Resource Server's database role and schema, with least privilege
# (ADR-SEC-019). Run from WSL; idempotent; run by deploy-local.sh and safe to
# re-run (it also re-applies the grants and resets the password to the secret's).
#
# Why a separate role: a compromised Resource Server must not hold the keys to the
# identity database. resource_app
#   - OWNS the `app` schema (its own tables, via Flyway), and
#   - can SELECT exactly two identity tables - tenants and subject_tenant_membership -
#     because membership is how it decides who may act where, and
#   - can do nothing else in the identity schema: no users, no credentials, no tokens.
#
# This is a PLATFORM step, not a pipeline step: the pipeline's deployer cannot read
# secrets or run SQL, and should not be able to grant itself database rights.
set -euo pipefail

CONTEXT="k3d-${K3D_CLUSTER:-dev}"
K="kubectl --context ${CONTEXT} -n zero-trust"

PW="$($K get secret zt-resource-db -o jsonpath='{.data.password}' | base64 -d)"
ADMIN="$($K get secret zt-db -o jsonpath='{.data.username}' | base64 -d)"
[ -n "$PW" ] || { echo "secret zt-resource-db has no password" >&2; exit 1; }

# The membership tables are created by the Authorization Server's migrations, so
# they only exist once it has started. Wait for them rather than fail.
echo "waiting for the identity schema (created by the Authorization Server)"
for _ in $(seq 1 90); do
  if $K exec postgres-0 -- psql -U "$ADMIN" -d authdb -Atc \
       "select to_regclass('public.subject_tenant_membership') is not null and to_regclass('public.tenants') is not null" 2>/dev/null | grep -q '^t$'; then
    ready=1; break
  fi
  sleep 3
done
[ "${ready:-0}" = "1" ] || { echo "the identity schema never appeared - is the Authorization Server running?" >&2; exit 1; }

$K exec -i postgres-0 -- psql -v ON_ERROR_STOP=1 -U "$ADMIN" -d authdb -v pw="$PW" <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'resource_app') THEN
    CREATE ROLE resource_app LOGIN;
  END IF;
END
$$;
ALTER ROLE resource_app PASSWORD :'pw';

-- Start from nothing in the identity schema, then grant back the minimum.
REVOKE ALL ON SCHEMA public FROM resource_app;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM resource_app;
GRANT USAGE ON SCHEMA public TO resource_app;
GRANT SELECT ON public.subject_tenant_membership, public.tenants TO resource_app;

-- Its own schema, owned by it, so Flyway can migrate it and nothing else can.
CREATE SCHEMA IF NOT EXISTS app AUTHORIZATION resource_app;
ALTER ROLE resource_app SET search_path = app;
SQL

echo "resource_app is ready: owns schema app, can read tenants and subject_tenant_membership only"
