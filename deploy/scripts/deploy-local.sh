#!/usr/bin/env bash
# Build, load and deploy the platform to the local k3d cluster.
# Run from WSL:   deploy/scripts/deploy-local.sh
#
# Idempotent. Re-running rebuilds images and rolls the workloads; existing
# secrets (and therefore the signing key and DB password) are never rotated
# as a side effect.
set -euo pipefail
cd "$(dirname "$0")/../.."

CLUSTER="${K3D_CLUSTER:-dev}"
CONTEXT="k3d-${CLUSTER}"
NS=zero-trust
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.21.2}"

log() { printf '\n==> %s\n' "$*"; }

for tool in kubectl k3d docker openssl; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done
# Never deploy to whatever cluster happens to be the current context.
kubectl --context "$CONTEXT" cluster-info >/dev/null
KUBECTL="kubectl --context $CONTEXT"

# ---- 1. cert-manager (TLS for the edge) -------------------------------------
if ! $KUBECTL get ns cert-manager >/dev/null 2>&1; then
  log "installing cert-manager ${CERT_MANAGER_VERSION}"
  $KUBECTL apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"
fi
$KUBECTL -n cert-manager rollout status deploy/cert-manager deploy/cert-manager-webhook deploy/cert-manager-cainjector --timeout=300s

# ---- 2. cluster-level pieces: CA, DNS override, admission policy ------------
log "applying cluster-level configuration"
$KUBECTL apply -k deploy/k8s/cluster/k3d
$KUBECTL -n kube-system rollout restart deploy/coredns
$KUBECTL -n kube-system rollout status deploy/coredns --timeout=120s

# ---- 3. images ---------------------------------------------------------------
log "building images"
deploy/scripts/build-images.sh
TAG="$(cat .image-tag)"

log "loading images into the cluster"
k3d image import -c "$CLUSTER" \
  "zero-trust/authorization-server:${TAG}" "zero-trust/resource-server:${TAG}" \
  "zero-trust/bff:${TAG}" "zero-trust/frontend:${TAG}"

# ---- 4. namespace + secrets --------------------------------------------------
log "ensuring namespace and secrets"
$KUBECTL apply -f deploy/k8s/bootstrap/namespace.yaml

rand() { openssl rand -base64 33 | tr -d '/+=\n' | cut -c1-40; }
have_secret() { $KUBECTL -n "$NS" get secret "$1" >/dev/null 2>&1; }

have_secret zt-db || $KUBECTL -n "$NS" create secret generic zt-db \
  --from-literal=username=auth --from-literal=password="$(rand)"
# The Resource Server's own database login (ADR-SEC-019): never the identity owner's.
have_secret zt-resource-db || $KUBECTL -n "$NS" create secret generic zt-resource-db   --from-literal=username=resource_app --from-literal=password="$(rand)"
have_secret zt-redis || $KUBECTL -n "$NS" create secret generic zt-redis \
  --from-literal=password="$(rand)"
have_secret zt-oidc || $KUBECTL -n "$NS" create secret generic zt-oidc \
  --from-literal=service-client-secret="$(rand)" --from-literal=bff-client-secret="$(rand)"
if ! have_secret zt-jwt-keys; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$tmp/private.pem" 2>/dev/null
  openssl pkey -in "$tmp/private.pem" -pubout -out "$tmp/public.pem"
  $KUBECTL -n "$NS" create secret generic zt-jwt-keys \
    --from-file=private.pem="$tmp/private.pem" --from-file=public.pem="$tmp/public.pem"
fi

# ---- 5. the application ------------------------------------------------------
log "applying workloads (tag ${TAG})"
# Renamed when the Resource Server was given database access; apply does not prune.
$KUBECTL -n "$NS" delete networkpolicy postgres-from-authorization-server --ignore-not-found >/dev/null
IMAGE_TAG="$TAG" KUBECTL="$KUBECTL" deploy/scripts/apply.sh

# The edge certificate must exist before the BFF's init container can mount its CA.
$KUBECTL -n "$NS" wait --for=condition=Ready certificate/zt-edge --timeout=120s

$KUBECTL -n "$NS" rollout status statefulset/postgres --timeout=300s
$KUBECTL -n "$NS" rollout status deploy/redis --timeout=180s
# The Resource Server's database role needs the identity schema the Authorization
# Server creates on start-up, so it is bootstrapped between the two.
$KUBECTL -n "$NS" rollout status deploy/authorization-server --timeout=400s
log "bootstrapping the Resource Server's database role"
deploy/scripts/bootstrap-db.sh
for d in resource-server bff frontend; do
  $KUBECTL -n "$NS" rollout status "deploy/$d" --timeout=400s
done

# ---- 6. export the CA so a browser / curl on the host can trust the edge ----
mkdir -p deploy/.local
$KUBECTL -n "$NS" get secret zt-edge-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > deploy/.local/zero-trust-ca.crt

log "done"
cat <<EOF

  App       https://zerotrust.localtest.me:8443
  Issuer    https://auth.zerotrust.localtest.me:8443/.well-known/openid-configuration
  CA cert   deploy/.local/zero-trust-ca.crt   (import it, or use curl --cacert)

  kubectl --context ${CONTEXT} -n ${NS} get pods
EOF
