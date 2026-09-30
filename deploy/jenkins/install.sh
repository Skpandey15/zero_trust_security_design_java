#!/usr/bin/env bash
# One-time (idempotent) setup of the pipeline's platform: image registry,
# Jenkins, and the agent's RBAC. Run from WSL after deploy-local.sh has
# installed cert-manager and created the zero-trust namespace.
set -euo pipefail
cd "$(dirname "$0")/../.."

CONTEXT="k3d-${K3D_CLUSTER:-dev}"
KUBECTL="kubectl --context $CONTEXT"
HELM="helm --kube-context $CONTEXT"

$KUBECTL get ns zero-trust >/dev/null 2>&1 || {
  echo "zero-trust namespace missing - run deploy/scripts/deploy-local.sh first" >&2; exit 1; }

echo "==> admission policy (allow registry-hosted images)"
$KUBECTL apply -k deploy/k8s/cluster/k3d

echo "==> image registry"
$KUBECTL apply -f deploy/registry/registry.yaml
$KUBECTL -n registry rollout status deploy/registry --timeout=180s

echo "==> jenkins platform (namespace, agent RBAC, caches, certificate)"
$KUBECTL apply -f deploy/jenkins/platform.yaml
$KUBECTL -n jenkins wait --for=condition=Ready certificate/jenkins-tls --timeout=120s

echo "==> jenkins"
$HELM repo add jenkins https://charts.jenkins.io >/dev/null 2>&1 || true
$HELM repo update jenkins >/dev/null
$HELM upgrade --install jenkins jenkins/jenkins -n jenkins -f deploy/jenkins/values.yaml --wait --timeout 10m

cat <<EOF

  Jenkins   https://jenkins.zerotrust.localtest.me:8443
  user      admin
  password  kubectl --context ${CONTEXT} -n jenkins get secret jenkins -o jsonpath='{.data.jenkins-admin-password}' | base64 -d
EOF
