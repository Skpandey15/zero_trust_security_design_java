#!/usr/bin/env bash
# Remove the zero-trust deployment from the local k3d cluster.
# Leaves cert-manager and every other namespace (tiny-url etc.) alone.
set -euo pipefail
cd "$(dirname "$0")/../.."
KUBECTL="kubectl --context k3d-${K3D_CLUSTER:-dev}"

$KUBECTL delete namespace zero-trust --ignore-not-found
$KUBECTL delete -k deploy/k8s/cluster/k3d --ignore-not-found
# The coredns-custom ConfigMap is gone; make CoreDNS forget the rewrite.
$KUBECTL -n kube-system rollout restart deploy/coredns
echo "removed. (cert-manager left installed; remove with: kubectl delete -f https://github.com/cert-manager/cert-manager/releases/download/v1.21.2/cert-manager.yaml)"
