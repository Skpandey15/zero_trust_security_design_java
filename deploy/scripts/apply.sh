#!/usr/bin/env bash
# Render the overlay and apply it. The one place image names and tags are
# substituted, used by both the local script and the Jenkins pipeline.
#
#   IMAGE_TAG        required  tag to deploy (git SHA)
#   IMAGE_REGISTRY   optional  registry prefix incl. trailing slash, e.g. localhost:30500/
#   OVERLAY          optional  default k3d
#   KUBECTL          optional  default "kubectl"
set -euo pipefail
cd "$(dirname "$0")/../.."

: "${IMAGE_TAG:?IMAGE_TAG is required}"
OVERLAY="${OVERLAY:-k3d}"
KUBECTL="${KUBECTL:-kubectl}"
REGISTRY="${IMAGE_REGISTRY:-}"

$KUBECTL kustomize "deploy/k8s/overlays/${OVERLAY}" \
  | sed -e "s|image: zero-trust/|image: ${REGISTRY}zero-trust/|" \
        -e "s|:__TAG__|:${IMAGE_TAG}|g" \
  | $KUBECTL apply ${DRY_RUN:+--dry-run=server} -f -
