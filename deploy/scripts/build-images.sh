#!/usr/bin/env bash
# Build the four service images, tagged with the git SHA (never :latest -
# the admission policy rejects it, and a mutable tag defeats rollback).
set -euo pipefail
cd "$(dirname "$0")/../.."

# A dirty tree gets a suffix derived from its CONTENT. A fixed "-dirty" would
# reuse the same tag for different code, so the cluster would see no change and
# never roll the pods.
dirty_suffix() {
  git diff --quiet HEAD -- . && [ -z "$(git ls-files -o --exclude-standard)" ] && return 0
  printf -- '-dirty-%s' "$( { git diff HEAD; git ls-files -o --exclude-standard | xargs -r cat; } | sha256sum | cut -c1-8)"
}
TAG="${IMAGE_TAG:-$(git rev-parse --short=12 HEAD)$(dirty_suffix)}"
export DOCKER_BUILDKIT=1

# The three Gradle builds run one after another: they share a BuildKit cache
# mount, and three cold wrapper downloads at once time out.
docker build -t "zero-trust/frontend:${TAG}" -f frontend/Dockerfile frontend &
docker build -t "zero-trust/authorization-server:${TAG}" -f backend/Dockerfile --build-arg MODULE=authorization-server backend
docker build -t "zero-trust/resource-server:${TAG}"      -f backend/Dockerfile --build-arg MODULE=resource-server backend
docker build -t "zero-trust/bff:${TAG}"                  -f bff/Dockerfile bff
wait

echo "${TAG}" > .image-tag
echo "built tag ${TAG}"
