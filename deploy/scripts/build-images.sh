#!/usr/bin/env bash
# Build the four service images, tagged with the git SHA (never :latest -
# the admission policy rejects it, and a mutable tag defeats rollback).
set -euo pipefail
cd "$(dirname "$0")/../.."

TAG="${IMAGE_TAG:-$(git rev-parse --short=12 HEAD)$(git diff --quiet HEAD -- . || echo -dirty)}"
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
