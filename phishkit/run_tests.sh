#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BASE_IMAGE="${BASE_IMAGE:-phishkit}"
TEST_IMAGE="${TEST_IMAGE:-phishkit-test}"
DOCKER_IMAGE_PREFIX="${DOCKER_IMAGE_PREFIX:-docker.io}"

echo "building base image: $BASE_IMAGE"
docker build -f "$REPO_ROOT/phishkit/Dockerfile.phishkit" \
    --build-arg "DOCKER_IMAGE_PREFIX=$DOCKER_IMAGE_PREFIX" -t "$BASE_IMAGE" "$REPO_ROOT"

echo "building test image: $TEST_IMAGE"
docker build -f "$REPO_ROOT/phishkit/Dockerfile.phishkit.test" --build-arg "BASE_IMAGE=$BASE_IMAGE" -t "$TEST_IMAGE" "$REPO_ROOT"

echo "running tests"
docker run --rm "$TEST_IMAGE" /opt/venv/bin/pytest /opt/app/tests/ -v -m unit "$@"
