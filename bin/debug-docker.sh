#!/usr/bin/env bash
#
# Open a throwaway shell on this checkout's ACE image, attached to its network and data volume.
# Useful when the stack is too broken to `docker compose exec` into.
#

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

# shellcheck disable=SC1091
set -a; [ -f .env ] && . ./.env; set +a

INSTANCE="${ACE_INSTANCE:-ace}"

docker run \
    -it \
    -u ace \
    --rm \
    --network "${INSTANCE}_ace" \
    --mount "source=${INSTANCE}_data,target=/opt/ace/data" \
    "${ACE3_IMAGE_URL:-ace3:latest}" \
    /bin/bash -il
