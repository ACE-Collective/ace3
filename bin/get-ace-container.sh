#!/usr/bin/env bash
#
# Print the container id of this checkout's ace (engine) container, or nothing if it is not
# running.
#

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
# --status is a compose v2 flag; fall back to a plain lookup if this build lacks it
if ! CONTAINER_IDS=$(docker compose ps --status running -q ace 2>/dev/null); then
    CONTAINER_IDS=$(docker compose ps -q ace 2>/dev/null)
fi

printf '%s\n' "${CONTAINER_IDS}" | head -n1
