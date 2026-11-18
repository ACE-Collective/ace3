#!/usr/bin/env bash
#
# Print the container id of this checkout's ace (engine) container, or nothing if it is not
# running.
#

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
# a worktree created on the other side of the dev container's mount names a gitdir that does not
# exist here, so git would not see a worktree and the lookup below would use the wrong checkout
if [ -f .git ] && ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "Error: git cannot open the worktree $(pwd -P), whose .git names $(sed -n 's/^gitdir: //p' .git)." \
         "It was created on the other side of the dev container's mount (the host or the container)," \
         "and is used only from there (CLAUDE.md)" >&2
    exit 1
fi
# a git worktree has no .env or docker-compose.override.yml of its own: its stack is the one of
# the checkout it was made from
common_dir=$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null)
[ "$common_dir" != "$(git rev-parse --path-format=absolute --git-dir 2>/dev/null)" ] && cd "$common_dir/.."
# --status is a compose v2 flag; fall back to a plain lookup if this build lacks it
if ! CONTAINER_IDS=$(docker compose ps --status running -q ace 2>/dev/null); then
    CONTAINER_IDS=$(docker compose ps -q ace 2>/dev/null)
fi

printf '%s\n' "${CONTAINER_IDS}" | head -n1
