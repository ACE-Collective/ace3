#!/usr/bin/env bash
#
# Gives a git worktree of this repo what the main checkout has and git does not track:
#
#   - integrations/<name>: a detached worktree of each integration repository in the main
#     checkout, at the commit the main checkout has checked out
#   - tests/test_external_integration_*: the main checkout's links into those repositories
#   - local: a link to the main checkout's local/, so what is written there outlives the worktree
#
# and prunes the integration repositories' records of worktrees that have since been deleted.
#
# Run by the SessionStart hook in .claude/settings.json; safe to run by hand. It does nothing in
# the main checkout, changes nothing that already exists, and prints only what it created, which
# the hook hands to Claude as context.
#

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

# outside a git repository there is nothing to set up, and failing would show as a hook error at
# the start of every session
common_dir=$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null) || exit 0
if [ "$(git rev-parse --path-format=absolute --git-dir)" = "$common_dir" ]; then
    exit 0
fi

worktree=$(git rev-parse --show-toplevel) || exit 1
main=$(dirname "$common_dir")
status=0

for repo in "$main"/integrations/*/; do
    repo=${repo%/}
    name=$(basename "$repo")
    # an integration installed as a plain directory has no repository to take a worktree of
    [ -e "$repo/.git" ] || continue

    git -C "$repo" worktree prune
    [ -e "$worktree/integrations/$name" ] && continue

    if git -C "$repo" worktree add --quiet --detach "$worktree/integrations/$name" HEAD; then
        echo "integrations/$name: new worktree of $repo, detached at $(git -C "$repo" rev-parse --short HEAD)." \
             "It is a separate repository: create a branch in it before committing, and its changes" \
             "do not show in this checkout's git status."
    else
        status=1
    fi
done

linked=0
for link in "$main"/tests/test_external_integration_*; do
    [ -L "$link" ] || continue
    name=$(basename "$link")
    target=$(readlink "$link")
    [ -e "$worktree/tests/$name" ] || [ -L "$worktree/tests/$name" ] && continue

    case $target in
        /*)
            # an absolute link would run the main checkout's integration tests, not this worktree's
            echo "tests/$name: not linked, because the main checkout's link is absolute ($target)" >&2
            status=1
            continue
            ;;
    esac

    # skip a link whose integration this worktree does not have, rather than leave it dangling
    (cd "$worktree/tests" && [ -e "$target" ]) || continue
    ln -s "$target" "$worktree/tests/$name" && linked=$((linked + 1))
done
[ $linked -gt 0 ] && echo "tests: linked $linked test_external_integration_* directories"

if [ ! -e "$worktree/local" ] && [ ! -L "$worktree/local" ]; then
    mkdir -p "$main/local"
    case $worktree in
        "$main"/*)
            # relative, so that it also resolves in the dev container, which mounts the main
            # checkout at /opt/ace
            up=$(printf '%s' "${worktree#"$main"/}" | sed 's|[^/][^/]*|..|g')
            ln -s "$up/local" "$worktree/local"
            ;;
        *)
            ln -s "$main/local" "$worktree/local"
            ;;
    esac && echo "local: linked to $main/local"
fi

exit $status
