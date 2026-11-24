#!/usr/bin/env bash
#
# Gives a git worktree of this repo what the main checkout has and git does not track:
#
#   - integrations/<name>: a detached worktree of each integration repository in the main
#     checkout, at the commit the main checkout has checked out
#   - local: a link to the main checkout's local/, so what is written there outlives the worktree
#   - data: a link to /opt/ace/data, the stack's data volume where the dev container mounts it, so
#     that ace run from the worktree there has the main checkout's data directory (logs, data/etc,
#     the yara socket) instead of failing on a missing one. It dangles on the host, where nothing
#     reads it
#   - a copy of each path in .worktreeinclude, which Claude Code copies into a worktree it creates
#     and other tools do not
#   - .agents/skills/<name>: a link to each skill in the main checkout and in ~/.claude/skills that
#     the worktree does not have, because a worktree gets only the skills git tracks. Codex reads
#     .agents/skills, and Claude Code reads it through the tracked link .claude/skills
#
# and removes the integration repositories' records of worktrees that have since been deleted.
#
# Run by the SessionStart hooks in .claude/settings.json and .codex/hooks.json; safe to run by
# hand. It does nothing in the main checkout, changes nothing that already exists, and prints only
# what it created, which the hook hands to the agent as context.
#

# as a hook (--hook), set up the directory the session works in, which the hook input names as "cwd":
# the desktop app runs a worktree session's hooks from the main checkout, which is where this script
# is then. Otherwise, set up the checkout the script is in, and leave stdin alone: only a hook's stdin
# is sure to reach EOF, and one left open by a background shell would block this forever.
dir=$(dirname "${BASH_SOURCE[0]}")/..
if [ "$1" = "--hook" ]; then
    cwd=$(python3 -c 'import json, sys; print(json.load(sys.stdin).get("cwd", ""))' 2>/dev/null)
    [ -n "$cwd" ] && dir=$cwd
fi
cd "$dir" || exit 1

# outside a git repository there is nothing to set up, and failing would show as a hook error at
# the start of every session
common_dir=$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null) || exit 0
if [ "$(git rev-parse --path-format=absolute --git-dir)" = "$common_dir" ]; then
    exit 0
fi

worktree=$(git rev-parse --show-toplevel) || exit 1
main=$(dirname "$common_dir")
status=0

# Removes the records of repository $1's worktrees that are missing under the main checkout or beside
# this worktree. Not `git worktree prune`: the host and the dev container see the checkout at
# different paths, so to one of them every worktree the other created is missing, and prune would
# remove its record and break git in it. A worktree is used only from the side that created it.
remove_missing_worktrees() {
    local path="" prunable="" line
    while IFS= read -r line; do
        case $line in
            "worktree "*) path=${line#worktree } ;;
            # git never lists a locked worktree as prunable
            prunable*) prunable=1 ;;
            "")
                if [ -n "$prunable" ]; then
                    case $path in
                        "$main"/*|"$(dirname "$worktree")"/*) git -C "$1" worktree remove "$path" || status=1 ;;
                    esac
                fi
                path="" prunable=""
                ;;
        esac
    done < <(git -C "$1" worktree list --porcelain; echo)
}

for repo in "$main"/integrations/*/; do
    repo=${repo%/}
    name=$(basename "$repo")
    # an integration installed as a plain directory has no repository to take a worktree of
    [ -e "$repo/.git" ] || continue

    remove_missing_worktrees "$repo"
    [ -e "$worktree/integrations/$name" ] && continue

    if git -C "$repo" worktree add --quiet --detach "$worktree/integrations/$name" HEAD; then
        echo "integrations/$name: new worktree of $repo, detached at $(git -C "$repo" rev-parse --short HEAD)." \
             "It is a separate repository: create a branch in it before committing, and its changes" \
             "do not show in this checkout's git status."
    else
        status=1
    fi
done

case $worktree in
    "$main"/*)
        # relative, so that they also resolve in the dev container, which mounts the main checkout
        # at /opt/ace
        up=$(printf '%s' "${worktree#"$main"/}" | sed 's|[^/][^/]*|..|g')
        local_target=$up/local
        skills_target=../../$up/.agents/skills
        ;;
    *)
        local_target=$main/local
        skills_target=$main/.agents/skills
        ;;
esac

if [ ! -e "$worktree/local" ] && [ ! -L "$worktree/local" ]; then
    mkdir -p "$main/local"
    ln -s "$local_target" "$worktree/local" && echo "local: linked to $main/local"
fi

if [ ! -e "$worktree/data" ] && [ ! -L "$worktree/data" ]; then
    ln -s /opt/ace/data "$worktree/data" && echo "data: linked to /opt/ace/data (the dev container's data volume)"
fi

# the main checkout's come first, so that it wins over the user for a skill they both have
mkdir -p "$worktree/.agents/skills"
linked=0
names=
for skill in "$main"/.agents/skills/*/ "$HOME"/.claude/skills/*/; do
    skill=${skill%/}
    name=$(basename "$skill")
    # this also skips a dangling link and a directory that is not a skill
    [ -e "$skill/SKILL.md" ] || continue
    [ -e "$worktree/.agents/skills/$name" ] || [ -L "$worktree/.agents/skills/$name" ] && continue

    case $skill in
        "$main"/*) target=$skills_target/$name ;;
        *) target=$skill ;;
    esac
    if ln -s "$target" "$worktree/.agents/skills/$name"; then
        linked=$((linked + 1))
        names="$names $name"
    else
        status=1
    fi
done
# Claude Code lists these from a session's second turn, so this is how its first turn learns of them
[ $linked -gt 0 ] && echo "skills: linked $linked from $main and ~/.claude/skills, which a session that" \
    "is already running lists from its next turn. Until then, read .agents/skills/<name>/SKILL.md to" \
    "use one:$names"

if [ -f "$main/.worktreeinclude" ]; then
    while IFS= read -r entry; do
        case $entry in
            ""|"#"*) continue ;;
        esac
        name=${entry%/}
        [ -e "$main/$name" ] || continue
        [ -e "$worktree/$name" ] && continue
        if cp -Rp "$main/$name" "$worktree/$name"; then
            echo "$name: copied from $main"
        else
            rm -rf "${worktree:?}/$name"
            status=1
        fi
    done < "$main/.worktreeinclude"
fi

exit $status
