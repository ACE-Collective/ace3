# Source this from a shell in the dev container, from anywhere in the main checkout:
#
#     source bin/enter-worktree.sh <branch> [<start point>]
#     source bin/enter-worktree.sh --pr <number>
#
# It checks <branch> out in a new git worktree at .claude/worktrees/<topic>, where <topic> is the
# branch name without its initials prefix (jd/fix-thing -> fix-thing). A branch that exists locally,
# or on exactly one remote (which git then tracks), is checked out as it is; any other is created from
# <start point>, default the main checkout's HEAD. With --pr, <branch> is the pull request's head
# branch, which `gh pr checkout` creates or brings up to date. It then sets the worktree up with
# bin/setup-worktree.sh, moves into it, and points SAQ_HOME, PYTHONPATH and PATH at it, so pytest and
# `ace` run the worktree's code. The prompt shows (wt:<topic>) until you leave with
#
#     wtx [-f]
#
# which puts SAQ_HOME, PYTHONPATH, PATH and the prompt back, moves to the main checkout and deletes the
# worktree, its integration worktrees and its test data directory. The branch is kept. wtx refuses
# while the worktree or one of its integration worktrees has uncommitted changes or commits no branch
# holds; -f deletes it anyway.
#
# The worktree is created in dev, so its git works only in dev (CLAUDE.md).

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    echo "source this script instead of running it: source $0 <branch> [<start point>] | --pr <number>" >&2
    exit 1
fi

_ace_wt_enter() {
    local script_dir=$1 usage branch start pr common_dir main name worktree
    shift
    usage="usage: source bin/enter-worktree.sh <branch> [<start point>] | --pr <number>"

    case ${1:-} in
        -p|--pr)
            pr=${2:-}
            if ! [[ $pr =~ ^[0-9]+$ ]] || [ $# -ne 2 ]; then
                echo "$usage" >&2
                return 1
            fi
            ;;
        ""|-*)
            echo "$usage" >&2
            return 1
            ;;
        *)
            branch=$1 start=${2:-}
            if [ $# -gt 2 ]; then
                echo "$usage" >&2
                return 1
            fi
            ;;
    esac
    if [ -n "${ACE_WORKTREE:-}" ]; then
        echo "already in the worktree $ACE_WORKTREE: leave it with wtx first" >&2
        return 1
    fi

    common_dir=$(git -C "$script_dir" rev-parse --path-format=absolute --git-common-dir) || return 1
    main=$(dirname "$common_dir")

    if [ -n "$pr" ]; then
        branch=$(cd "$main" && gh pr view "$pr" --json headRefName --jq .headRefName) || return 1
    fi
    # the name goes into PS1, which the shell expands, so allow nothing it would expand
    if ! [[ $branch =~ ^[A-Za-z0-9._/-]+$ ]] || ! git check-ref-format --branch "$branch" >/dev/null 2>&1; then
        echo "not a branch name this script takes (letters, digits, . _ / -): $branch" >&2
        return 1
    fi

    name=${branch#*/}
    name=${name//\//-}
    worktree=$main/.claude/worktrees/$name
    if [ -e "$worktree" ]; then
        echo "$worktree already exists" >&2
        return 1
    fi

    if [ -n "$pr" ]; then
        # gh fetches the head (from a fork too), creates the branch or fast-forwards the existing one,
        # and sets its upstream; it leaves no worktree behind when it fails
        (cd "$main" && gh pr checkout "$pr" --branch "$branch" --worktree "$worktree") || return 1
    elif git -C "$main" show-ref --verify --quiet "refs/heads/$branch"; then
        if [ -n "$start" ]; then
            echo "the branch $branch already exists, so a start point does not apply to it" >&2
            return 1
        fi
        git -C "$main" worktree add "$worktree" "$branch" || return 1
    elif [ -z "$start" ] && [ "$(git -C "$main" for-each-ref --format=x "refs/remotes/*/$branch" | wc -l)" -eq 1 ]; then
        # git creates the branch from the remote's and tracks it
        git -C "$main" worktree add "$worktree" "$branch" || return 1
    else
        git -C "$main" worktree add -b "$branch" "$worktree" "${start:-HEAD}" || return 1
    fi
    # integrations, ssl/ and the local/ link, which the tests need and git does not track
    if ! "$worktree/bin/setup-worktree.sh"; then
        echo "bin/setup-worktree.sh failed: the worktree may be missing integrations or ssl/" >&2
    fi

    _ACE_WT_SAQ_HOME_SET=${SAQ_HOME+1}
    _ACE_WT_SAQ_HOME=${SAQ_HOME-}
    _ACE_WT_PYTHONPATH_SET=${PYTHONPATH+1}
    _ACE_WT_PYTHONPATH=${PYTHONPATH-}
    _ACE_WT_PATH=$PATH
    _ACE_WT_PS1=${PS1-}
    _ACE_WT_MAIN=$main

    export ACE_WORKTREE=$worktree
    export SAQ_HOME=$worktree
    export PYTHONPATH=$worktree
    # ahead of the main checkout's, which load_environment put on PATH: `ace` from the main checkout
    # would import the main checkout's saq, since a script's own directory comes first on sys.path
    export PATH=$worktree:$worktree/bin:$PATH
    PS1="(wt:$name) ${PS1-}"
    alias wtx=_ace_wt_exit

    cd "$worktree" || return 1
    echo "in $worktree on $branch; wtx deletes the worktree and takes you back to $main"
}

# Prints why the checkout $1 cannot be deleted without losing work, and nothing if it can.
_ace_wt_unsaved() {
    local changes
    changes=$(git -C "$1" status --porcelain)
    [ -n "$changes" ] && printf '%s has uncommitted changes:\n%s\n' "$1" "$changes"
    if [ -z "$(git -C "$1" for-each-ref --contains HEAD --count=1 refs/heads refs/remotes)" ]; then
        echo "$1 has commits no branch holds: $(git -C "$1" log --oneline -1 HEAD)"
    fi
}

_ace_wt_exit() {
    local force= worktree=${ACE_WORKTREE:-} main=${_ACE_WT_MAIN:-} branch problems dir data_dir status=0

    case ${1:-} in
        -f|--force) force=1 ;;
        "") ;;
        *) echo "usage: wtx [-f]" >&2; return 1 ;;
    esac
    if [ -z "$worktree" ] || [ -z "$main" ]; then
        echo "not in a worktree entered with bin/enter-worktree.sh" >&2
        return 1
    fi

    if [ -z "$force" ]; then
        problems=$(_ace_wt_unsaved "$worktree")
        for dir in "$worktree"/integrations/*/; do
            [ -f "$dir/.git" ] && problems+=$(_ace_wt_unsaved "${dir%/}")
        done
        if [ -n "$problems" ]; then
            printf '%s\nnothing was deleted; commit or discard it, or run wtx -f\n' "$problems" >&2
            return 1
        fi
    fi

    branch=$(git -C "$worktree" branch --show-current)
    # hashed the way tests/unittest_session.py names the checkout's test data directory
    data_dir=/var/tmp/ace-unittest/$(printf '%s' "$(realpath "$worktree")" | sha256sum | cut -c1-12)

    if [ -n "$_ACE_WT_SAQ_HOME_SET" ]; then export SAQ_HOME=$_ACE_WT_SAQ_HOME; else unset SAQ_HOME; fi
    if [ -n "$_ACE_WT_PYTHONPATH_SET" ]; then export PYTHONPATH=$_ACE_WT_PYTHONPATH; else unset PYTHONPATH; fi
    export PATH=$_ACE_WT_PATH
    PS1=$_ACE_WT_PS1
    unset ACE_WORKTREE _ACE_WT_SAQ_HOME_SET _ACE_WT_SAQ_HOME _ACE_WT_PYTHONPATH_SET _ACE_WT_PYTHONPATH \
        _ACE_WT_PATH _ACE_WT_PS1 _ACE_WT_MAIN
    unalias wtx 2>/dev/null
    cd "$main" || return 1

    # each integration worktree is a worktree of a repository in the main checkout, so remove it from
    # there, or that repository keeps a record of a worktree that no longer exists
    for dir in "$worktree"/integrations/*/; do
        dir=${dir%/}
        [ -f "$dir/.git" ] || continue
        git -C "$main/integrations/$(basename "$dir")" worktree remove ${force:+--force} "$dir" || status=1
    done
    git -C "$main" worktree remove ${force:+--force} "$worktree" || status=1
    rm -rf "$data_dir"

    if [ $status -ne 0 ]; then
        echo "could not delete all of $worktree; see the errors above" >&2
        return 1
    fi
    echo "deleted $worktree; the branch $branch is kept"
}

_ace_wt_enter "$(dirname "${BASH_SOURCE[0]}")" "$@"
