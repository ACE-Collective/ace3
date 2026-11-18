#!/usr/bin/env bash
#
# From the host, runs a command in this checkout's dev container, at this checkout's path there, with
# SAQ_HOME and PYTHONPATH on it. Inside a container it refuses: run the command directly there.
#
# resolve everything relative to this script rather than the caller's cwd, so that
# bin/get-dev-container.sh below finds this checkout's compose project (and therefore this ACE
# instance) no matter where the script is invoked from
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

USER="ace"
INTERACTIVE=""
TTY=""

# Parse command line options
while getopts "u:it" opt; do
    case ${opt} in
        u)
            USER="$OPTARG"
            ;;
        i)
            INTERACTIVE="-i"
            ;;
        t)
            TTY="-t"
            ;;
        *)
            echo "Usage: $0 [-u username] [-i] [-t] command [args...]"
            echo "  -u username: Run as specified user (default: ace)"
            echo "  -i: Keep STDIN open (interactive)"
            echo "  -t: Allocate pseudo-TTY"
            echo "Example: $0 pytest tests/saq/database/util/test_alert.py::test_set_dispositions_basic -v"
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))

# Check if command was provided
if [ $# -eq 0 ]; then
    echo "Error: No command specified"
    echo "Usage: $0 [-u username] [-i] [-t] command [args...]"
    exit 1
fi

# Already in a container of the stack (the dev container has no docker): there is no container to run
# the command in. Refuse rather than run it here, so that what runs in dev is always the command as typed,
# with the shell's own quoting, and not one that went through this script.
if ! command -v docker >/dev/null && [ -e /.dockerenv ]; then
    checkout=$(pwd -P)
    {
        echo "Error: bin/exec-in-container.sh runs a command in the dev container from the host, and this is already a container."
        echo "Run the command directly, from $checkout:"
        # one argument is usually a whole command line, written for the shell this script used to run
        if [ $# -eq 1 ]; then
            echo "    $1"
        else
            printf '   '; printf ' %q' "$@"; echo
        fi
        if [ "${SAQ_HOME:-}" != "$checkout" ]; then
            echo "SAQ_HOME is ${SAQ_HOME:-unset}, not this checkout. First run"
            echo "    export SAQ_HOME=$checkout PYTHONPATH=$checkout PATH=$checkout:$checkout/bin:\$PATH"
        fi
    } >&2
    exit 1
fi

# Get the container name
CONTAINER=$(bash bin/get-dev-container.sh) || exit 1

if [ -z "$CONTAINER" ]; then
    echo "Error: No development container found"
    exit 1
fi

# Prints where a bind mount of the container shows a host path, the deepest mount winning.
path_in_container() {
    local source destination best_source="" best_destination=""
    while IFS=$'\t' read -r source destination; do
        case $1 in
            "$source"|"$source"/*)
                if [ ${#source} -gt ${#best_source} ]; then
                    best_source=$source
                    best_destination=$destination
                fi
                ;;
        esac
    done < <(docker inspect --format '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}{{"\t"}}{{.Destination}}{{"\n"}}{{end}}{{end}}' "$CONTAINER")
    [ -n "$best_source" ] && echo "$best_destination${1#"$best_source"}"
}

# The dev container mounts the main checkout at /opt/ace, so a git worktree under it is at
# /opt/ace/<its path in the main checkout>. A worktree anywhere else is visible only through a mount
# of its own (docs/MULTI_INSTANCE.md). Run there, with SAQ_HOME and PYTHONPATH on it, so the command
# runs this checkout's code rather than the main checkout's.
WORKDIR=/opt/ace
common_dir=$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null)
if [ "$common_dir" != "$(git rev-parse --path-format=absolute --git-dir 2>/dev/null)" ]; then
    checkout=$(pwd -P)
    main=$(cd "$common_dir/.." && pwd -P)
    case $checkout in
        "$main"/*)
            WORKDIR="/opt/ace/${checkout#"$main"/}"
            ;;
        *)
            WORKDIR=$(path_in_container "$checkout")
            if [ -z "$WORKDIR" ]; then
                echo "Error: the dev container cannot see $checkout. Mount it (or a directory above it) for" \
                     "the dev service in $main/docker-compose.override.yml and recreate dev (docs/MULTI_INSTANCE.md)" >&2
                exit 1
            fi
            ;;
    esac
fi

#echo "Executing in container: $CONTAINER"
#echo "Command: $@"
#echo "User: $USER"
#echo ""

# Execute the command in the container, sourcing load_environment first. The arguments are passed as
# they are, as docker exec passes them, so a shell construct (a pipe, &&, a redirect) inside the container
# needs an explicit bash -c '...'. ./ because the dev container's PATH has /opt/ace on it, and source
# searches PATH first, so a bare `source load_environment` would source the main checkout's.
docker exec $INTERACTIVE $TTY -u $USER -w "$WORKDIR" -e SAQ_HOME="$WORKDIR" -e PYTHONPATH="$WORKDIR" "$CONTAINER" \
    bash -c 'source ./load_environment && source /venv/bin/activate && exec "$@"' bash "$@"
