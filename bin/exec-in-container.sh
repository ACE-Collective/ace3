#!/usr/bin/env bash

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

# The dev container mounts the main checkout at /opt/ace, so a git worktree under it is at
# /opt/ace/<its path in the main checkout>. Run there, with SAQ_HOME and PYTHONPATH on it, so the
# command runs this checkout's code rather than the main checkout's.
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
            echo "Error: $checkout is not inside $main, so the dev container cannot see it"
            exit 1
            ;;
    esac
fi

# Get the container name
CONTAINER=$(bin/get-dev-container.sh)

if [ -z "$CONTAINER" ]; then
    echo "Error: No development container found"
    exit 1
fi

#echo "Executing in container: $CONTAINER"
#echo "Command: $@"
#echo "User: $USER"
#echo ""

# Execute the command in the container, sourcing load_environment first
docker exec $INTERACTIVE $TTY -u $USER -w "$WORKDIR" -e SAQ_HOME="$WORKDIR" -e PYTHONPATH="$WORKDIR" "$CONTAINER" bash -c "source load_environment && source /venv/bin/activate && $*"