#!/usr/bin/env bash

cd "${SAQ_HOME:-/opt/ace}"
source /venv/bin/activate
source load_environment

cd "${SAQ_HOME:-/opt/ace}" && \
if [ -d integrations ]; then
    # skip dot-directories (.git, agent worktrees), which discovery never loads (saq/integration/integration_util.py)
    find integrations -name '.*' -prune -o -type f -name integration.md -print | LC_ALL=C sort | while read -r mdpath
    do
        dir=$(dirname "$mdpath")
        if [ -f "$dir/install.sh" ]; then
            echo "installing $dir"
            (cd "$dir" && ./install.sh)
        else
            echo "skipping $dir (no install.sh)"
        fi
    done
fi
