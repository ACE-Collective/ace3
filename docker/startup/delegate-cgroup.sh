#!/usr/bin/env bash
#
# Starts a container that runs sandboxed tools (tool-runner, and dev for the test suite): hands the
# ace user a cgroup subtree to create one cgroup per tool run in, then runs the given command as ace
# with no capabilities (docs/TOOL_SANDBOX.md).
#
# It runs as root with CAP_SYS_ADMIN and an AppArmor profile that allows mount, because docker mounts
# /sys/fs/cgroup read-only in every container that is not privileged. The capability is gone from
# every process once this execs the command; the container still holds it, so a root docker exec
# could use it.
#
# cgroup v2 lets a cgroup that enables controllers for its children hold no processes, so every
# process of the container moves to tools/service first, and the tool runner creates each run's
# cgroup beside it, under tools, which ace owns (saq/tool_runner/cgroup.py). docker exec joins the
# cgroup of the container's init, so what it starts is in tools/service too.

set -euo pipefail

root=/sys/fs/cgroup
controllers="+memory +pids"

mount -o remount,rw "$root"
mkdir -p "$root/tools/service"
# all of cgroup.procs is read before any move: the file changes as processes leave it. A process
# that exited since is ignored, and one forked meanwhile is moved on the next pass
for _ in 1 2 3
do
    for pid in $(cat "$root/cgroup.procs")
    do
        echo "$pid" > "$root/tools/service/cgroup.procs" 2>/dev/null || true
    done
done

echo "$controllers" > "$root/cgroup.subtree_control"
echo "$controllers" > "$root/tools/cgroup.subtree_control"
chown -R ace:ace "$root/tools"

HOME=$(getent passwd ace | cut -d: -f6)
export HOME USER=ace LOGNAME=ace
exec setpriv --reuid=ace --regid=ace --init-groups --inh-caps=-all --bounding-set=-all -- "$@"
