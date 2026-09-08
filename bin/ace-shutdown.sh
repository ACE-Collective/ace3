#!/usr/bin/env bash
#
# Shut down this ACE node cleanly.
#
# Run this instead of `docker compose stop` directly. The difference is the drain: it
# takes the node out of the cluster's rotation *before* anything is stopped, so peers
# stop routing work here and the collectors flush what they have already accepted. Only
# then are the containers stopped, in dependency order, each with a grace period long
# enough for the process inside it to exit on its own.
#
# Analysis still running when the stop begins is abandoned and requeued rather than
# finished: each worker cancels its current analysis, releases its lock and exits, which
# leaves the work claimable by another node immediately.
#
# Usage:
#   bin/ace-shutdown.sh                 drain (waiting up to 300s), then stop
#   bin/ace-shutdown.sh --fast          skip the drain and stop now
#   bin/ace-shutdown.sh --timeout 600   allow longer for the drain
#   bin/ace-shutdown.sh --down          `docker compose down` instead of `stop`
#

set -u

DRAIN=1
DRAIN_TIMEOUT=300
COMPOSE_ACTION=stop

while [ $# -gt 0 ]; do
    case "$1" in
        --fast) DRAIN=0; shift ;;
        --timeout) DRAIN_TIMEOUT="$2"; shift 2 ;;
        --down) COMPOSE_ACTION=down; shift ;;
        -h|--help) awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

cd "$(dirname "$0")/.." || exit 1

if [ "$DRAIN" -eq 1 ]; then
    echo "draining node (timeout ${DRAIN_TIMEOUT}s)..."

    # the drain runs inside a container because it needs ACE's configuration and database
    # credentials. a failure here is not fatal: a node that cannot be drained can still be
    # stopped, and the primary node recovers anything left behind once its locks expire.
    if ! docker compose exec -T ace ./ace node drain --wait --timeout "$DRAIN_TIMEOUT"; then
        echo "WARNING: drain did not complete; stopping anyway" >&2
    fi
fi

echo "stopping containers..."

# no -t here on purpose. passing a timeout to compose overrides the per-service
# stop_grace_period values in docker-compose.yml with one number for everything, which
# would give the engine the same few seconds as a stateless proxy. the grace periods are
# already sized per service, and each process exits well inside its own.
exec docker compose "$COMPOSE_ACTION"
