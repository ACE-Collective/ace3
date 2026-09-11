#!/usr/bin/env bash
#
# One-time migration for environments created before ACE supported multiple instances.
#
# The named volumes used to carry an explicit `name:` in docker-compose.yml, which pinned them
# to fixed, global names (ace-data, ace-db, ...). That is exactly what made two instances on one
# host impossible, so the `name:` keys are gone and compose now prefixes each volume with the
# project name instead: ace-data becomes ace_data, ace-db becomes ace_db, and so on.
#
# Nothing is destroyed by this. The old volumes are left exactly as they are; this copies their
# contents into the new names and then prints -- but does not run -- the commands to remove the
# originals once you are satisfied.
#
# Usage:
#   bin/migrate-volume-names.sh            show what would be copied
#   bin/migrate-volume-names.sh --yes      actually copy
#
# If the data in this environment is disposable, `docker compose down -v` followed by
# `docker compose up` is faster and needs no migration at all.
#

set -u

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

# shellcheck disable=SC1091
set -a; [ -f .env ] && . ./.env; set +a

INSTANCE="${ACE_INSTANCE:-ace}"
IMAGE="${ACE3_IMAGE_URL:-ace3:latest}"

APPLY=0
case "${1:-}" in
    --yes) APPLY=1 ;;
    "")    APPLY=0 ;;
    -h|--help) awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
esac

# legacy volume name -> compose volume key
KEYS="data db db-readonly sql sql-readonly phishkit js-deobfuscator auth qdrant user-home"

volume_exists() { docker volume inspect "$1" >/dev/null 2>&1; }

# An existing destination is usually not a reason to stop. Compose creates every named volume the
# moment anything in the stack is brought up -- including a single `docker compose up -d dev`, or
# an editor re-attaching to the dev container -- so by the time you get here the new names very
# often already exist and are empty. Refusing on existence alone would skip every volume, report
# "nothing to do" with a zero exit, and leave you with an empty stack believing you had migrated.
# Only a destination with something in it is a real conflict.
volume_is_empty() {
    [ -z "$(docker run --rm --user 0:0 -v "$1:/v:ro" "$IMAGE" sh -c 'ls -A /v' 2>/dev/null)" ]
}

# Refuse to copy out from under a running stack -- mysql in particular must not have its datadir
# read while it is writing to it.
#
# This deliberately does not ask `docker compose ps`. The legacy volumes predate the project
# prefix, so the stack holding them is almost always running under a *different* compose project
# name than this checkout now resolves to: before this change the project name came from the
# checkout directory (a checkout in ~/dev/ace3 ran as project `ace3`), and it is now `ACE_INSTANCE`.
# `docker compose ps` would look under the new name, find nothing, and report the old stack as
# stopped. Asking the daemon which containers have the volumes mounted is project-independent and
# is the actual condition we care about.
BUSY=""
for key in $KEYS; do
    ids="$(docker ps -q --filter "volume=ace-${key}" 2>/dev/null)"
    [ -n "$ids" ] && BUSY="${BUSY} ${ids}"
done

if [ -n "${BUSY// /}" ]; then
    echo "error: the legacy volumes are mounted by running containers. stop that stack first." >&2
    echo >&2
    echo "containers holding them:" >&2
    # shellcheck disable=SC2086
    docker inspect --format '    {{.Name}} (compose project: {{index .Config.Labels "com.docker.compose.project"}})' $BUSY 2>/dev/null | sort -u >&2
    echo >&2
    PROJECTS="$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' $BUSY 2>/dev/null | sort -u | grep -v '^$')"
    for project in $PROJECTS; do
        if [ "$project" = "$INSTANCE" ]; then
            echo "    bin/ace-shutdown.sh --fast" >&2
        else
            echo "    # that stack runs as project '${project}', not '${INSTANCE}', so the" >&2
            echo "    # checkout's own helpers will not stop it:" >&2
            echo "    docker compose -p ${project} stop" >&2
            echo >&2
            echo "    # and note the destination names below assume ACE_INSTANCE=${INSTANCE}." >&2
            echo "    # to keep the containers, network and volumes on the name this environment" >&2
            echo "    # already uses, put ACE_INSTANCE=${project} in .env before migrating." >&2
        fi
    done
    exit 1
fi

TO_COPY=""
for key in $KEYS; do
    old="ace-${key}"
    new="${INSTANCE}_${key}"

    if ! volume_exists "$old"; then
        echo "skip  ${old} -> ${new}  (no legacy volume; nothing to migrate)"
        continue
    fi
    if volume_exists "$new" && ! volume_is_empty "$new"; then
        echo "skip  ${old} -> ${new}  (destination exists and is not empty; remove it first to redo)"
        continue
    fi
    if volume_exists "$new"; then
        echo "copy  ${old} -> ${new}  (destination exists but is empty; reusing it)"
    else
        echo "copy  ${old} -> ${new}"
    fi
    TO_COPY="${TO_COPY} ${key}"
done

if [ -z "${TO_COPY// /}" ]; then
    echo
    echo "nothing to do."
    exit 0
fi

if [ "$APPLY" -ne 1 ]; then
    echo
    echo "this was a dry run. re-run with --yes to copy."
    exit 0
fi

for key in $TO_COPY; do
    old="ace-${key}"
    new="${INSTANCE}_${key}"
    echo "copying ${old} -> ${new} ..."
    docker volume create "$new" >/dev/null || exit 1
    # --user 0:0 so ownership and permissions survive the copy; cp -a preserves both, and the
    # /from mount is read-only so a mistake here cannot damage the original
    if ! docker run --rm --user 0:0 \
        -v "${old}:/from:ro" \
        -v "${new}:/to" \
        "$IMAGE" \
        sh -c 'cp -a /from/. /to/'; then
        echo "error: copy of ${old} failed; ${new} may be incomplete" >&2
        exit 1
    fi
done

echo
echo "done. the legacy volumes are untouched. once you have confirmed the stack comes up"
echo "cleanly with 'docker compose up', you can reclaim the space with:"
echo
for key in $TO_COPY; do
    echo "    docker volume rm ace-${key}"
done
