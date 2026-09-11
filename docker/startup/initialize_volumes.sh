#!/usr/bin/env bash
#

#
# guard against a data volume that belongs to a different ACE stack
#
# ACE_STACK is the compose project name, which is what prefixes every named volume, so the
# two normally cannot disagree. They can if COMPOSE_PROJECT_NAME is set directly, since that
# overrides the top-level name: in docker-compose.yml -- the volumes would then follow
# COMPOSE_PROJECT_NAME while the phishkit and js-deobfuscator managers are still handed volume
# names built from ACE_STACK. Two stacks writing one MySQL datadir is the worst outcome
# available here, so stop before anything else in the stack starts.
#
# This service runs first (everything else depends on it) and as root, with the data volume
# mounted, which is why the check lives here. To deliberately re-point an existing volume at a
# new stack name, delete the marker or run `docker compose down -v` to start clean.
#

STACK_MARKER=/opt/ace/data/.ace_stack
EXPECTED_STACK="${ACE_STACK:-ace}"

if [ -d /opt/ace/data ]
then
    if [ -f "${STACK_MARKER}" ]
    then
        ACTUAL_STACK="$(cat "${STACK_MARKER}")"
        if [ "${ACTUAL_STACK}" != "${EXPECTED_STACK}" ]
        then
            echo "FATAL: this data volume belongs to ACE stack '${ACTUAL_STACK}', but this" >&2
            echo "       stack is running as '${EXPECTED_STACK}'. refusing to start." >&2
            echo "       check that ACE_STACK is set correctly and that COMPOSE_PROJECT_NAME is not set." >&2
            exit 1
        fi
    else
        echo "${EXPECTED_STACK}" > "${STACK_MARKER}"
        chown ace:ace "${STACK_MARKER}"
    fi
fi

#
# special handling for the phishkit volume
#

if [ ! -d /phishkit/input ]
then
    mkdir -p /phishkit/input
    chown ace:ace /phishkit/input
fi

if [ ! -d /phishkit/output ]
then
    mkdir -p /phishkit/output
    chown ace:ace /phishkit/output
fi

#
# special handling for the js-deobfuscator volume
#

if [ ! -d /js-deobfuscator/input ]
then
    mkdir -p /js-deobfuscator/input
    chown ace:ace /js-deobfuscator/input
fi

if [ ! -d /js-deobfuscator/output ]
then
    mkdir -p /js-deobfuscator/output
    chown ace:ace /js-deobfuscator/output
fi

#
# when docker creates a named volume it creates it owned root:root
# this ensures that the volumes are owned by ace instead
#

for path in \
    /opt/ace/data \
    /opt/ace/signatures \
    /opt/ace/ssl \
    /docker-entrypoint-initdb.d \
    /ace-sql-readonly \
    /auth \
    /home/ace \
    /phishkit /phishkit/input /phishkit/output \
    /js-deobfuscator /js-deobfuscator/input /js-deobfuscator/output
do
    if [ -d "${path}" ]
    then
        if [[ $(stat -c "%U" ${path}) != "ace" ]]
        then
            chown ace:ace ${path}
        fi
    fi
done
