#!/usr/bin/env bash
#
# ensures all the files and directories that are needed exist
# and waits for the database connection to become available
# this file is sourced from every other startup file
#

source bin/initialize-environment.sh

# ace exits with 75 (EXIT_DATABASE_UNAVAILABLE in saq/cli/cli_main.py) when it cannot reach a
# database, the one failure that waiting fixes. anything else, such as a configuration error, fails
# the same way on every attempt, so exit and leave it to the container's restart policy, where the
# restart count shows it
#
# the wait for an unreachable database is bounded too: pymysql reports a hostname that fails TLS
# verification, or one that never resolves, the same way as a database that is not up yet
database_wait_seconds="${ACE_DATABASE_WAIT_SECONDS:-300}"
deadline=$((SECONDS + database_wait_seconds))
echo -n "waiting for database..."
while :
do
    ace test database-connections
    result=$?
    if [ "$result" -eq 0 ]
    then
        echo
        break
    fi

    if [ "$result" -ne 75 ]
    then
        echo "ace test database-connections failed with exit code $result, which waiting will not fix" >&2
        exit "$result"
    fi

    if [ "$SECONDS" -ge "$deadline" ]
    then
        echo "no database reachable after ${database_wait_seconds} seconds, giving up" >&2
        exit "$result"
    fi

    echo .
    sleep 1
done

echo 
echo "starting ace..."
echo

# run the command passed to this script
#
# exec replaces this shell with the command so the command itself becomes PID 1 of the
# container and receives SIGTERM directly from docker. without exec, bash remains PID 1
# with the command as a foreground child; a non-interactive bash does not forward SIGTERM
# to a foreground child, so the process never sees the signal and docker SIGKILLs the
# whole container once the stop grace period expires.
#
# note that start_nothing.sh sources this file with no positional arguments. "$@" then
# expands to nothing and exec becomes a no-op, so that script's own trailing loop still
# runs as before.
exec "$@"
