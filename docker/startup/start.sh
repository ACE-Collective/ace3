#!/usr/bin/env bash
#
# ensures all the files and directories that are needed exist
# and waits for the database connection to become available
# this file is sourced from every other startup file
#

source bin/initialize-environment.sh

echo -n "waiting for database..."
while :
do
    if ace --skip-initialize-automation-user test database-connections
    then
        echo
        break
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
