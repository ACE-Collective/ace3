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
"$@"
