#!/usr/bin/env bash

#
# this is the container to attach to for development purposes
#

# start.sh exits when the database wait fails, but dev stays up: it is where whatever made the
# wait fail gets fixed. start.sh's exec does nothing here, since this passes it no command
( source docker/startup/start.sh ) || echo "database wait failed with exit code $?; dev stays up for debugging" >&2
while :; do sleep 1; done
