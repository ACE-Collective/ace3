#!/usr/bin/env bash
source /opt/ace/bin/initialize-environment.sh

# runs every task in etc/cron/daily (and in etc/cron/daily of each enabled integration) in parallel,
# each through bin/run-cron-job with its own log and outcome record -- see docs/CRON.md
exec ace cron run daily
