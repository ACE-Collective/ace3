#!/usr/bin/env bash
source /opt/ace/bin/initialize-environment.sh

# runs every task in etc/cron/hourly (and in etc/cron/hourly of each enabled integration) in parallel,
# each through bin/run-cron-job with its own log and outcome record -- see docs/CRON.md
exec ace cron run hourly
