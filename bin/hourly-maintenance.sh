#!/usr/bin/env bash
source /opt/ace/bin/initialize-environment.sh

# delete analysis module crash reports past their retention window, along with their index rows
# (the two go together on purpose -- see `ace crash prune`). the retention window comes from
# crash_reporting.retention_days unless --days overrides it
ace crash prune

# index any crash report on this node that has no database row -- the in-process timeout watchdog
# never writes one (it must not block on the database before os._exit), and an inline insert can
# fail. engine workers drain this spool as they start; this is the catch-up for a quiet node.
# AFTER prune, so it never indexes a report this same run just deleted
ace crash index

# replicate any crash report that is not yet in shared storage, so every node can serve it.
# no-op unless crash_reporting.replicate is set. deliberately AFTER prune: running it first would
# upload reports that this same run is about to delete, and briefly resurrect them remotely.
# this is the catch-up path only -- the engine replicates in the background as crashes happen
ace crash sync
