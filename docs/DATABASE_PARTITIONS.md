# Date-partitioned tables

Some high-volume tables keep only a window of recent rows. Instead of deleting old rows, which
locks rows, writes undo log and can block inserts for as long as it runs, they are
`RANGE COLUMNS` partitioned by a date column and expire a whole partition at a time with
`ALTER TABLE … DROP PARTITION`, which is a metadata operation.

| Table | Database | Column | One partition per | Retention (config) | Provisioned ahead |
|---|---|---|---|---|---|
| `archive`, `archive_index` | email archive | `insert_date` | ISO week (`pGGGGwVV`) | `email_archive.partition_retention_days` (30) | 4 weeks |
| `email_history` | email archive | `insert_date` | ISO week (`pGGGGwVV`) | `email_archive.email_history_retention_days` (30) | 4 weeks |
| `analysis_result_cache`, `blob_refs` | analysis result cache | `created_at` | day (`pYYYYMMDD`) | `analysis_cache.partition_retention_days` (35, at least 31) | 7 days |

Every table also has a `p_catchall VALUES LESS THAN (MAXVALUE)` partition on top, so a row always
has somewhere to land. The code is `saq/database/partitions.py`; the command is `ace partitions`.

## The catchall must stay empty

A new partition can only be added by splitting it off the catchall
(`ALTER TABLE … REORGANIZE PARTITION p_catchall INTO (…)`), because RANGE partitions have to
increase and the catchall already covers everything above the highest one. Splitting copies
**every row** in the catchall. While it runs, writes to the table are blocked and the copy can
fill the InnoDB redo log, which stalls writes to every table on the server. Splitting an empty
catchall takes no time at all; splitting one with months of rows in it is an outage.

This is not hypothetical. The email archive's partition script was broken for a long time, so
months of rows piled up in the catchall. Once it was fixed, its weekly run tried to split all of
them out. Inserts into the table blocked for hours, each analysis worker that hit the table was
killed for exceeding its time limit while its server connection stayed stuck behind the lock, and
the server ran out of connections. Every Monday the run was killed by a database restart, rolled
back, and started over the following week with more rows to copy.

So maintenance:

- provisions partitions ahead of time, so rows land in a dated partition and never in the catchall;
- never splits a catchall holding more than `CATCHALL_SPLIT_MAX_ROWS` (10,000) rows, and never
  partitions an unpartitioned table holding more than that. It fails instead, and the table needs a
  rebuild (below);
- runs every DDL statement with `lock_wait_timeout` set to a few seconds. A DDL statement waiting
  for its metadata lock blocks every later statement on the table, so a statement that would have
  to wait behind a long transaction gives up and is retried on the next run.

## Daily maintenance

`ace partitions maintain` runs daily from `etc/cron/daily/partitions`, and once at startup from
`docker/startup/setup.sh` (which is what partitions the analysis cache tables on a new install:
their migration creates them unpartitioned, and they are partitioned while they are still empty).
For each table it:

1. drops the partitions every row of which is past retention;
2. splits partitions off the catchall for the rest of the retention window and the periods ahead,
   if it is empty enough.

The databases are shared, so it does nothing on a node that is not the primary
(`ACE_IS_PRIMARY_NODE`), unless given `--force`. It exits 1 when any table needs attention, so the
`daily-partitions` cron job shows up as failed, with the reason in its output.
`--dry-run` shows what it would do.

`ace partitions status` shows each table's partitions, how far ahead they are provisioned, and
whether the catchall can still be split.

| Message | Meaning | What to do |
|---|---|---|
| `p_catchall holds more than 10000 rows …` | rows landed in the catchall (maintenance did not run for longer than the provisioned window, or never worked) | `ace partitions rebuild <table>` |
| `table is not partitioned and holds more than 10000 rows …` | the table was never partitioned | `ace partitions rebuild <table>` |
| `table has no p_catchall partition …` | partitioned by something else | `ace partitions rebuild <table>` |
| `table busy, will try again next run …` | a long transaction held the table | nothing, unless it repeats |
| `retention of N days is below the minimum …` | the retention setting is too low (the analysis cache must outlive the longest module `cache_ttl`) | fix the config |

## Rebuilding a table

`ace partitions rebuild <table>` repairs a table whose catchall holds data without blocking writes
to it:

1. it creates an empty copy of the table, partitioned for the retention window and the periods
   ahead (instant, because the copy is empty), and starts its `AUTO_INCREMENT` counter well above
   the old table's;
2. it swaps the copy in with one atomic `RENAME TABLE`, so new rows go to the rebuilt table from
   then on, and the old table becomes `<table>__old`;
3. it copies the rows still inside retention back from `<table>__old`, in batches walked along the
   primary key, with a pause between batches;
4. it drops `<table>__old`, and every row past retention with it.

```
ace partitions status
ace partitions rebuild email_archive.archive_index             # shows what it would do
ace partitions rebuild email_archive.archive_index --execute
```

Things to know before running it:

- **It deletes every row past retention.** That is what the daily maintenance would do anyway, but
  on a table that was never maintained it may be most of the table. Raise the retention setting
  first if more should be kept.
- **Lookups miss rows that have not been copied back yet** while step 3 runs, so run it when the
  table is quiet. The copy walks the whole old table once, so it takes time in proportion to the old
  table's size, not to the rows kept. `--batch-size` and `--pause` trade speed against load on the
  server and the replica.
- **Both tables exist until step 4**, so the server needs free disk for the rows kept.
- **It is safe to interrupt.** Running it again finds `<table>__old` and resumes the copy; rows
  already copied are skipped.

## Adding a table

Add a `ManagedTable` to `get_managed_tables()`. MySQL requires the partitioning column in every
unique key of a partitioned table, including the primary key, and does not allow foreign keys on
it. Either partition the table in its migration with only `p_catchall`, or leave it unpartitioned
and let maintenance partition it while it is still empty.
