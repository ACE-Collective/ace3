# Email archive

ACE keeps a copy of every email the `email_archiver` module sees (files with the `archive`
directive), so that an email can be pulled back later by its Message-ID: the `message_id_analyzer`
does that when an alert names a Message-ID, and `GET /api/v2/email/archive?message_id=` streams one
to an analyst. The code is `saq/email_archive/`.

The archive is not searchable. Searching email (by URL, recipient, sender, subject) happens in the
log platform, from the entry `email_logger` exports for every email, which carries the email's
`message_id`, `env_rcpt_to`, `extracted_urls` and its digest in the pool as `archive_hash`. The
archive answers one question: which email does this Message-ID name.

## What is stored where

- **The email.** Its bytes are an object in the CAS pool named by `email_archive.pool` (default
  `email_archive`, `docs/CAS.md`), and its digest is the sha256 of the email. The pool is encrypted
  with the system key and gzip-compressed (`compression: gzip`). The digest is still that of the
  uncompressed email.
- **Which Message-ID names which email.** `archived_messages` in the email archive database
  (`database_email_archive`) has one row per (hash of the Message-ID, digest, time it was
  archived). It is partitioned by week and dropped by `ace partitions maintain`
  (`docs/DATABASE_PARTITIONS.md`).

Archiving an email is the pool `put` and that one row. `archive_email()` does the `put` first, so a
row never names an email the pool never had. `find_archived_email(message_id)` returns the digest of the newest email
archived under that Message-ID that the pool still has. One Message-ID can name more than one email,
for example a journaled copy and the original.

## Retention

The pool is a `ttl` pool (`docs/CAS.md`, "Retention modes and churn"). An email lives for
`ttl_days` (30) after the last day it was archived, plus `grace_seconds`. The hourly `ace cas gc`
then deletes it. Archiving the same email again renews it. A legal hold (`ace cas hold add
email_archive <sha256> ...`) keeps an email past its ttl.

The rows go a weekly partition at a time, once all of the partition is older than
`email_archive.partition_retention_days` (30). So a Message-ID's rows can outlive its email by up to
a week. A lookup in that week finds the rows but not the email, logs it at INFO, and reports the
email as not archived. `ace partitions maintain` refuses a `partition_retention_days` below the
pool's `ttl_days`, which would drop the Message-ID of an email the pool still has.

The pool's index (`cas_objects`, `cas_touches`, ...) is in the email archive database, not the main
one (`index_database: email_archive`). The email archive is the high-churn store that motivated
keeping a ttl pool's index out of the main database (`docs/SVS_REVIEW.md`, CAS-7).

## Single node and multi-node

`backend: local` means a single-node install: a developer's stack, a test install or a small site.
The CAS index is shared, but a local backend's bytes are on one node's disk, and only the primary
node runs GC. So a cluster of more than one node can't use the local backend for this pool. If it
does, every node except the primary keeps every email it archives until its disk fills. The
`cas.pool` monitor reports `node_local` and `live_nodes` for each pool, and logs an ERROR every run
while a node-local pool has more than one live node (`docs/CAS.md`, "Sharing between nodes").

A multi-node site gives the pool a backend every node can reach, and `shared: true`, in its own
configuration, even if it disables the `email_archiver` module. The CAS has no object-store backend of its own; an integration provides one as a
`custom` backend (`docs/CAS.md`, "Backends"):

```yaml
cas:
  pools:
    email_archive:
      backend: custom
      custom:
        python_module: my_integration.cas_s3
        python_class: S3Backend
        config: { bucket: my-email-archive }
      shared: true
```

S3 archiving through `email_archive.target: s3` was removed. A configuration that still sets it
fails to load, so an S3 site does not fall back to local storage without anyone noticing. Such a
site configures its integration's backend for this pool before it upgrades.

## Migrating from the old archive

Before the CAS, each node wrote the emails it archived to
`<DATA_DIR>/<email_archive.archive_dir>/<hostname>/<sha[:2]>/<sha>.gz.e`, gzip and then encrypted
(`saq.crypto` v0), and indexed them in the `archive`, `archive_index`, `email_history` and
`archive_server` tables. The upgrade creates `archived_messages` empty and drops `email_history`,
which nothing read. An email that has not been migrated cannot be found, so run the migration on
every node that archived email, as soon as the new code is running and within
`partition_retention_days` (after that, partition maintenance has emptied the old tables and the
cron task has deleted the old files):

```bash
ace email-archive migrate --dry-run     # count what would move
ace email-archive migrate               # move it
```

First, the migration copies the Message-ID of every legacy `archive` row into `archived_messages`,
keeping the time it was archived, so it ages out when the legacy row would have. It does this in
batches of `archive_id`, one short transaction each. The legacy tables are shared by every node, so
the first node to run copies them all and the others copy nothing.

Then, for each file, the migration:

- skips the file and leaves it in place when no `archive` row names it any more. Nothing can find
  such an email. The daily `archive` cron task deletes these files after 30 days;
- removes the file if the pool already has the email (an earlier run, or the email was archived
  again since);
- otherwise decrypts and decompresses it, puts the plaintext in the pool (which refuses it if it
  does not hash to the name), and then removes the file.

A file that fails is logged at ERROR, kept, and makes the command exit 2. Running the migration
again retries it. `--keep-source` leaves every file in place, `--limit N` stops after N emails, and
`--archive-dir` reads another directory. The migration is safe to stop and to run again.

A migrated email counts as archived on the day it was migrated, so it lives `ttl_days` from then
rather than from when it was first archived. Its Message-ID row keeps the original date, so the row
can go before the email does; the email is then unreachable and GC deletes it at the end of its ttl.

Nothing writes `archive`, `archive_index` or `archive_server` once the new code runs. Partition
maintenance empties the first two, and a later release drops all three.

The migration needs the encryption key, since it has to decrypt the old files and the pool encrypts
what it stores.

## Code

- `saq/email_archive/archive.py`: archiving, lookups and reading.
- `saq/email_archive/migrate.py`: the migration, which `ace email-archive migrate`
  (`saq/cli/commands/email_archive.py`) runs.
- `saq/modules/email/archive.py`: the `email_archiver` module, which archives each email that has
  a Message-ID. One without is copied to `data/review/rfc822/` and logged at ERROR, since it could
  never be found again.
- `saq/modules/email/message_id.py`: the `message_id_analyzer`, which materializes an archived
  email into an alert.
- `aceapi_v2/email/`: `GET /api/v2/email/archive`. The email is looked up and verified (and
  decrypted into the CAS read cache) before the response starts, so a corrupt email fails the
  request instead of truncating it.

The email log entry that `email_logger` exports (fluent-bit, brocess) carries the email's digest as
`archive_hash`. Its old `archive_path` field named the `.gz.e` file and is gone.

The URL pivot (`url_email_pivot_analyzer`), which counted the archived emails that contained a URL,
and `encrypted_archive_analyzer`, which decrypted a `.gz.e` file of the old archive found in an
alert, were removed with the search tables. Their analyses in existing alerts load as unknown
analyses (`deprecated_modules`).
