# Email archive

ACE keeps a copy of every email the `email_archiver` module sees (files with the `archive`
directive), so that an email can be pulled back later by its Message-ID: the `message_id_analyzer`
does that when an alert names a Message-ID, and `GET /api/v2/email/archive?message_id=` streams one
to an analyst. The code is `saq/email_archive/`.

## What is stored where

- **The email.** Its bytes are an object in the CAS pool named by `email_archive.pool` (default
  `email_archive`, `docs/CAS.md`), and its digest is the sha256 of the email. The pool is encrypted
  with the system key and gzip-compressed (`compression: gzip`). The digest is still that of the
  uncompressed email.
- **Which Message-ID names which email, and who received it.** These are in the email archive
  database (`database_email_archive`):
  - `archive` has one row per (archiving host, email, time it was archived);
  - `archive_index` maps the hash of a Message-ID, or of a URL found in the email, to `archive` rows;
  - `email_history` maps a Message-ID to the recipients it was delivered to, which remediation uses.

  All three are partitioned by week and dropped by `ace partitions maintain`
  (`docs/DATABASE_PARTITIONS.md`). `archive_server` names the hosts.

`archive_email()` puts the email in the pool before it writes any row, so a row never names an email
the pool never had. `find_archived_email(message_id)` returns the digest of the newest email
archived under that Message-ID that the pool still has. One Message-ID can name more than one email,
for example a journaled copy and the original.

## Retention

The pool is a `ttl` pool (`docs/CAS.md`, "Retention modes and churn"). An email lives for
`ttl_days` (30) after the last day it was archived, plus `grace_seconds`. The hourly `ace cas gc`
then deletes it. Archiving the same email again renews it. A legal hold (`ace cas hold add
email_archive <sha256> ...`) keeps an email past its ttl.

The database rows go a weekly partition at a time, once all of the partition is older than
`email_archive.partition_retention_days` (30). So a Message-ID's rows can outlive its email by up to
a week. A lookup in that week finds the rows but not the email, logs it at INFO, and reports the
email as not archived.

The pool's index (`cas_objects`, `cas_touches`, ...) is in the email archive database, not the main
one (`index_database: email_archive`). The email archive is the high-churn store that motivated
keeping a ttl pool's index out of the main database (`docs/SVS_REVIEW.md`, CAS-7).

## More than one node

`backend: local` keeps an email on the node that archived it. That is enough when one node archives
email. When more than one node archives email, give the pool a backend every node can reach and
`shared: true`, in the site's own configuration. The CAS has no object-store backend of its own, but
an integration can provide one as a `custom` backend (`docs/CAS.md`, "Backends"):

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
fails to load, so an S3 site does not fall back to local storage without anyone noticing.

## Migrating from the old archive

Before the CAS, each node wrote the emails it archived to
`<DATA_DIR>/<email_archive.archive_dir>/<hostname>/<sha[:2]>/<sha>.gz.e`, gzip and then encrypted
(`saq.crypto` v0). An email that has not been migrated cannot be found, so run the migration on
every node that archived email, as soon as the new code is running:

```bash
ace email-archive migrate --dry-run     # count what would move
ace email-archive migrate               # move it
```

For each file, the migration:

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
rather than from when it was first archived.

The migration needs the encryption key, since it has to decrypt the old files and the pool encrypts
what it stores.

## Code

- `saq/email_archive/archive.py`: archiving, lookups and reading.
- `saq/email_archive/migrate.py`: the migration, which `ace email-archive migrate`
  (`saq/cli/commands/email_archive.py`) runs.
- `saq/modules/email/archive.py`: the `email_archiver` module, which archives each email and
  indexes the URLs found in it in post-analysis.
- `saq/modules/email/message_id.py`: the `message_id_analyzer`, which materializes an archived
  email into an alert.
- `aceapi_v2/email/`: `GET /api/v2/email/archive`. The email is looked up and verified (and
  decrypted into the CAS read cache) before the response starts, so a corrupt email fails the
  request instead of truncating it.

The email log entry that `email_logger` exports (fluent-bit, brocess) carries the email's digest as
`archive_hash`. Its old `archive_path` field named the `.gz.e` file and is gone.
