# amc — postfix journal-email collector

Two standalone Python scripts that ingest journal email from postfix, filter
via yara, and upload to S3-compatible storage. This subdirectory is a
self-contained deployable: it does not import from the rest of ACE.

## Components

- **`amc_mda_s3.py`** — invoked per email by postfix/maildrop. Reads stdin,
  writes the email atomically into a spool directory, exits. Designed to be as
  fast as possible so postfix never queues behind it.
- **`amc_s3_service.py`** — long-running asyncio service. Watches the spool
  directory via inotify, runs each new file through yara (in a fixed pool of
  forked worker processes), and uploads passing files to S3. Periodically
  rescans the spool to recover any signals lost to inotify queue overflow or
  to the service being down.

The two communicate purely through the filesystem. Component A's atomic
`<uuid>.new` → `<uuid>` rename is the signal that B consumes.

## Install

```sh
pip install -r requirements.txt
```

The `yara-python` wheel needs the `libyara` system library; install it with
your distro's package manager (`apt install libyara-dev` / `yum install yara`)
before pip install if a wheel isn't available.

## Component A — `amc_mda_s3.py`

```sh
python3 amc_mda_s3.py --spool-dir /var/spool/amc_s3 [--syslog]
```

Flags:
- `--spool-dir` — directory to write incoming emails into. Must already exist.
  Default `/opt/ace/data/var/incoming/amc_s3`.
- `--syslog` — log to syslog instead of stderr.

Postfix invocation typically goes through maildrop; the relevant maildrop
filter just pipes the email into `amc_mda_s3.py --syslog --spool-dir ...`.

## Component B — `amc_s3_service.py`

```sh
python3 amc_s3_service.py \
  --spool-dir /var/spool/amc_s3 \
  --yara-rule-path /etc/amc/journal.yar \
  --bucket journal-emails \
  --endpoint s3.amazonaws.com --secure \
  --region us-east-1 \
  --syslog
```

Key flags:
- `--spool-dir` (required) — directory to watch.
- `--rescan-interval-seconds` (default 60) — how often to sweep the spool dir
  for files inotify missed.
- `--max-concurrent-yara` — max simultaneous yara scans. CPU-bound; default
  `max(1, cpu_count - 1)`.
- `--max-concurrent-emails` — max simultaneous emails being processed
  end-to-end. I/O-bound; default `min(32, cpu_count + 4)`.
- `--scan-size-kb` (default 64) — only scan the first N KB of each email.
- `--yara-rule-path` — yara rule with `allow` / `block` tags. Without it the
  service falls back to `--default-block` (block all) or allow-all.
- `--default-block` — invert the default decision when no rule matches.
- S3: `--bucket`, `--endpoint`, `--secure`,
  `--region` (required). On AWS, credentials come from the IAM role via
  the default credential chain — no flags needed. For S3-compatible
  endpoints (Garage, MinIO, etc.) supply `--access-key` and `--secret-key`
  together.
- `--syslog` — log to syslog instead of stderr.

The S3 key for each upload is the local UUID filename, so an object in S3 can
be traced back to its on-disk file without timestamp correlation.

## Yara rule conventions

- A match tagged `allow` causes the email to be uploaded.
- A match tagged `block` causes the email to be silently dropped (file
  deleted, no upload).
- If both fire, the last one wins (block trumps allow if it matches later).
- No matches → default decision (`allow` unless `--default-block`).

## Suggested systemd unit (sketch)

The actual deployment lives outside this repo. As a starting point:

```ini
[Unit]
Description=amc S3 journal email service
After=network.target

[Service]
Type=simple
User=amc
ExecStart=/usr/bin/python3 /opt/amc/amc_s3_service.py \
  --spool-dir /var/spool/amc_s3 \
  --yara-rule-path /etc/amc/journal.yar \
  --bucket journal-emails \
  --endpoint s3.amazonaws.com --secure \
  --region us-east-1 \
  --syslog
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Tests

```sh
pip install -r requirements.txt
pytest tests/
```

The test suite is fully self-contained — it does not depend on the rest of
the ACE codebase, its database, or its `conftest.py`.
