#!/usr/bin/env python3
"""amc_mda_s3 — MDA invoked by postfix/maildrop.

Reads an email from stdin, writes it atomically into the spool directory,
and exits. The atomic rename of <uuid>.new -> <uuid> is the signal that
amc_s3_service consumes via inotify.
"""

import argparse
import logging
import logging.handlers
import os
import shutil
import sys
import uuid


def write_email_to_disk(spool_dir: str) -> str:
    """write stdin to <spool_dir>/<uuid>.new, fsync, rename to <uuid>.

    returns the final path. caller is responsible for ensuring spool_dir exists.
    """
    name = uuid.uuid4().hex
    final_path = os.path.join(spool_dir, name)
    tmp_path = final_path + ".new"

    with open(tmp_path, "wb") as fp:
        shutil.copyfileobj(sys.stdin.buffer, fp)
        fp.flush()
        os.fsync(fp.fileno())

    os.rename(tmp_path, final_path)
    return final_path


def setup_logging(use_syslog: bool) -> logging.Logger:
    logger = logging.getLogger("amc_mda_s3")
    logger.setLevel(logging.INFO)

    if use_syslog and os.path.exists("/dev/log"):
        handler = logging.handlers.SysLogHandler(address="/dev/log")
    else:
        handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(logging.Formatter("%(name)s[%(process)d] %(levelname)s %(message)s"))
    logger.addHandler(handler)
    return logger


def main(args) -> int:
    logger = setup_logging(args.syslog)
    try:
        path = write_email_to_disk(args.spool_dir)
    except Exception as e:
        logger.error("failed to write email to spool dir %s: %s", args.spool_dir, e)
        return 1

    logger.info("stored email %s", path)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="slim MDA: write incoming email to spool dir")
    parser.add_argument(
        "--spool-dir",
        default="/opt/ace/data/var/incoming/amc_s3",
        help="directory where incoming emails are written (must already exist)",
    )
    parser.add_argument("--syslog", action="store_true", help="log to syslog instead of stderr")
    return parser


if __name__ == "__main__":
    sys.exit(main(build_parser().parse_args()))
