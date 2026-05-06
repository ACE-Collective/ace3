#!/usr/bin/env python3
"""amc_compile_yara — pre-compile a YARA rule to <path>c.

amc_s3_service loads the compiled .yarc at runtime; this script lets a
deploy / install step compile ahead of time so the service never falls
back to compile-on-the-fly.
"""

import argparse
import logging
import logging.handlers
import os
import sys

import yara


def get_compiled_yara_rule_path(yara_rule_path: str) -> str:
    return f"{yara_rule_path}c"


def compile_yara_rule(yara_rule_path: str, logger: logging.Logger) -> None:
    compiled = get_compiled_yara_rule_path(yara_rule_path)
    if (
        not os.path.exists(compiled)
        or os.path.getmtime(yara_rule_path) > os.path.getmtime(compiled)
    ):
        logger.info("compiling yara rule %s", yara_rule_path)
        rules = yara.compile(filepath=yara_rule_path)
        rules.save(compiled)
    else:
        logger.info("compiled yara rule %s is up to date", compiled)


def setup_logging(use_syslog: bool) -> logging.Logger:
    logger = logging.getLogger("amc_compile_yara")
    logger.setLevel(logging.INFO)
    if use_syslog and os.path.exists("/dev/log"):
        handler = logging.handlers.SysLogHandler(address="/dev/log")
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter("%(name)s[%(process)d] %(levelname)s %(message)s")
    )
    logger.addHandler(handler)
    return logger


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="pre-compile a yara rule for amc_s3_service"
    )
    p.add_argument("--yara-rule-path", required=True, help="path to .yar source")
    p.add_argument(
        "--syslog", action="store_true", help="log to syslog instead of stderr"
    )
    return p


def main(args) -> int:
    logger = setup_logging(args.syslog)
    try:
        compile_yara_rule(args.yara_rule_path, logger)
    except Exception as e:
        logger.error("failed to compile %s: %s", args.yara_rule_path, e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(build_parser().parse_args()))
