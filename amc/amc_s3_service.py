#!/usr/bin/env python3
"""amc_s3_service — long-running async service that drains the amc_mda_s3 spool directory.

For each file dropped by amc_mda_s3:
  1. yara-scan the first N KB in a ProcessPoolExecutor worker (CPU-bound, isolated)
  2. on allow: upload to S3 via aioboto3 (key = local UUID), then delete the file
  3. on block: just delete the file

Discovery is via inotify on the spool directory plus a periodic rescan that
recovers signals lost to IN_Q_OVERFLOW or to the service being down.
"""

import argparse
import asyncio
import contextlib
import dataclasses
import logging
import logging.handlers
import os
import signal
import sys
from concurrent.futures import ProcessPoolExecutor
from typing import Optional

import aioboto3
import yara
from asyncinotify import Inotify, Mask
from botocore.config import Config as BotoConfig

ALLOW = "allow"
BLOCK = "block"

logger = logging.getLogger("amc_s3_service")


# --- yara helpers (duplicated from the old script; this subproject is standalone) ---


def get_compiled_yara_rule_path(yara_rule_path: str) -> str:
    return f"{yara_rule_path}c"


def load_yara_rule(yara_rule_path: str) -> yara.Rules:
    compiled_rule_path = get_compiled_yara_rule_path(yara_rule_path)
    if os.path.exists(compiled_rule_path):
        return yara.load(compiled_rule_path)
    return yara.compile(filepath=yara_rule_path)


# --- yara_scan runs inside ProcessPoolExecutor workers; rules are cached per worker ---

_worker_rules: Optional[yara.Rules] = None
_worker_rules_path: Optional[str] = None


def yara_scan(path: str, scan_size_bytes: int, yara_rule_path: Optional[str], default_decision: str) -> str:
    """scan the first scan_size_bytes of `path` and return "allow" or "block".

    runs inside a ProcessPoolExecutor worker. caches compiled rules per worker.
    """
    if not yara_rule_path:
        return default_decision

    global _worker_rules, _worker_rules_path
    if _worker_rules is None or _worker_rules_path != yara_rule_path:
        _worker_rules = load_yara_rule(yara_rule_path)
        _worker_rules_path = yara_rule_path

    with open(path, "rb") as fp:
        data = fp.read(scan_size_bytes)

    decision = default_decision
    for match in _worker_rules.match(data=data):
        for tag in match.tags:
            if tag == BLOCK:
                decision = BLOCK
            elif tag == ALLOW:
                decision = ALLOW
    return decision


# --- service context ---


@dataclasses.dataclass
class ServiceContext:
    s3_client: object
    bucket: Optional[str]
    default_decision: str
    scan_size_bytes: int
    yara_rule_path: Optional[str]
    spool_dir: str
    yara_pool: ProcessPoolExecutor


# --- discovery: inotify + rescan ---


async def inotify_task(spool_dir: str, queue: asyncio.Queue, in_flight: set):
    """watch spool_dir for IN_MOVED_TO and enqueue new file paths."""
    with Inotify() as inotify:
        inotify.add_watch(spool_dir, Mask.MOVED_TO | Mask.Q_OVERFLOW)
        async for event in inotify:
            if Mask.Q_OVERFLOW in event.mask:
                logger.warning("inotify queue overflow; relying on rescan to recover")
                continue

            if event.name is None:
                continue

            name = str(event.name)
            if name.endswith(".new"):
                continue

            path = os.path.join(spool_dir, name)
            if path in in_flight:
                continue

            in_flight.add(path)
            await queue.put(path)


async def rescan_task(spool_dir: str, queue: asyncio.Queue, in_flight: set, interval: float):
    """periodically scan spool_dir for files whose inotify event was missed."""
    while True:
        try:
            for name in os.listdir(spool_dir):
                if name.endswith(".new"):
                    continue
                path = os.path.join(spool_dir, name)
                if path in in_flight:
                    continue
                if not os.path.isfile(path):
                    continue
                in_flight.add(path)
                await queue.put(path)
        except FileNotFoundError:
            logger.warning("spool dir %s does not exist", spool_dir)
        except Exception as e:
            logger.exception("rescan failed: %s", e)

        await asyncio.sleep(interval)


# --- per-email pipeline ---


async def upload_to_s3(ctx: ServiceContext, path: str, key: str):
    """upload `path` to s3 using aioboto3."""
    await ctx.s3_client.upload_file(path, ctx.bucket, key)


async def process_one(path: str, ctx: ServiceContext, in_flight: set):
    try:
        if not os.path.exists(path):
            logger.debug("file %s disappeared before processing", path)
            return

        loop = asyncio.get_running_loop()
        try:
            decision = await loop.run_in_executor(
                ctx.yara_pool,
                yara_scan,
                path,
                ctx.scan_size_bytes,
                ctx.yara_rule_path,
                ctx.default_decision,
            )
        except Exception as e:
            logger.exception("yara scan failed for %s: %s", path, e)
            return

        if decision == BLOCK:
            logger.info("blocking %s", path)
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            return

        if not ctx.bucket:
            logger.warning("no bucket configured; skipping upload of %s", path)
            return

        key = os.path.basename(path)
        try:
            await upload_to_s3(ctx, path, key)
        except Exception as e:
            logger.exception("upload of %s to s3 failed: %s", path, e)
            return

        logger.info("uploaded %s", key)
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    finally:
        in_flight.discard(path)


async def worker_task(queue: asyncio.Queue, in_flight: set, ctx: ServiceContext):
    while True:
        path = await queue.get()
        try:
            await process_one(path, ctx, in_flight)
        except Exception as e:
            logger.exception("worker error processing %s: %s", path, e)
        finally:
            queue.task_done()


# --- s3 client construction ---


def _build_aioboto3_client_kwargs(args) -> dict:
    protocol = "https" if args.secure else "http"
    kwargs = {
        "endpoint_url": f"{protocol}://{args.endpoint}",
        "region_name": args.region,
        "config": BotoConfig(signature_version="s3v4"),
    }
    # explicit keys are only for s3-compatible endpoints; on aws, omit and let
    # the default credential chain (env, ~/.aws, IAM role) resolve them
    if args.access_key and args.secret_key:
        kwargs["aws_access_key_id"] = args.access_key
        kwargs["aws_secret_access_key"] = args.secret_key
    return kwargs


# --- service main ---


async def service_main(args) -> int:
    if not os.path.isdir(args.spool_dir):
        logger.error("spool dir %s does not exist", args.spool_dir)
        return 1

    if bool(args.access_key) ^ bool(args.secret_key):
        logger.error("--access-key and --secret-key must be provided together, or both omitted")
        return 1

    default_decision = BLOCK if args.default_block else ALLOW
    scan_size_bytes = args.scan_size_kb * 1024

    queue: asyncio.Queue = asyncio.Queue()
    in_flight: set[str] = set()

    yara_pool = ProcessPoolExecutor(max_workers=args.max_concurrent_yara)

    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown_event.set)

    async with contextlib.AsyncExitStack() as stack:
        s3_client = None
        if args.bucket:
            session = aioboto3.Session()
            s3_client = await stack.enter_async_context(
                session.client("s3", **_build_aioboto3_client_kwargs(args))
            )

        ctx = ServiceContext(
            s3_client=s3_client,
            bucket=args.bucket,
            default_decision=default_decision,
            scan_size_bytes=scan_size_bytes,
            yara_rule_path=args.yara_rule_path,
            spool_dir=args.spool_dir,
            yara_pool=yara_pool,
        )

        # initial rescan synchronously before we start the listener so cold-start orphans
        # are queued before any new IN_MOVED_TO events
        for name in os.listdir(args.spool_dir):
            if name.endswith(".new"):
                continue
            path = os.path.join(args.spool_dir, name)
            if os.path.isfile(path) and path not in in_flight:
                in_flight.add(path)
                await queue.put(path)

        bg_tasks = [
            asyncio.create_task(inotify_task(args.spool_dir, queue, in_flight), name="inotify"),
            asyncio.create_task(
                rescan_task(args.spool_dir, queue, in_flight, args.rescan_interval_seconds),
                name="rescan",
            ),
        ]
        workers = [
            asyncio.create_task(worker_task(queue, in_flight, ctx), name=f"worker-{i}")
            for i in range(args.max_concurrent_emails)
        ]

        logger.info(
            "amc_s3_service running: spool=%s yara_workers=%d email_workers=%d scan_size=%dKB bucket=%s",
            args.spool_dir,
            args.max_concurrent_yara,
            args.max_concurrent_emails,
            args.scan_size_kb,
            args.bucket,
        )

        await shutdown_event.wait()
        logger.info("shutdown signal received, draining")

        for task in bg_tasks + workers:
            task.cancel()
        await asyncio.gather(*bg_tasks, *workers, return_exceptions=True)

    yara_pool.shutdown(wait=True, cancel_futures=False)
    logger.info("amc_s3_service stopped")
    return 0


# --- argparse / entry point ---


def setup_logging(use_syslog: bool):
    logger.setLevel(logging.INFO)
    if use_syslog and os.path.exists("/dev/log"):
        handler = logging.handlers.SysLogHandler(address="/dev/log")
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(name)s[%(process)d] %(levelname)s %(message)s"))
    logger.addHandler(handler)


def _default_yara_workers() -> int:
    return max(1, (os.cpu_count() or 2) - 1)


def _default_email_workers() -> int:
    return min(32, (os.cpu_count() or 2) + 4)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="async s3 uploader for amc_mda_s3 spool")

    parser.add_argument("--spool-dir", required=True, help="directory to watch for incoming emails")
    parser.add_argument("--rescan-interval-seconds", type=float, default=60,
                        help="how often to rescan the spool dir to catch missed inotify events")

    parser.add_argument(
        "--max-concurrent-yara",
        type=int,
        default=_default_yara_workers(),
        help="max simultaneous yara scans. cpu-bound; default max(1, cpu_count - 1) "
             "to leave one core for the event loop",
    )
    parser.add_argument(
        "--max-concurrent-emails",
        type=int,
        default=_default_email_workers(),
        help="max simultaneous emails being processed end-to-end. i/o-bound; "
             "default min(32, cpu_count + 4)",
    )

    parser.add_argument("--yara-rule-path", help="path to yara rule for filtering")
    parser.add_argument("--scan-size-kb", type=int, default=64,
                        help="scan only the first N kilobytes of each email")
    parser.add_argument("--default-block", action="store_true",
                        help="block by default; only allow content matching yara rules with 'allow' tag")

    parser.add_argument("--bucket", help="s3 bucket to upload to")
    parser.add_argument("--endpoint", default="garagehq:3900", help="s3-compatible endpoint host:port")
    parser.add_argument("--access-key",
                        help="s3 access key. only for s3-compatible endpoints (garage, minio, etc.); "
                             "on aws, omit and let the default credential chain resolve the IAM role")
    parser.add_argument("--secret-key",
                        help="s3 secret key. paired with --access-key; both must be provided together")
    parser.add_argument("--secure", action="store_true", help="use https")
    parser.add_argument("--region", required=True, help="s3 region")

    parser.add_argument("--syslog", action="store_true", help="log to syslog instead of stderr")
    return parser


def main():
    args = build_parser().parse_args()
    setup_logging(args.syslog)
    try:
        sys.exit(asyncio.run(service_main(args)))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
