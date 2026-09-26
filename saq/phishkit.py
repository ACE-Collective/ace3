import logging
import os
import shutil
import threading
import time
import uuid

from celery.exceptions import TimeoutError
from celery.result import AsyncResult

from saq.configuration.config import get_config


def initialize_phishkit():
    from phishkit.phishkit import app
    rabbitmq_user = get_config().rabbitmq.username
    rabbitmq_password = get_config().rabbitmq.password
    rabbitmq_host = get_config().rabbitmq.host
    app.conf.update({
        "broker_url": f"pyamqp://{rabbitmq_user}:{rabbitmq_password}@{rabbitmq_host}//"
    })

# How long a scanner_image_id probe result is reused in this process. The image changes only on
# deploy, so a success is good for a while; a failure is retried sooner, but not on every call:
# each failed probe blocks the caller for the full PROBE_TIMEOUT_SECONDS.
SCANNER_VERSION_SUCCESS_TTL_SECONDS = 600
SCANNER_VERSION_FAILURE_TTL_SECONDS = 60
PROBE_TIMEOUT_SECONDS = 5

# (value, expires_at on the _now() clock) of the last scanner_image_id probe, or None
_scanner_version_cache: tuple[dict, float] | None = None
_scanner_version_lock = threading.Lock()


def _now() -> float:
    """Clock for the scanner version cache; tests patch this."""
    return time.monotonic()


def _reset_scanner_version_cache_for_tests() -> None:
    global _scanner_version_cache
    _scanner_version_cache = None


def ping_phishkit() -> str:
    from phishkit.phishkit import ping as pk_ping
    # expires: a ping nobody is waiting for any more is dropped instead of executed late
    result = pk_ping.apply_async(expires=PROBE_TIMEOUT_SECONDS)
    return result.get(timeout=PROBE_TIMEOUT_SECONDS)


def get_phishkit_scanner_image() -> dict:
    from phishkit.phishkit import scanner_image_id as pk_scanner_image_id
    result = pk_scanner_image_id.apply_async(expires=PROBE_TIMEOUT_SECONDS)
    return result.get(timeout=PROBE_TIMEOUT_SECONDS)


def get_phishkit_scanner_version() -> dict:
    """Scanner identity dict for the phishkit cache key, or {} if the worker can't be asked.

    The answer is cached in this process: a result with an image_id for
    SCANNER_VERSION_SUCCESS_TTL_SECONDS, anything else for SCANNER_VERSION_FAILURE_TTL_SECONDS.
    The lock is held across the probe so concurrent callers wait for one probe instead of each
    sending their own."""
    global _scanner_version_cache
    with _scanner_version_lock:
        if _scanner_version_cache is not None:
            value, expires_at = _scanner_version_cache
            if _now() < expires_at:
                return value

        try:
            value = get_phishkit_scanner_image()
            if not isinstance(value, dict):
                value = {}
        except Exception as e:
            logging.warning("get_phishkit_scanner_version: phishkit scanner image query failed: %s", e)
            value = {}

        ttl = SCANNER_VERSION_SUCCESS_TTL_SECONDS if value.get("image_id") else SCANNER_VERSION_FAILURE_TTL_SECONDS
        _scanner_version_cache = (value, _now() + ttl)
        return value

def _copy_files(source_dir: str, output_dir: str) -> list[str]:
    """Copy all files from source_dir into output_dir, preserving relative paths."""
    os.makedirs(output_dir, exist_ok=True)

    files = []
    for root, _, filenames in os.walk(source_dir):
        for filename in filenames:
            src_path = os.path.join(root, filename)
            relative_path = os.path.relpath(src_path, start=source_dir)
            dest_path = os.path.join(output_dir, relative_path)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            shutil.copy2(src_path, dest_path)
            files.append(dest_path)

    return files

def scan_file(file_path: str, output_dir: str, is_async: bool = False, timeout: float = 15, scanner_timeout: int = 15, proxy: str = None, proxy_fallback_to_direct: bool = False, config_path: str = None) -> str | list[str]:
    from phishkit.phishkit import scan_file as pk_scan_file

    # copy the file to the shared volume so the celery worker can access it
    shared_dir = f"/phishkit/input/{uuid.uuid4()}"
    os.makedirs(shared_dir, exist_ok=True)
    shared_file_path = os.path.join(shared_dir, os.path.basename(file_path))
    shutil.copy2(file_path, shared_file_path)

    # scan the file
    result = pk_scan_file.delay(shared_file_path, timeout=scanner_timeout, proxy=proxy, proxy_fallback_to_direct=proxy_fallback_to_direct, config_path=config_path)

    if is_async:
        return result.id
    else:
        # copy the results from the shared volume
        result_dir = result.get(timeout=timeout)
        return _copy_files(result_dir, output_dir)

def scan_url(url: str, output_dir: str, is_async: bool = False, timeout: float = 15, scanner_timeout: int = 15, proxy: str = None, proxy_fallback_to_direct: bool = False, config_path: str = None) -> str | list[str]:
    from phishkit.phishkit import scan_url as pk_scan_url
    result = pk_scan_url.delay(url, timeout=scanner_timeout, proxy=proxy, proxy_fallback_to_direct=proxy_fallback_to_direct, config_path=config_path)

    if is_async:
        return result.id
    else:
        # copy the results from the shared volume
        result_dir = result.get(timeout=timeout)
        return _copy_files(result_dir, output_dir)

def get_async_scan_result(result_id: str, output_dir: str, timeout: float = 1) -> list[str] | None:
    """Gets the result of a scan asynchronously. Returns the list of files if the scan is complete, otherwise None."""
    from phishkit.phishkit import app

    result = AsyncResult(result_id, app=app)

    # Ask whether the result is stored before asking for it. ready() is a plain
    # read of the backend's result key; get() instead waits on the backend's
    # result consumer, which for redis means draining a pub/sub channel. Polling
    # a not-yet-finished job with get() therefore blocks the calling thread for
    # the whole timeout.
    if not result.ready():
        return None

    try:
        result_dir = result.get(timeout=timeout)
        return _copy_files(result_dir, output_dir)
    except TimeoutError:
        return None

def maintain_files(max_file_age_days: int, timeout: float = 300) -> dict:
    """Run the phishkit file-maintenance task."""
    from phishkit.phishkit import maintain_files as pk_maintain_files
    result = pk_maintain_files.delay(max_file_age_days)
    return result.get(timeout=timeout)


