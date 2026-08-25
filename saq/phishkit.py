import logging
import os
import shutil
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

def ping_phishkit() -> str:
    from phishkit.phishkit import ping as pk_ping
    result = pk_ping.delay()
    return result.get(timeout=5)


def get_phishkit_scanner_image() -> dict:
    from phishkit.phishkit import scanner_image_id as pk_scanner_image_id
    result = pk_scanner_image_id.delay()
    return result.get(timeout=5)


def get_phishkit_scanner_version() -> dict:
    """Scanner identity dict for the phishkit cache key."""
    try:
        value = get_phishkit_scanner_image()
        return value if isinstance(value, dict) else {}
    except Exception as e:
        logging.warning("get_phishkit_scanner_version: phishkit scanner image query failed: %s", e)
        return {}

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


