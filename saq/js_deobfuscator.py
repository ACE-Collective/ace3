"""Client wrapper for the js_deobfuscator celery-backed service.

Mirrors saq/phishkit.py: the manager container (built from
js_deobfuscator/Dockerfile) runs a celery worker that spawns throwaway
scanner containers on demand. ACE analysis modules talk to it through
the helpers here instead of invoking docker directly.

Scans are short (~seconds) so we expose a synchronous ``deobfuscate_file``
and skip the async/delay_analysis dance that phishkit needs.
"""

import os
import shutil
import uuid

from celery.exceptions import TimeoutError
from celery.result import AsyncResult

from saq.configuration.config import get_config

SHARED_INPUT_DIR = "/js-deobfuscator/input"


def initialize_js_deobfuscator():
    from js_deobfuscator.js_deobfuscator import app
    rabbitmq_user = get_config().rabbitmq.username
    rabbitmq_password = get_config().rabbitmq.password
    rabbitmq_host = get_config().rabbitmq.host
    app.conf.update({
        "broker_url": f"pyamqp://{rabbitmq_user}:{rabbitmq_password}@{rabbitmq_host}//"
    })


def ping_js_deobfuscator() -> str:
    from js_deobfuscator.js_deobfuscator import ping as pk_ping
    result = pk_ping.delay()
    return result.get(timeout=5)


def _copy_files(source_dir: str, output_dir: str) -> list[str]:
    """Copy everything under source_dir into output_dir, preserving structure."""
    os.makedirs(output_dir, exist_ok=True)

    files = []
    for root, _, filenames in os.walk(source_dir):
        for filename in filenames:
            src_path = os.path.join(root, filename)
            relative_path = os.path.relpath(src_path, start=source_dir)
            dest_path = os.path.join(output_dir, relative_path)
            os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
            shutil.copy2(src_path, dest_path)
            files.append(dest_path)

    return files


def deobfuscate_file(
    file_path: str,
    output_dir: str,
    is_async: bool = False,
    timeout: float = 60,
    scanner_timeout: int = 30,
) -> str | list[str]:
    """Run the sandbox harness against ``file_path`` in the manager service.

    If ``is_async=True`` returns the celery job id so the caller can poll
    with ``get_async_deobfuscate_result``. Otherwise blocks up to
    ``timeout`` seconds, copies the result files into ``output_dir``, and
    returns the list of copied paths.
    """
    from js_deobfuscator.js_deobfuscator import deobfuscate as pk_deobfuscate

    # copy the file onto the shared volume so the celery worker can see it
    shared_dir = f"{SHARED_INPUT_DIR}/{uuid.uuid4()}"
    os.makedirs(shared_dir, exist_ok=True)
    shared_file_path = os.path.join(shared_dir, os.path.basename(file_path))
    shutil.copy2(file_path, shared_file_path)

    # If html_js_extraction wrote a DOM snapshot beside the script, ship it too.
    # The harness discovers it by the `<input>.dom.json` convention rather than
    # via the celery signature, so no task-signature change is needed. It lets
    # the sandbox resolve document lookups against the source document's real
    # element attributes. (If deob results are ever cached, note the cache key
    # would then need to account for this sidecar's content — neither the
    # extractor nor the deobfuscator is cacheable today.)
    sidecar_path = file_path + ".dom.json"
    if os.path.exists(sidecar_path):
        shutil.copy2(sidecar_path, shared_file_path + ".dom.json")

    result = pk_deobfuscate.delay(shared_file_path, timeout=scanner_timeout)

    if is_async:
        return result.id

    result_dir = result.get(timeout=timeout)
    return _copy_files(result_dir, output_dir)


def get_async_deobfuscate_result(
    result_id: str,
    output_dir: str,
    timeout: float = 1,
) -> list[str] | None:
    """Peek at a pending deobfuscation job. Returns None if not ready."""
    from js_deobfuscator.js_deobfuscator import app

    result = AsyncResult(result_id, app=app)
    try:
        result_dir = result.get(timeout=timeout)
        return _copy_files(result_dir, output_dir)
    except TimeoutError:
        return None
