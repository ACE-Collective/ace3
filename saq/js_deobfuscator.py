"""Client for the js_deobfuscator celery service.

The manager container (built from js_deobfuscator/Dockerfile) runs a celery
worker that runs each sample in a throwaway scanner container. A scan takes
seconds, so ``deobfuscate_file`` waits for it rather than delaying analysis
the way phishkit's client does.

Tasks go to the broker that js_deobfuscator/js_deobfuscator.py builds its
app with: the user ace3, the host rabbitmq and the password in
/auth/passwords/rabbitmq. This is on purpose. The manager's container never
sees ACE's configuration, so the two sides agree only while both use that
fixed broker. That is why this client doesn't apply ACE's ``rabbitmq``
configuration, although saq/phishkit.py applies it to phishkit's app.
Issue #1100 covers giving both sides one broker setting.
"""

import os
import shutil
import uuid

# the manager's module, and with it celery (~5 MB), is imported where a task is sent: the search indexer and the GUI
# import the js module, and so this one, only to read its analysis

SHARED_INPUT_DIR = "/js-deobfuscator/input"


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
    timeout: float = 60,
    scanner_timeout: int = 30,
    dom_snapshot_path: str | None = None,
) -> list[str]:
    """Run the sandbox harness against ``file_path`` in the manager service.

    ``dom_snapshot_path`` is the DOM snapshot (written by html_js_extraction)
    of the document the script runs in, or None to run it without one.

    Blocks up to ``timeout`` seconds, copies the result files into
    ``output_dir``, and returns the list of copied paths.
    """
    from js_deobfuscator.js_deobfuscator import deobfuscate as pk_deobfuscate

    # copy the file onto the shared volume so the celery worker can see it
    shared_dir = f"{SHARED_INPUT_DIR}/{uuid.uuid4()}"
    os.makedirs(shared_dir, exist_ok=True)
    shared_file_path = os.path.join(shared_dir, os.path.basename(file_path))
    shutil.copy2(file_path, shared_file_path)

    # The harness discovers the snapshot by the `<input>.dom.json` convention
    # rather than via the celery signature, so no task-signature change is
    # needed. It lets the sandbox resolve document lookups against the
    # document's real element attributes and location. (If deob results are
    # ever cached, note the cache key would then need to account for this
    # snapshot's content — neither the extractor nor the deobfuscator is
    # cacheable today.)
    if dom_snapshot_path is not None:
        shutil.copy2(dom_snapshot_path, shared_file_path + ".dom.json")

    result = pk_deobfuscate.delay(shared_file_path, timeout=scanner_timeout)
    result_dir = result.get(timeout=timeout)
    return _copy_files(result_dir, output_dir)


def maintain_files(max_file_age_days: int, timeout: float = 300) -> dict:
    """Run the js-deobfuscator file-maintenance task."""
    # imported here like the other tasks: importing the module builds the celery app
    from js_deobfuscator.js_deobfuscator import maintain_files as jd_maintain_files
    result = jd_maintain_files.delay(max_file_age_days)
    return result.get(timeout=timeout)
