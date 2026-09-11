#!/usr/bin/env python3

#
# NOTE this is external to ACE so it doesn't use the saq namespace
#

import argparse
import json
import logging
import mimetypes
import os
import socket
import subprocess
import tempfile
import threading
import time
from subprocess import PIPE, Popen, TimeoutExpired
import uuid
from celery import Celery
from celery.signals import worker_ready, worker_shutting_down
import shutil
from yaml import load, SafeLoader
import magic

logger = logging.getLogger(__name__)

# which ACE instance this worker belongs to. several instances can share one docker daemon, so
# every container we spawn is labelled with this and the reaper only ever looks at its own. the
# worker hostname cannot be used for that: docker-compose.yml pins `hostname: phishkit` on this
# container, so every instance's manager reports the same name.
STACK = os.environ.get("ACE_INSTANCE", "ace")
# the name of the volume we share with the scanner containers we spawn. compose prefixes named
# volumes with the project name, so this is not a constant -- it is passed in as
# ACE_PHISHKIT_VOLUME. the default is the pre-multi-instance name.
PHISHKIT_VOLUME = os.environ.get("ACE_PHISHKIT_VOLUME", "ace-phishkit")

SHARED_CONFIG_DIR = "/phishkit/config"
DEFAULT_CONFIG_PATH = "/opt/ace/etc/phishkit_config.yaml"

DEFAULT_RESOURCE_LIMITS = {
    "container_memory": "2g",
    "container_cpus": "2.0",
    "reaper_max_age_seconds": 600,
    "reaper_interval_seconds": 60,
    # Worst-case scanner_timeout across deployments — drives celery's task
    # time limits (hint * 2 + 60 / hint * 2 + 120). Must always exceed any
    # scanner_timeout set in any saq.yaml or SoftTimeLimitExceeded will
    # preempt subprocess.TimeoutExpired and silently skip retry_on_timeout.
    # Fallback only — the active value lives in etc/phishkit_config.yaml.
    "scanner_timeout_hint": 90,
}


def _load_resource_limits(config_path: str | None = None) -> dict:
    """Load the resource_limits section from the phishkit yaml, falling back to safe defaults."""
    path = config_path or DEFAULT_CONFIG_PATH
    merged = dict(DEFAULT_RESOURCE_LIMITS)
    try:
        with open(path, "r") as fp:
            data = load(fp, Loader=SafeLoader) or {}
        user = data.get("resource_limits") or {}
        if isinstance(user, dict):
            merged.update({k: v for k, v in user.items() if k in DEFAULT_RESOURCE_LIMITS})
    except FileNotFoundError:
        logger.debug("resource_limits config not found at %s, using defaults", path)
    except Exception as e:
        logger.warning("failed to load resource_limits from %s: %s", path, e)
    return merged


# Frozen scanner image content id for ACE's analysis cache key.
_scanner_image: "dict | None" = None


def _inspect_scanner_image() -> dict:
    """inspect the scanner image and return its identity dict.

    returns ``{"image_url": ..., "image_id": ...}`` where ``image_id`` is the
    content id (``{{.Id}}``) of the exact image this worker would ``docker run``
    for a scan, or None when the image is absent locally or docker inspect is
    unavailable.
    """
    image_url = os.environ.get("ACE3_PHISHKIT_IMAGE_URL", "phishkit")
    image_id = None
    try:
        result = subprocess.run(
            ["docker", "inspect", image_url, "--format", "{{.Id}}"],
            capture_output=True, text=True, timeout=5, check=True,
        )
        image_id = result.stdout.strip() or None
    except Exception as e:
        logger.warning("unable to inspect phishkit image %s: %s", image_url, e)

    return {"image_url": image_url, "image_id": image_id}


def get_scanner_image_id() -> dict:
    """Returns the scanner image identity ID."""
    global _scanner_image
    if _scanner_image is not None and _scanner_image.get("image_id"):
        return _scanner_image

    value = _inspect_scanner_image()
    if value.get("image_id"):
        _scanner_image = value

    return value


def _reset_scanner_image_cache_for_tests() -> None:
    global _scanner_image
    _scanner_image = None


def _force_stop_container(name: str) -> None:
    """Best-effort kill and remove a scanner container. Silent if already gone."""
    try:
        subprocess.run(["docker", "kill", name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=10, check=False)
    except Exception as e:
        logger.debug("docker kill %s failed: %s", name, e)
    try:
        subprocess.run(["docker", "rm", "-f", name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=10, check=False)
    except Exception as e:
        logger.debug("docker rm -f %s failed: %s", name, e)


def _graceful_stop_container(name: str) -> None:
    """Best-effort graceful stop: SIGTERM the scanner container and give it a grace
    window to flush partial output before it is killed.

    The scanner installs a SIGTERM handler that flushes requests.json/dom.html/
    metrics.json (marked interrupted) and exits 143, so a timed-out crawl still
    leaves the captured traffic (e.g. redirect/CDN URLs) on disk for ACE to harvest.
    `docker stop` sends SIGTERM and waits up to --time seconds before escalating to
    SIGKILL, so that flush can run; `docker kill` (see _force_stop_container) would
    send an uncatchable SIGKILL and discard the in-memory request log. Silent if the
    container is already gone."""
    try:
        subprocess.run(["docker", "stop", "--time", "5", name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=15, check=False)
    except Exception as e:
        logger.debug("docker stop %s failed: %s", name, e)


def _list_phishkit_containers() -> list[dict]:
    """Return metadata for every running scanner container spawned by *this* ACE instance.

    The stack filter matters: the docker daemon is shared with every other ACE instance on the
    host, so without it this returns their scanner containers too and the reaper kills them.
    """
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "label=phishkit.job_id",
             "--filter", f"label=phishkit.stack={STACK}",
             "--format",
             '{{.ID}}|{{.Names}}|{{.Label "phishkit.started_at"}}|{{.Label "phishkit.worker"}}'],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except Exception as e:
        logger.warning("docker ps for reaper failed: %s", e)
        return []
    containers = []
    for line in result.stdout.splitlines():
        parts = line.split("|", 3)
        if len(parts) != 4:
            continue
        cid, name, started, worker = parts
        try:
            started_at = int(started)
        except ValueError:
            continue
        containers.append({"id": cid, "name": name, "started_at": started_at, "worker": worker})
    return containers


def _reap_orphans(max_age_seconds: int, only_this_worker: bool = False) -> int:
    """Kill this instance's phishkit scanner containers older than max_age_seconds.

    Returns the count killed. Containers belonging to another ACE instance are never considered
    -- see _list_phishkit_containers. Within one instance, only_this_worker narrows further to
    the containers this worker process started.
    """
    now = int(time.time())
    this_worker = socket.gethostname()
    killed = 0
    for c in _list_phishkit_containers():
        if only_this_worker and c["worker"] != this_worker:
            continue
        age = now - c["started_at"]
        if age > max_age_seconds:
            logger.warning("reaping orphan phishkit container %s (age=%ss, worker=%s)",
                           c["name"], age, c["worker"])
            _force_stop_container(c["name"])
            killed += 1
    return killed


_reaper_stop = threading.Event()


def _reaper_loop(max_age: int, interval: int) -> None:
    while not _reaper_stop.wait(interval):
        try:
            _reap_orphans(max_age)
        except Exception as e:
            logger.exception("reaper sweep failed: %s", e)


@worker_ready.connect
def _start_reaper(**_):
    cfg = _load_resource_limits()
    # Floor prevents a mistakenly-small reaper_max_age_seconds from killing jobs that just
    # barely finish on time — must be several multiples of the task timeout plus margin.
    max_age = max(int(cfg["reaper_max_age_seconds"]),
                  int(cfg["scanner_timeout_hint"]) * 4 + 120)
    interval = int(cfg["reaper_interval_seconds"])
    logger.info("phishkit reaper starting: max_age=%ss interval=%ss", max_age, interval)
    try:
        _reap_orphans(max_age)
    except Exception as e:
        logger.exception("initial reaper sweep failed: %s", e)
    threading.Thread(target=_reaper_loop, args=(max_age, interval),
                     daemon=True, name="phishkit-reaper").start()


@worker_ready.connect
def _warm_scanner_image_cache(**_):
    try:
        # go ahead and store at startup instead of waiting for first request
        result = get_scanner_image_id()
        logger.info("phishkit scanner image id resolved: %s", result.get("image_id"))
    except Exception as e:
        logger.warning("failed to resolve scanner image id at startup: %s", e)


@worker_shutting_down.connect
def _shutdown_reaper(**_):
    _reaper_stop.set()
    try:
        _reap_orphans(max_age_seconds=0, only_this_worker=True)
    except Exception as e:
        logger.exception("shutdown reaper sweep failed: %s", e)


def _matched_proxy_error_patterns(stdout: str, stderr: str, error_patterns: list[str]) -> list[str]:
    """Return the subset of error_patterns that appear in stdout/stderr."""
    combined = (stdout or "") + (stderr or "")
    return [pattern for pattern in error_patterns if pattern in combined]


def _matched_proxy_status_code(output_dir: str, proxy_status_codes: list[int]) -> int | None:
    """Return the main page response status code if it indicates a proxy error, else None.

    The main page response is the first entry with type=="response" in requests.json.
    """
    if not proxy_status_codes:
        return None
    requests_path = os.path.join(output_dir, "requests.json")
    try:
        with open(requests_path, "r") as f:
            requests_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
        logger.debug("could not read requests.json from %s: %s", output_dir, e)
        return None

    for entry in requests_data:
        if entry.get("type") == "response":
            status_code = entry.get("status_code")
            if status_code in proxy_status_codes:
                logger.info(
                    "main page returned proxy error status %s in %s",
                    status_code, output_dir,
                )
                return status_code
            return None

    return None


def _sanitize_proxy_for_display(proxy: str | None) -> str | None:
    """Strip user:pass@ credentials from a proxy URL for display.

    Mirrors the redaction in saq/modules/phishkit.py::_redact_proxy_credentials.
    Returns None when no proxy is configured.
    """
    if not proxy:
        return None
    if "@" not in proxy:
        return proxy
    before_at, after_at = proxy.rsplit("@", 1)
    if "://" in before_at:
        scheme = before_at.split("://", 1)[0]
        return f"{scheme}://{after_at}"
    return after_at


def _sync_config(source_path: str | None) -> str | None:
    """Copy phishkit config to a unique file on the shared phishkit volume.

    Each call writes a fresh uniquely-named file so concurrent scans never read
    a partially-written config. Returns the destination path if successful, None
    otherwise. The caller owns the returned file and must delete it after use.
    """
    if not source_path or not os.path.isfile(source_path):
        logger.info("no config found at %s", source_path)
        return None

    dest = None
    try:
        os.makedirs(SHARED_CONFIG_DIR, exist_ok=True)
        fd, dest = tempfile.mkstemp(
            dir=SHARED_CONFIG_DIR, prefix="phishkit_config-", suffix=".yaml")
        os.close(fd)
        shutil.copyfile(source_path, dest)
        logger.info("synced config %s to %s", source_path, dest)
        return dest
    except Exception as e:
        logger.warning("failed to sync config: %s", e)
        if dest is not None:
            try:
                os.remove(dest)
            except OSError:
                pass
        return None


def _run_scanner(
    target_args: list,
    output_dir: str,
    job_id: str,
    timeout: int,
    proxy: str | None,
    proxy_fallback_to_direct: bool,
    config_path: str,
) -> tuple:
    """Run the phishkit scanner, optionally retrying without proxy on proxy errors.

    Returns (stdout, stderr, returncode).
    """
    if not config_path:
        raise ValueError("config_path is required")
    abs_config = os.path.join("/opt/ace", config_path)
    if not os.path.isfile(abs_config):
        raise FileNotFoundError(f"phishkit config not found: {abs_config}")

    with open(abs_config, "r") as f:
        config = load(f, Loader=SafeLoader)
    proxy_fallback = config.get("proxy_fallback", {}) if isinstance(config, dict) else {}
    resource_limits = _load_resource_limits(abs_config)

    synced = _sync_config(abs_config)

    try:
        container_name = f"phishkit-scan-{job_id}"
        worker_hostname = socket.gethostname()

        def build_cmd(use_proxy, out_dir, name):
            mem = resource_limits["container_memory"]
            cmd = [
                "docker",
                "run",
                "--rm",
                "--init",
                "--name", name,
                "--label", f"phishkit.job_id={job_id}",
                "--label", f"phishkit.stack={STACK}",
                "--label", f"phishkit.worker={worker_hostname}",
                "--label", f"phishkit.started_at={int(time.time())}",
                "--memory", str(mem),
                "--memory-swap", str(mem),
                "--cpus", str(resource_limits["container_cpus"]),
                "--stop-timeout", "5",
                "-v",
                f"{PHISHKIT_VOLUME}:/phishkit",
                os.environ.get("ACE3_PHISHKIT_IMAGE_URL", "phishkit"),
                "/opt/venv/bin/python",
                "/opt/app/scanner.py",
                *target_args,
                "--output-dir",
                out_dir,
            ]
            if use_proxy and proxy:
                cmd.extend(["--proxy", proxy])
            if synced:
                cmd.extend(["--config", synced])
            return cmd

        cmd = build_cmd(use_proxy=True, out_dir=output_dir, name=container_name)
        process = Popen(cmd, stdout=PIPE, stderr=PIPE, text=True)

        fallback_reason: str | None = None
        fallback_details: dict = {}
        timed_out = False
        _stdout, _stderr = "", ""

        try:
            try:
                _stdout, _stderr = process.communicate(timeout=timeout)
            except TimeoutExpired:
                logger.warning("phishkit job %s timed out, gracefully stopping container %s", job_id, container_name)
                # SIGTERM (not SIGKILL) so the scanner's _on_term handler can flush
                # partial requests.json/dom.html/metrics.json and exit 143 before the
                # finally-block _force_stop_container reaps the container.
                _graceful_stop_container(container_name)
                try:
                    _stdout, _stderr = process.communicate(timeout=10)
                except TimeoutExpired:
                    process.kill()
                    _stdout, _stderr = process.communicate()
                timed_out = True
                if proxy and proxy_fallback_to_direct and proxy_fallback.get("retry_on_timeout", False):
                    fallback_reason = "timeout"
                    logger.warning("timeout for job %s, retrying without proxy", job_id)
                else:
                    # Don't discard the run. The scanner's SIGTERM handler flushes
                    # partial requests.json/dom.html/metrics.json into output_dir
                    # before the container dies, so fall through to persist
                    # std.out/exit.code/proxy.json and return — ACE can then still
                    # harvest observables (redirect URLs/domains) from the captured
                    # traffic instead of getting an empty result.
                    logger.warning("timeout for job %s, no proxy retry; returning partial results", job_id)
        finally:
            _force_stop_container(container_name)

        if not timed_out:
            for line in _stdout.splitlines():
                logging.info(f"stdout> {line}")

            if process.returncode != 0:
                for line in _stderr.splitlines():
                    logging.info(f"stderr> {line}")

            if proxy and proxy_fallback_to_direct:
                matched_patterns = _matched_proxy_error_patterns(
                    _stdout, _stderr, proxy_fallback.get("error_patterns", []),
                )
                if matched_patterns:
                    fallback_reason = "error_pattern"
                    fallback_details["matched_error_patterns"] = matched_patterns
                    logger.warning("proxy error detected for job %s, retrying without proxy", job_id)
                else:
                    matched_code = _matched_proxy_status_code(
                        output_dir, proxy_fallback.get("proxy_status_codes", []),
                    )
                    if matched_code is not None:
                        fallback_reason = "status_code"
                        fallback_details["matched_status_code"] = matched_code
                        logger.warning("proxy error status code for job %s, retrying without proxy", job_id)

        should_retry = fallback_reason is not None

        if should_retry:
            proxy_stdout = _stdout

            retry_output_dir = f"{output_dir}-direct"
            os.makedirs(retry_output_dir, exist_ok=True)

            retry_container_name = f"phishkit-scan-{job_id}-direct"
            retry_cmd = build_cmd(use_proxy=False, out_dir=retry_output_dir, name=retry_container_name)
            process = Popen(retry_cmd, stdout=PIPE, stderr=PIPE, text=True)
            try:
                try:
                    _stdout, _stderr = process.communicate(timeout=timeout)
                except TimeoutExpired:
                    logger.warning("phishkit job %s (direct retry) timed out, gracefully stopping container %s",
                                   job_id, retry_container_name)
                    # SIGTERM first so the scanner flushes partial output and exits
                    # 143; the finally-block _force_stop_container is the hard backstop.
                    _graceful_stop_container(retry_container_name)
                    try:
                        _stdout, _stderr = process.communicate(timeout=10)
                    except TimeoutExpired:
                        process.kill()
                        _stdout, _stderr = process.communicate()
                    # Same rationale as the proxy attempt above: fall through to
                    # persist + copy back the direct attempt's SIGTERM-flushed
                    # partial output instead of raising it away.
                    logger.warning("direct retry for job %s timed out; returning partial results", job_id)
            finally:
                _force_stop_container(retry_container_name)

            for line in _stdout.splitlines():
                logging.info(f"stdout(direct)> {line}")

            if process.returncode != 0:
                for line in _stderr.splitlines():
                    logging.info(f"stderr(direct)> {line}")

            reason = "timed out" if timed_out else "failed"
            _stdout = f"--- PROXY ATTEMPT ({reason}, retried direct) ---\n{proxy_stdout}\n--- DIRECT ATTEMPT ---\n{_stdout}"

            # copy retry output files into the main output directory
            for entry in os.listdir(retry_output_dir):
                src = os.path.join(retry_output_dir, entry)
                dst = os.path.join(output_dir, entry)
                if os.path.isfile(src):
                    shutil.copy2(src, dst)
                elif os.path.isdir(src):
                    shutil.copytree(src, dst, dirs_exist_ok=True)

        with open(os.path.join(output_dir, "std.out"), "w") as fp:
            fp.write(_stdout)

        with open(os.path.join(output_dir, "std.err"), "w") as fp:
            fp.write(_stderr)

        with open(os.path.join(output_dir, "exit.code"), "w") as fp:
            fp.write(str(process.returncode))

        proxy_status = {
            "configured": bool(proxy),
            "host": _sanitize_proxy_for_display(proxy),
            "fallback_enabled": bool(proxy_fallback_to_direct),
            "fallback_triggered": should_retry,
            "fallback_reason": fallback_reason,
            "fallback_details": fallback_details,
            "final_route": (
                "direct" if should_retry
                else ("proxy" if proxy else "none")
            ),
        }
        with open(os.path.join(output_dir, "proxy.json"), "w") as fp:
            json.dump(proxy_status, fp)

        return _stdout, _stderr, process.returncode
    finally:
        if synced:
            try:
                os.remove(synced)
            except OSError as e:
                logger.warning("failed to remove synced config %s: %s", synced, e)


if os.path.exists("/auth/passwords/redis"):
    with open("/auth/passwords/redis", "r") as fp:
        redis_password = fp.read().strip()
else:
    redis_password = ""

if os.path.exists("/auth/passwords/rabbitmq"):
    with open("/auth/passwords/rabbitmq", "r") as fp:
        rabbitmq_password = fp.read().strip()
else:
    rabbitmq_password = ""

app = Celery(
    "phishkit",
    backend=f"redis://ace3:{redis_password}@redis:6379/7",
    broker=f"pyamqp://ace3:{rabbitmq_password}@rabbitmq//")

app.conf.broker_transport_options = {"global_keyprefix": "phishkit"}

# Celery's task time limits are the safety net only — per-attempt duration is
# enforced by subprocess.communicate(timeout=scanner_timeout) inside _run_scanner.
# _run_scanner's worst case is two attempts (proxy + direct fallback) plus
# container-stop grace, so the soft limit must comfortably exceed
# (2 * scanner_timeout_hint). Without this headroom, SoftTimeLimitExceeded
# preempts subprocess.TimeoutExpired and the retry_on_timeout branch in
# _run_scanner never runs.
_scanner_timeout_hint = int(_load_resource_limits()["scanner_timeout_hint"])
app.conf.task_soft_time_limit = _scanner_timeout_hint * 2 + 60
app.conf.task_time_limit = _scanner_timeout_hint * 2 + 120

@app.task
def ping() -> str:
    return "pong"


@app.task
def scanner_image_id() -> dict:
    """Report the scanner image identity for ACE's analysis cache key.

    Returns ``{"image_url": ..., "image_id": ...}`` for the exact image this
    worker would ``docker run`` for a scan. 
    """
    return get_scanner_image_id()

# immediate subdirectories of these are aged out by maintain_files
PHISHKIT_DATA_DIRS = ("/phishkit/input", "/phishkit/output")


def _delete_aged_dirs(directory: str, cutoff: float) -> list:
    """Delete immediate subdirectories of `directory` whose mtime is older than `cutoff`.

    Returns the list of removed paths.
    """
    removed = []
    if not os.path.isdir(directory):
        return removed
    for entry in os.scandir(directory):
        if not entry.is_dir(follow_symlinks=False):
            continue
        try:
            if entry.stat(follow_symlinks=False).st_mtime >= cutoff:
                continue
            shutil.rmtree(entry.path)
            removed.append(entry.path)
        except OSError as e:
            logger.warning("maintain_files failed to remove %s: %s", entry.path, e)
    return removed


@app.task
def maintain_files(max_file_age_days: int) -> dict:
    """Delete phishkit input/output job directories older than max_file_age_days."""
    cutoff = time.time() - int(max_file_age_days) * 86400
    deleted = {}
    for directory in PHISHKIT_DATA_DIRS:
        removed = _delete_aged_dirs(directory, cutoff)
        logger.info("maintain_files removed %d directories from %s", len(removed), directory)
        deleted[directory] = removed
    return deleted

def _process_output(job_id: str, output_dir: str) -> str:
    """Returns the output directory path for the completed scan job."""
    return output_dir

def _has_recoverable_output(output_dir: str) -> bool:
    """True if the scanner left partial artifacts worth returning to the caller.

    On a timed-out / interrupted scan the scanner's SIGTERM handler flushes
    requests.json (and dom.html/metrics.json) before the container is killed.
    When those exist we want to hand the directory back even on a non-zero exit
    so ACE can extract captured-traffic observables, rather than discarding the
    whole run.
    """
    for name in ("requests.json", "dom.html"):
        if os.path.exists(os.path.join(output_dir, name)):
            return True
    return False

def _correct_file_extension(file_path: str) -> str:
    """Attempts to correct the file extension of the given file based on the mime type.
    If the file extension needs to change, the file is renamed and the new file path is returned.
    If the guess on the mime type or file extension fails, the original file path is returned.
    Otherwise, the original file path is returned."""

    mime_type = magic.from_file(file_path, mime=True)
    if not mime_type:
        return file_path

    logging.info(f"mime type: {mime_type} for {file_path}")

    # libmagic frequently misclassifies HTML fragments (no <!doctype>/<html> wrapper) and
    # other text-based formats as text/plain. "Correcting" such a file to .txt would make the
    # browser render the raw source instead of the page, since Chrome derives the MIME type for
    # file:// URLs from the extension. Never downgrade an existing extension on a low-confidence
    # text/plain guess — trust the extension the caller already assigned (e.g. EmailAnalyzer's
    # .html for an HTML email body).
    _, existing_extension = os.path.splitext(file_path)
    if mime_type == "text/plain" and existing_extension:
        logging.info(f"keeping existing extension {existing_extension} for text/plain {file_path}")
        return file_path

    file_extension = mimetypes.guess_extension(mime_type)
    if not file_extension:
        return file_path

    # NOTE file_extension already has a leading dot
    logging.info(f"file extension: {file_extension} for {file_path}")

    if file_path.lower().endswith(f"{file_extension.lower()}"):
        return file_path

    # create a new file path with the correct extension
    dir_path = os.path.dirname(file_path)
    file_name, _ = os.path.splitext(os.path.basename(file_path))
    new_file_path = f"{dir_path}/{file_name}{file_extension}"
    logging.info(f"correcting file extension from {file_path} to {new_file_path}")
    os.rename(file_path, new_file_path)
    return new_file_path

@app.task
def scan_file(file_path: str, timeout: int = 15, proxy: str = None, proxy_fallback_to_direct: bool = False, config_path: str = None) -> str:
    # create a place to put the file we're going to render in the browser
    job_id = str(uuid.uuid4())
    input_dir = f"/phishkit/input/{job_id}"
    output_dir = f"/phishkit/output/{job_id}"
    os.makedirs(input_dir)
    os.makedirs(output_dir)

    logger.info("started file job %s for %s", job_id, file_path)

    # copy the file into the job input directory
    target_file_path = f"{input_dir}/{os.path.basename(file_path)}"
    shutil.copy2(file_path, target_file_path)

    # correct the file extension
    target_file_path = _correct_file_extension(target_file_path)

    _run_scanner(
        target_args=["--file", target_file_path],
        output_dir=output_dir,
        job_id=job_id,
        timeout=timeout,
        proxy=proxy,
        proxy_fallback_to_direct=proxy_fallback_to_direct,
        config_path=config_path,
    )

    return _process_output(job_id, output_dir)

@app.task
def scan_url(url: str, timeout: int = 15, proxy: str = None, proxy_fallback_to_direct: bool = False, config_path: str = None) -> str:
    # create an output directory for the scan
    job_id = str(uuid.uuid4())
    output_dir = f"/phishkit/output/{job_id}"
    os.makedirs(output_dir)

    logger.info(f"started url job {job_id} for {url}")

    _stdout, _stderr, returncode = _run_scanner(
        target_args=[url],
        output_dir=output_dir,
        job_id=job_id,
        timeout=timeout,
        proxy=proxy,
        proxy_fallback_to_direct=proxy_fallback_to_direct,
        config_path=config_path,
    )

    # A non-zero exit with no recoverable artifacts is a genuine hard failure —
    # raise so ACE records an error. But if the scanner flushed partial output
    # (e.g. a timeout-killed crawl that still captured the redirect chain in
    # requests.json), return the directory so ACE can harvest those observables.
    if returncode != 0 and not _has_recoverable_output(output_dir):
        raise Exception(f"scan failed: {_stderr}")

    return _process_output(job_id, output_dir)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="Load celery configuration from this file.")
    args = parser.parse_args()

    if args.config:
        with open(args.config, "r") as f:
            config = load(f, Loader=SafeLoader)
            if config:
                app.conf.update(config)

    app.worker_main(
        [
            "worker",
            "--loglevel=INFO",
        ]
    )
