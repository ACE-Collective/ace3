"""Probe external inputs for cache-key ``extended_version`` use.

Many analysis modules shell out to CLI tools whose version participates in
output correctness (OCR uses ``tesseract``; QR decoding uses ``zbarimg``,
``gs``, ``pdfinfo``). When such a module opts into analysis-result caching,
its ``extended_version`` must include those tool versions so a package
upgrade that changes tool behavior invalidates stale cache entries instead
of silently serving replays produced by the old tool.

``probe_binary_version`` resolves the binary the same way ``Popen`` would
(via ``shutil.which``), runs it once, and caches the result keyed on the
resolved path's ``(st_mtime_ns, st_size)`` — so the subprocess runs at most
once per installed binary, and an upgrade (which replaces the file and moves
its mtime) triggers a fresh probe. See docs/ANALYSIS_CACHING.md ("tool-version
helper").

``file_content_version`` covers the other extended_version flavor: a small
backing file (e.g. the QR URL filter) whose *contents* change module output.
It returns a content sha256 — deterministic across hosts, unlike mtime.
"""

import hashlib
import logging
import os
import shutil
import subprocess
from typing import Optional

# probe cache: (resolved_path, st_mtime_ns, st_size) -> version string or None.
# Negative results are cached too — a broken tool must not be re-spawned on
# every cache-key computation.
_probe_cache: dict[tuple[str, int, int], Optional[str]] = {}

_PROBE_TIMEOUT_SECONDS = 10


def probe_binary_version(name: str, args: Optional[list[str]] = None) -> Optional[str]:
    """Returns a version string for the named CLI tool, or None on any failure.

    The tool is resolved via ``shutil.which`` (recording what ``Popen`` would
    actually run) and invoked with ``args`` (default ``["--version"]``). The
    first non-empty line of stdout — falling back to stderr, since some tools
    (e.g. ``pdfinfo``) print their version there — is returned, stripped.

    Returns None when the tool is missing, times out, or exits non-zero
    (whatever it printed then is an error message, not a version).
    Never raises. Callers building an ``extended_version`` dict should omit
    the tool's key on None: that accepts staleness across an upgrade rather
    than poisoning the cache key with a transient probe failure.
    """
    resolved = shutil.which(name)
    if resolved is None:
        logging.warning("probe_binary_version: tool %s not found on PATH", name)
        return None

    try:
        st = os.stat(resolved)
    except OSError as e:
        logging.warning("probe_binary_version: unable to stat %s: %s", resolved, e)
        return None

    cache_key = (resolved, st.st_mtime_ns, st.st_size)
    if cache_key in _probe_cache:
        return _probe_cache[cache_key]

    version: Optional[str] = None
    try:
        result = subprocess.run(
            [resolved] + (args if args is not None else ["--version"]),
            capture_output=True,
            text=True,
            timeout=_PROBE_TIMEOUT_SECONDS,
        )
        first_line: Optional[str] = None
        for output in (result.stdout, result.stderr):
            for line in output.splitlines():
                if line.strip():
                    first_line = line.strip()
                    break
            if first_line is not None:
                break
        if result.returncode != 0:
            # the first line is usually the tool's complaint about the args, not a version
            logging.warning(
                "probe_binary_version: %s exited with status %d: %s",
                resolved, result.returncode, first_line,
            )
        elif first_line is None:
            logging.warning("probe_binary_version: %s produced no output", resolved)
        else:
            version = first_line
    except (OSError, subprocess.SubprocessError) as e:
        logging.warning("probe_binary_version: failed to probe %s: %s", resolved, e)

    _probe_cache[cache_key] = version
    return version


def file_content_version(path: str) -> Optional[str]:
    """sha256 hex of a (small) file's contents, for ``extended_version`` use.

    Deterministic across hosts for identical content — unlike a file's mtime,
    which a git checkout/pull sets per host (so an mtime fingerprint diverges
    per system for the same content). Any edit — committed or an uncommitted
    working-tree edit — shifts the digest.

    Returns None if the file is missing or unreadable, so the caller omits the
    key: staleness over poisoning the key with a transient read failure. Never
    raises.

    Intended for small files read on every cache-key computation; unlike
    ``probe_binary_version`` it does not memoize. Reading + hashing a tiny
    config file is microseconds, and a memo keyed on ``(mtime, size)`` would
    reintroduce the very per-host mtime dependence this helper removes.
    """
    try:
        with open(path, "rb") as fp:
            return hashlib.sha256(fp.read()).hexdigest()
    except OSError as e:
        logging.warning("file_content_version: unable to read %s: %s", path, e)
        return None


def _reset_probe_cache_for_tests() -> None:
    _probe_cache.clear()
