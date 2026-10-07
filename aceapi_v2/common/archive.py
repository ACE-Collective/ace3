"""Building encrypted zip archives for download endpoints.

Everything ACE hands an analyst as a download is potentially hostile -- an alert's storage
directory and an analysis module crash report both contain, by construction, whatever the
sample was. The archive is encrypted so it survives the trip through the analyst's browser,
mail gateway and endpoint AV as an opaque blob rather than being quarantined (or detonated)
on the way. "infected" is the convention the malware analysis world already uses for this, and
ACE uses the same password for the alert download.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime
from typing import Collection, Optional

from fastapi import HTTPException

from saq.cas.errors import ObjectNotFound
from saq.cas.pool import CASPool
from saq.environment import get_temp_dir

logger = logging.getLogger(__name__)

ZIP_PASSWORD = "infected"

MANIFEST_NAME = "manifest.json"

_SAFE_FILE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_FILE_NAME_LENGTH = 128


def add_to_encrypted_zip(dest: str, cwd: str, target: str, label: str) -> None:
    """Add ``target`` (relative to ``cwd``) to the encrypted zip at ``dest``.

    Running against an existing archive appends to it, so content from different working
    directories can be assembled into one archive under a common prefix.

    ``label`` identifies the subject in log messages (an alert uuid, a crash id).
    """
    proc = subprocess.run(
        ["zip", "-e", "-P", ZIP_PASSWORD, "-r", dest, "--", target],
        cwd=cwd,
        check=False,
        capture_output=True,
    )
    if proc.returncode != 0:
        logger.error(
            "zip failed for %s (rc=%s): %s",
            label,
            proc.returncode,
            proc.stderr.decode(errors="replace"),
        )
        try:
            os.remove(dest)
        except OSError:
            pass
        raise HTTPException(status_code=500, detail="failed to create zip archive")


def remove_stale(path: str) -> None:
    """Remove a leftover archive so ``zip`` builds a new one instead of updating it."""
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


def safe_file_name(file_name: str, reserved: Collection[str] = (MANIFEST_NAME,)) -> str:
    """A name for a file inside a zip that cannot be anything but a plain file name: stored names
    come from the analyzed data. A name in reserved (the archive's own entries next to it) gets a
    prefix."""
    name = _SAFE_FILE_NAME.sub("_", os.path.basename(file_name or "")).lstrip(".")[:_MAX_FILE_NAME_LENGTH]
    if not name:
        return "file"
    if name in reserved:
        return f"file_{name}"
    return name


@dataclass(frozen=True)
class CASArchiveEntry:
    """One directory of a zip built from CAS objects."""
    # the directory under the zip's top-level directory
    directory: str
    # (name inside the directory, digest in the pool) of each file
    members: tuple[tuple[str, str], ...]
    # what the manifest says about the entry when it is skipped
    manifest: dict
    # what the manifest says about it when it is included (with the paths of its members)
    included: dict


def create_encrypted_cas_zip(
    label: str,
    pool: CASPool,
    entries: list[CASArchiveEntry],
    skipped: list[dict],
    *,
    manifest_key: str,
    description: str,
    actor: Optional[str],
    node: Optional[str],
) -> tuple[str, str]:
    """Zip CAS objects, encrypted with the password infected. Returns (zip path, staging
    directory); the caller removes the staging directory, which holds the zip.

    Layout, under one top-level directory named after label:
        manifest.json               what is in the zip (under manifest_key), what was skipped and why
        <entry directory>/<name>    each member of each entry

    An entry with a member that is no longer stored is left out and listed as skipped
    (no_longer_stored); 404 when nothing is left. The plaintext copies are deleted as soon as the
    zip is written."""
    staging = tempfile.mkdtemp(prefix=f"{label[:64]}-", dir=get_temp_dir())
    try:
        top = os.path.join(staging, label)
        os.mkdir(top)

        included, skipped = [], list(skipped)
        for entry in entries:
            entry_path = os.path.join(top, entry.directory)
            os.mkdir(entry_path)
            try:
                for name, digest in entry.members:
                    pool.materialize(digest, os.path.join(entry_path, name))
            except ObjectNotFound:
                # collected or purged since the rows were read
                shutil.rmtree(entry_path, ignore_errors=True)
                skipped.append({**entry.manifest, "reason": "no_longer_stored"})
                continue

            included.append(entry.included)

        if not included:
            raise HTTPException(status_code=404, detail="none of the requested files are stored any more")

        with open(os.path.join(top, MANIFEST_NAME), "w") as fp:
            json.dump({
                "generated_at": datetime.now().isoformat(), "generated_by": actor,
                "generated_on": node, "password": ZIP_PASSWORD,
                manifest_key: included, "skipped": skipped,
            }, fp, indent=2, default=str)

        zip_path = os.path.join(staging, f"{label}.zip")
        add_to_encrypted_zip(zip_path, staging, label, description)
        shutil.rmtree(top, ignore_errors=True)
        return zip_path, staging
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
