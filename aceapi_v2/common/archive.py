"""Building encrypted zip archives for download endpoints.

Everything ACE hands an analyst as a download is potentially hostile -- an alert's storage
directory and an analysis module crash report both contain, by construction, whatever the
sample was. The archive is encrypted so it survives the trip through the analyst's browser,
mail gateway and endpoint AV as an opaque blob rather than being quarantined (or detonated)
on the way. "infected" is the convention the malware analysis world already uses for this, and
ACE uses the same password for the alert download.
"""

import logging
import os
import subprocess

from fastapi import HTTPException

logger = logging.getLogger(__name__)

ZIP_PASSWORD = "infected"


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
