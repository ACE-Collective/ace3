"""tests for component A (the slim postfix-side MDA)."""

import io
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit


def test_writes_atomic_then_renames(amc_mda_s3, tmp_spool, monkeypatch):
    payload = b"From: alice@example.com\r\nSubject: hello\r\n\r\nbody\r\n"
    monkeypatch.setattr(sys, "stdin", type("S", (), {"buffer": io.BytesIO(payload)})())

    final_path = amc_mda_s3.write_email_to_disk(str(tmp_spool))

    assert os.path.exists(final_path)
    assert not os.path.exists(final_path + ".new")
    assert Path(final_path).read_bytes() == payload
    # filename should be the uuid (32 hex chars)
    name = os.path.basename(final_path)
    assert len(name) == 32
    int(name, 16)  # raises if not hex


def test_writes_unique_names_per_invocation(amc_mda_s3, tmp_spool, monkeypatch):
    monkeypatch.setattr(sys, "stdin", type("S", (), {"buffer": io.BytesIO(b"a")})())
    p1 = amc_mda_s3.write_email_to_disk(str(tmp_spool))
    monkeypatch.setattr(sys, "stdin", type("S", (), {"buffer": io.BytesIO(b"b")})())
    p2 = amc_mda_s3.write_email_to_disk(str(tmp_spool))
    assert p1 != p2


def test_main_returns_zero(amc_dir, tmp_spool):
    """end-to-end: invoke the script as a subprocess with stdin piped in."""
    result = subprocess.run(
        [sys.executable, str(amc_dir / "amc_mda_s3.py"), "--spool-dir", str(tmp_spool)],
        input=b"From: x\r\n\r\nbody\r\n",
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    files = [p for p in tmp_spool.iterdir() if not p.name.endswith(".new")]
    assert len(files) == 1


def test_main_returns_nonzero_when_spool_missing(amc_dir, tmp_path):
    """no autocreate: deployment is responsible for ensuring the spool dir exists."""
    missing = tmp_path / "does-not-exist"
    result = subprocess.run(
        [sys.executable, str(amc_dir / "amc_mda_s3.py"), "--spool-dir", str(missing)],
        input=b"x",
        capture_output=True,
        timeout=10,
    )
    assert result.returncode != 0
