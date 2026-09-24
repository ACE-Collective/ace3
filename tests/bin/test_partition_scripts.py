"""Tests for the primary-node gate on the partition maintenance scripts.

Both scripts issue DDL against a database every node shares, and every node runs the cron
file and the etc/cron/<cadence> tasks that call them, so the gate is what keeps a
multi-node cluster to one run.
"""

import os
import subprocess
from pathlib import Path

import pytest

BIN_DIR = Path(__file__).resolve().parents[2] / "bin"

SCRIPTS = [
    "manage-analysis-result-cache-partitions.sh",
    "manage-email-archive-partitions.sh",
]


@pytest.fixture
def fake_mysql(tmp_path):
    """a mysql client on PATH that records each call and fails, so nothing reaches a database"""
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir()
    calls = tmp_path / "mysql-calls"
    mysql = bin_dir / "mysql"
    mysql.write_text(f'#!/usr/bin/env bash\necho "$@" >> {calls}\nexit 1\n')
    mysql.chmod(0o755)
    return bin_dir, calls


def _run(script: str, fake_bin: Path, is_primary: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["ACE_IS_PRIMARY_NODE"] = is_primary
    return subprocess.run(
        [str(BIN_DIR / script)],
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.mark.unit
@pytest.mark.parametrize("script", SCRIPTS)
def test_skips_on_non_primary_node(script, fake_mysql):
    fake_bin, calls = fake_mysql
    result = _run(script, fake_bin, "0")

    assert result.returncode == 0
    assert "not the primary node" in result.stdout
    assert not calls.exists()


@pytest.mark.unit
@pytest.mark.parametrize("script", SCRIPTS)
def test_runs_on_primary_node(script, fake_mysql):
    fake_bin, _ = fake_mysql
    result = _run(script, fake_bin, "1")

    # past the gate the script goes on to its own checks, which fail here (the fake client
    # cannot connect) -- all that matters is that it did not skip
    assert "not the primary node" not in result.stdout + result.stderr
