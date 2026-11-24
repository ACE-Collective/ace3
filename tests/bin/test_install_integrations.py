"""Tests for bin/install_integrations.sh, which runs each integration's install.sh at image build."""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from tests import unittest_session

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "bin" / "install_integrations.sh"

pytestmark = pytest.mark.unit


@pytest.fixture
def saq_home():
    """a temp SAQ_HOME under this slot's data directory, because the script executes each install.sh
    and pytest's tmp_path is under /tmp, which is mounted noexec in the container"""
    os.makedirs(unittest_session.get_session_data_dir(), exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix="install-integrations-", dir=unittest_session.get_session_data_dir()))
    shutil.copy(ROOT / "load_environment", path / "load_environment")
    yield path
    shutil.rmtree(path, ignore_errors=True)


def _add_integration(path: Path, ran: Path) -> None:
    path.mkdir(parents=True)
    (path / "integration.md").write_text("# Integration\n")
    install = path / "install.sh"
    install.write_text(f"#!/usr/bin/env bash\necho {path} >> {ran}\n")
    install.chmod(0o755)


def test_skips_integrations_under_dot_directories(saq_home):
    # discovery (saq/integration/integration_util.py) never loads these, so the build must not install them
    ran = saq_home / "ran.txt"
    ran.touch()

    integrations = saq_home / "integrations"
    _add_integration(integrations / "repo" / "integration1", ran)
    _add_integration(integrations / "repo" / ".claude" / "worktrees" / "wt" / "integration1", ran)
    _add_integration(integrations / ".hidden", ran)

    result = subprocess.run(["bash", str(SCRIPT)], env={"PATH": "/usr/bin:/bin", "SAQ_HOME": str(saq_home)},
                            capture_output=True, text=True, timeout=30)

    assert result.returncode == 0, result.stderr
    assert ran.read_text().splitlines() == [str(integrations / "repo" / "integration1")]
