"""Tests for bin/attach-container.sh, which opens a shell in the dev container."""

import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "bin" / "attach-container.sh"

pytestmark = pytest.mark.unit


def test_in_the_container_says_so_instead_of_failing():
    # the test suite runs in the dev container, which has no docker
    assert Path("/.dockerenv").exists()

    # through bash, because the dev container mounts /tmp noexec
    result = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, timeout=60,
                            stdin=subprocess.DEVNULL)

    assert result.returncode == 0, result.stderr
    assert "already in a container" in result.stdout
