"""A run refuses to start when it is set up for a checkout other than its tests' (tests/unittest_session.py)."""

import os
import subprocess
import sys

import pytest

from tests import session_lock, unittest_session

CHECKOUT = unittest_session.CHECKOUT
SAQ_HERE = os.path.join(CHECKOUT, "saq")

pytestmark = pytest.mark.unit


def test_the_checkout_of_the_tests_is_accepted(monkeypatch):
    monkeypatch.setenv("SAQ_HOME", CHECKOUT)

    assert unittest_session.get_checkout_mismatch(SAQ_HERE) is None


def test_a_link_to_the_checkout_is_the_checkout(monkeypatch, tmp_path):
    os.symlink(CHECKOUT, tmp_path / "link")
    monkeypatch.setenv("SAQ_HOME", str(tmp_path / "link"))

    assert unittest_session.get_checkout_mismatch(str(tmp_path / "link" / "saq")) is None


def test_saq_home_of_another_checkout_is_refused(monkeypatch, tmp_path):
    monkeypatch.setenv("SAQ_HOME", str(tmp_path))

    mismatch = unittest_session.get_checkout_mismatch(SAQ_HERE)

    assert f"SAQ_HOME is {tmp_path}" in mismatch
    assert "saq is imported" not in mismatch
    assert f"export SAQ_HOME={CHECKOUT} PYTHONPATH={CHECKOUT} PATH={CHECKOUT}:{CHECKOUT}/bin:$PATH" in mismatch


def test_without_saq_home_the_working_directory_is_the_project_root(monkeypatch, tmp_path):
    monkeypatch.delenv("SAQ_HOME")
    monkeypatch.chdir(tmp_path)

    assert f"SAQ_HOME is {tmp_path}" in unittest_session.get_checkout_mismatch(SAQ_HERE)


def test_saq_of_another_checkout_is_refused(monkeypatch, tmp_path):
    monkeypatch.setenv("SAQ_HOME", CHECKOUT)

    mismatch = unittest_session.get_checkout_mismatch(str(tmp_path / "saq"))

    assert f"saq is imported from {tmp_path}" in mismatch
    assert "SAQ_HOME is" not in mismatch


def test_a_run_with_saq_home_elsewhere_stops_before_it_takes_the_lock(tmp_path):
    # SAQ_HOME the way the dev image sets it in a worktree that nothing pointed it at
    env = {**os.environ, "SAQ_HOME": str(tmp_path), "PYTHONPATH": CHECKOUT}

    result = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "tests/test_unittest_session.py"],
                            cwd=CHECKOUT, env=env, capture_output=True, text=True, timeout=300,
                            stdin=subprocess.DEVNULL)

    assert result.returncode == pytest.ExitCode.USAGE_ERROR, result.stdout + result.stderr
    assert f"SAQ_HOME is {tmp_path}" in result.stderr
    assert not os.path.exists(tmp_path / session_lock.MARKER_FILENAME)
