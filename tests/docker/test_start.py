"""Tests for docker/startup/start.sh, which every ACE container runs first: it waits for the
database and then execs the container's command, and for start_nothing.sh, the dev container's
command, which sources it.

ace is replaced by a shell function that exits with the given codes in turn, because the dev
container mounts /tmp noexec and a stand-in script there could not run.
"""

import os
import shlex
import subprocess
from pathlib import Path

import pytest

from saq.cli.cli_main import EXIT_DATABASE_UNAVAILABLE
from saq.environment import get_base_dir
from tests.saq.helpers import wait_for_condition

START = Path(__file__).resolve().parents[2] / "docker" / "startup" / "start.sh"
START_NOTHING = START.with_name("start_nothing.sh")

pytestmark = pytest.mark.unit


def _script(tmp_path, exit_codes, command: str) -> tuple[str, Path]:
    """bash that runs command with ace replaced by a function exiting with exit_codes in turn, and the
    file each call of it is recorded in"""
    codes = tmp_path / "codes"
    codes.write_text("".join(f"{code}\n" for code in exit_codes))
    calls = tmp_path / "calls"
    calls.touch()
    script = f"""
ace() {{
    echo "$*" >> {shlex.quote(str(calls))}
    local code
    code=$(head -n 1 {shlex.quote(str(codes))})
    sed -i 1d {shlex.quote(str(codes))}
    return "$code"
}}
export -f ace
exec {command}
"""
    return script, calls


def _start(tmp_path, *exit_codes: int, env: dict[str, str] | None = None,
           timeout: int = 60) -> tuple[subprocess.CompletedProcess, list[str]]:
    script, calls = _script(tmp_path, exit_codes, f"bash {shlex.quote(str(START))} echo STARTED")
    result = subprocess.run(["bash", "-c", script], cwd=get_base_dir(), capture_output=True, text=True,
                            timeout=timeout, env=dict(os.environ, **(env or {})))
    return result, calls.read_text().splitlines()


def test_waits_while_the_database_is_unreachable(tmp_path):
    result, calls = _start(tmp_path, EXIT_DATABASE_UNAVAILABLE, EXIT_DATABASE_UNAVAILABLE, 0)

    assert result.returncode == 0, result.stderr
    assert calls == ["test database-connections"] * 3
    assert result.stdout.splitlines()[-1] == "STARTED"


def test_a_failure_waiting_cannot_fix_exits_instead_of_retrying(tmp_path):
    # a configuration error, say: retrying it forever cost a core per attempt and was never restarted
    result, calls = _start(tmp_path, 1, 0)

    assert result.returncode == 1
    assert calls == ["test database-connections"]
    assert "STARTED" not in result.stdout
    assert "ace test database-connections failed with exit code 1" in result.stderr


def test_gives_up_on_a_database_that_stays_unreachable(tmp_path):
    # a hostname that fails TLS verification is as unreachable as a database that is not up yet
    result, calls = _start(tmp_path, *[EXIT_DATABASE_UNAVAILABLE] * 30, env={"ACE_DATABASE_WAIT_SECONDS": "2"},
                           timeout=20)

    assert result.returncode == EXIT_DATABASE_UNAVAILABLE
    assert 2 <= len(calls) < 30
    assert "STARTED" not in result.stdout
    assert "no database reachable after 2 seconds" in result.stderr


def test_dev_stays_up_when_the_wait_fails(tmp_path):
    # dev is the container a broken configuration is fixed and debugged from
    script, calls = _script(tmp_path, [1], f"bash {shlex.quote(str(START_NOTHING))}")
    stderr_path = tmp_path / "stderr"
    with open(stderr_path, "w") as stderr:
        process = subprocess.Popen(["bash", "-c", script], cwd=get_base_dir(), stdout=subprocess.DEVNULL,
                                   stderr=stderr)
    try:
        wait_for_condition(lambda: "dev stays up" in stderr_path.read_text(), timeout=30)
        assert process.poll() is None
    finally:
        process.kill()
        process.wait(timeout=10)

    assert "database wait failed with exit code 1" in stderr_path.read_text()
    assert calls.read_text().splitlines() == ["test database-connections"]
