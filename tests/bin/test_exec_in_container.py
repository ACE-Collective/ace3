"""Tests for bin/exec-in-container.sh, which runs a command in the dev container from the path the
calling checkout has there.

Each test builds a throwaway main checkout holding the real scripts. Run from the host, docker is a
bash function that answers from what the test says is mounted and records the docker exec. Run from
inside the dev container, which these tests are, there is no docker.
"""

import getpass
import os
import shutil
import subprocess
from pathlib import Path

import pytest

BIN = Path(__file__).resolve().parents[2] / "bin"

pytestmark = pytest.mark.unit


def _git(cwd: Path, *args: str):
    subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example.com", *args],
                   cwd=cwd, capture_output=True, text=True, check=True)


@pytest.fixture
def main(tmp_path) -> Path:
    main = tmp_path / "main"
    (main / "bin").mkdir(parents=True)
    for script in ("exec-in-container.sh", "get-dev-container.sh", "get-ace-container.sh"):
        shutil.copy2(BIN / script, main / "bin" / script)
    # records which checkout's copy was sourced
    (main / "load_environment").write_text('export SOURCED_LOAD_ENVIRONMENT="${BASH_SOURCE[0]}"\n')
    _git(main, "init", "--quiet", "--initial-branch=main")
    _git(main, "add", ".")
    _git(main, "commit", "--quiet", "-m", "initial")
    return main


def _run(tmp_path: Path, checkout: Path, mounts: dict[Path, str], container: str = "container-id"):
    """Runs the script in checkout. Returns its result and the arguments of the docker exec it ran,
    None if it ran none."""
    record = tmp_path / "docker-exec"
    lines = "".join(f"{source}\\t{destination}\\n" for source, destination in mounts.items())
    docker = (
        '() { case "$1" in\n'
        f"  compose) echo {container} ;;\n"
        f"  inspect) printf '{lines}' ;;\n"
        f'  exec) printf "%s\\n" "$@" > "{record}" ;;\n'
        "esac; }"
    )
    env = {**os.environ, "BASH_FUNC_docker%%": docker}
    # through bash, because the dev container mounts /tmp noexec
    result = subprocess.run(["bash", str(checkout / "bin" / "exec-in-container.sh"), "pytest", "-q"],
                            env=env, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
    return result, record.read_text().splitlines() if record.exists() else None


def _workdir(exec_args: list[str]) -> str:
    return exec_args[exec_args.index("-w") + 1]


def _worktree(main: Path, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    _git(main, "worktree", "add", "--quiet", "--detach", str(path))
    return path


def test_main_checkout_runs_at_opt_ace(main, tmp_path):
    result, exec_args = _run(tmp_path, main, {main: "/opt/ace"})

    assert result.returncode == 0, result.stderr
    assert _workdir(exec_args) == "/opt/ace"
    assert "SAQ_HOME=/opt/ace" in exec_args
    assert "PYTHONPATH=/opt/ace" in exec_args
    assert "container-id" in exec_args
    assert exec_args[-1].endswith("pytest -q")


def test_worktree_inside_the_checkout(main, tmp_path):
    worktree = _worktree(main, main / ".claude" / "worktrees" / "wt")

    # needs no mount of its own, so it does not depend on what docker reports
    result, exec_args = _run(tmp_path, worktree, {})

    assert result.returncode == 0, result.stderr
    assert _workdir(exec_args) == "/opt/ace/.claude/worktrees/wt"
    assert "SAQ_HOME=/opt/ace/.claude/worktrees/wt" in exec_args


def test_worktree_outside_the_checkout_runs_at_its_mount(main, tmp_path):
    worktree = _worktree(main, tmp_path / "elsewhere" / "wt")

    result, exec_args = _run(tmp_path, worktree, {main: "/opt/ace", tmp_path / "elsewhere": "/opt/ace-worktrees"})

    assert result.returncode == 0, result.stderr
    assert _workdir(exec_args) == "/opt/ace-worktrees/wt"
    assert "SAQ_HOME=/opt/ace-worktrees/wt" in exec_args
    assert "PYTHONPATH=/opt/ace-worktrees/wt" in exec_args


def test_worktree_mounted_directly(main, tmp_path):
    worktree = _worktree(main, tmp_path / "elsewhere" / "wt")

    _, exec_args = _run(tmp_path, worktree, {worktree: "/opt/wt"})

    assert _workdir(exec_args) == "/opt/wt"


@pytest.mark.parametrize("first_deepest", [True, False])
def test_deepest_mount_wins(main, tmp_path, first_deepest):
    worktree = _worktree(main, tmp_path / "elsewhere" / "wt")
    mounts = [(worktree, "/deep"), (tmp_path / "elsewhere", "/shallow")]

    _, exec_args = _run(tmp_path, worktree, dict(mounts if first_deepest else reversed(mounts)))

    assert _workdir(exec_args) == "/deep"


def test_worktree_that_is_not_mounted_is_refused(main, tmp_path):
    worktree = _worktree(main, tmp_path / "elsewhere" / "wt")

    result, exec_args = _run(tmp_path, worktree, {main: "/opt/ace"})

    assert result.returncode == 1
    assert exec_args is None
    assert str(worktree) in result.stderr + result.stdout
    assert "docker-compose.override.yml" in result.stderr + result.stdout


def test_a_mount_of_a_sibling_with_the_same_prefix_does_not_match(main, tmp_path):
    worktree = _worktree(main, tmp_path / "elsewhere-2" / "wt")

    result, exec_args = _run(tmp_path, worktree, {tmp_path / "elsewhere": "/opt/ace-worktrees"})

    assert result.returncode == 1
    assert exec_args is None


def test_no_container(main, tmp_path):
    result, exec_args = _run(tmp_path, main, {main: "/opt/ace"}, container="")

    assert result.returncode == 1
    assert exec_args is None
    assert "No development container" in result.stdout + result.stderr


def _created_on_the_other_side(worktree: Path):
    """makes the worktree look the way one created on the other side of the dev container's mount
    does: its .git names a gitdir at a path that does not exist on this side"""
    (worktree / ".git").write_text("gitdir: /the/other/side/.git/worktrees/wt\n")


def test_worktree_created_on_the_other_side_is_refused(main, tmp_path):
    # git cannot open it here, so without the check it would run as the main checkout at /opt/ace
    worktree = _worktree(main, main / ".claude" / "worktrees" / "wt")
    _created_on_the_other_side(worktree)

    result, exec_args = _run(tmp_path, worktree, {main: "/opt/ace"})

    assert result.returncode == 1
    assert exec_args is None
    assert "/the/other/side/.git/worktrees/wt" in result.stderr
    assert "other side" in result.stderr
    # the container is not what is missing
    assert "No development container" not in result.stdout + result.stderr


def test_ace_container_lookup_refuses_a_worktree_created_on_the_other_side(main):
    worktree = _worktree(main, main / ".claude" / "worktrees" / "wt")
    _created_on_the_other_side(worktree)

    result = subprocess.run(["bash", str(worktree / "bin" / "get-ace-container.sh")],
                            capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)

    assert result.returncode == 1
    assert result.stdout == ""
    assert "/the/other/side/.git/worktrees/wt" in result.stderr


REPORT = 'echo "$PWD|$SAQ_HOME|$PYTHONPATH|$VIRTUAL_ENV|$SOURCED_LOAD_ENVIRONMENT"'


def _run_in_container(checkout: Path, *args: str) -> subprocess.CompletedProcess:
    """Runs the script in checkout the way it runs inside the dev container, with no docker."""
    assert Path("/.dockerenv").exists(), "the test suite runs in the dev container"
    env = {name: value for name, value in os.environ.items() if not name.startswith("BASH_FUNC_docker")}
    return subprocess.run(["bash", str(checkout / "bin" / "exec-in-container.sh"), *args],
                          env=env, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)


def test_in_the_container_the_main_checkout_runs_here(main):
    result = _run_in_container(main, REPORT)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"{main}|{main}|{main}|/venv|{main}/load_environment"


@pytest.mark.parametrize("location", ["inside", "outside"])
def test_in_the_container_a_worktree_runs_its_own_code(main, tmp_path, location):
    path = main / ".claude" / "worktrees" / "wt" if location == "inside" else tmp_path / "elsewhere" / "wt"
    worktree = _worktree(main, path)

    # the dev container's PATH has /opt/ace on it, so a bare `source load_environment` would source
    # the main checkout's
    result = _run_in_container(worktree, REPORT)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"{worktree}|{worktree}|{worktree}|/venv|{worktree}/load_environment"


def test_in_the_container_the_arguments_and_exit_status_pass_through(main):
    result = _run_in_container(main, "echo", "two words;", "exit 3")

    assert result.returncode == 3
    assert result.stdout.strip() == "two words"


def test_in_the_container_the_interactive_flags_are_accepted(main):
    result = _run_in_container(main, "-i", "-t", "echo ran")

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ran"


def test_in_the_container_another_user_is_refused(main):
    result = _run_in_container(main, "-u", "root", "echo ran")

    assert result.returncode == 1
    assert "ran" not in result.stdout
    assert "root" in result.stderr


def test_in_the_container_the_current_user_is_accepted(main):
    result = _run_in_container(main, "-u", getpass.getuser(), "echo ran")

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ran"
