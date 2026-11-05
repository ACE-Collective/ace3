"""Tests for bin/exec-in-container.sh, which runs a command in the dev container from the path the
calling checkout has there.

Each test builds a throwaway main checkout holding the real scripts, and replaces docker with a
bash function that answers from what the test says is mounted and records the docker exec.
"""

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
    for script in ("exec-in-container.sh", "get-dev-container.sh"):
        shutil.copy2(BIN / script, main / "bin" / script)
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
