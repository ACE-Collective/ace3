"""Tests for bin/exec-in-container.sh, which runs a command from the host in the dev container, at the path
the calling checkout has there, and for the Makefile, which runs its commands the same way.

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
    shutil.copy2(BIN.parent / "Makefile", main / "Makefile")
    # records which checkout's copy was sourced
    (main / "load_environment").write_text(
        'export SOURCED_LOAD_ENVIRONMENT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/load_environment"\n')
    _git(main, "init", "--quiet", "--initial-branch=main")
    _git(main, "add", ".")
    _git(main, "commit", "--quiet", "-m", "initial")
    return main


# a docker exec that runs the command it was given here, in the calling checkout, rather than recording it
_EXEC_HERE = 'exec) while [ "$1" != container-id ]; do shift; done; shift; "$@" ;;'


def _run(tmp_path: Path, checkout: Path, mounts: dict[Path, str], container: str = "container-id",
         args: tuple[str, ...] = ("pytest", "-q"), exec_here: bool = False,
         extra_env: dict[str, str] | None = None):
    """Runs the script in checkout from the host. Returns its result and the arguments of the docker exec
    it ran, None if it ran none (or if exec_here ran the command instead)."""
    record = tmp_path / "docker-exec"
    lines = "".join(f"{source}\\t{destination}\\n" for source, destination in mounts.items())
    exec_case = _EXEC_HERE if exec_here else f'exec) printf "%s\\n" "$@" > "{record}" ;;'
    docker = (
        '() { case "$1" in\n'
        f"  compose) echo {container} ;;\n"
        f"  inspect) printf '{lines}' ;;\n"
        f"  {exec_case}\n"
        "esac; }"
    )
    env = {**os.environ, **(extra_env or {}), "BASH_FUNC_docker%%": docker}
    # through bash, because the dev container mounts /tmp noexec
    result = subprocess.run(["bash", str(checkout / "bin" / "exec-in-container.sh"), *args],
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
    # the command follows the script that bash -c runs, as that script's arguments
    assert exec_args[exec_args.index("container-id") + 1:][-3:] == ["bash", "pytest", "-q"]


def test_the_arguments_and_exit_status_pass_through(main, tmp_path):
    result, _ = _run(tmp_path, main, {main: "/opt/ace"}, exec_here=True,
                     args=("bash", "-c", 'printf "[%s]\\n" "$@"; exit 3', "bash", "two words", "a;b", "$HOME", "*"))

    assert result.returncode == 3, result.stderr
    assert result.stdout.splitlines() == ["[two words]", "[a;b]", "[$HOME]", "[*]"]


def test_the_checkout_s_own_load_environment_is_sourced(main, tmp_path):
    # the dev container's PATH has /opt/ace on it, and source searches PATH first
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "load_environment").write_text("export SOURCED_LOAD_ENVIRONMENT=elsewhere\n")

    result, _ = _run(tmp_path, main, {main: "/opt/ace"}, exec_here=True,
                     extra_env={"PATH": f"{elsewhere}:{os.environ['PATH']}"},
                     args=("bash", "-c", 'echo "$SOURCED_LOAD_ENVIRONMENT|$VIRTUAL_ENV"'))

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"{main}/load_environment|/venv"


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


def _run_in_container(checkout: Path, *args: str, saq_home: str | None = None) -> subprocess.CompletedProcess:
    """Runs the script in checkout the way it runs inside the dev container, with no docker."""
    assert Path("/.dockerenv").exists(), "the test suite runs in the dev container"
    env = {name: value for name, value in os.environ.items() if not name.startswith("BASH_FUNC_docker")}
    if saq_home is not None:
        env["SAQ_HOME"] = saq_home
    return subprocess.run(["bash", str(checkout / "bin" / "exec-in-container.sh"), *args],
                          env=env, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)


@pytest.mark.parametrize("location", ["main", "inside", "outside"])
def test_in_the_container_it_refuses_and_runs_nothing(main, tmp_path, location):
    checkout = {"main": main,
                "inside": main / ".claude" / "worktrees" / "wt",
                "outside": tmp_path / "elsewhere" / "wt"}[location]
    if location != "main":
        _worktree(main, checkout)
    ran = tmp_path / "ran"

    result = _run_in_container(checkout, "-u", getpass.getuser(), "touch", str(ran), "two words",
                               saq_home=str(checkout))

    assert result.returncode == 1
    assert not ran.exists()
    assert "already a container" in result.stderr
    # the command to run instead, from where to run it
    assert f"touch {ran} two\\ words" in result.stderr
    assert str(checkout) in result.stderr
    assert "export SAQ_HOME" not in result.stderr


def test_in_the_container_a_command_line_in_one_argument_is_shown_as_it_is(main):
    result = _run_in_container(main, 'pytest -k "a or b"', saq_home=str(main))

    assert result.returncode == 1
    assert '    pytest -k "a or b"\n' in result.stderr


def test_in_the_container_it_says_when_saq_home_is_another_checkout(main):
    worktree = _worktree(main, main / ".claude" / "worktrees" / "wt")

    result = _run_in_container(worktree, "pytest", saq_home=str(main))

    assert result.returncode == 1
    assert f"SAQ_HOME is {main}" in result.stderr
    assert f"export SAQ_HOME={worktree} PYTHONPATH={worktree} PATH={worktree}:{worktree}/bin:$PATH" in result.stderr


def _make_in_container(checkout: Path, command: str) -> subprocess.CompletedProcess:
    """Runs command the way the Makefile's targets run theirs, through its EXEC, with make in the dev
    container."""
    env = {name: value for name, value in os.environ.items() if not name.startswith("BASH_FUNC_docker")}
    env["SAQ_HOME"] = "/opt/ace"
    return subprocess.run(["make", "--no-print-directory", "-C", str(checkout), "--eval", f"probe:\n\t$(EXEC) {command}", "probe"],
                          env=env, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)


def test_make_in_the_container_runs_in_place_as_the_checkout(main, tmp_path):
    worktree = _worktree(main, main / ".claude" / "worktrees" / "wt")

    result = _make_in_container(worktree, 'bash -c \'echo "$$PWD|$$SAQ_HOME|$$PYTHONPATH|$$SOURCED_LOAD_ENVIRONMENT"\'')

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-1] == f"{worktree}|{worktree}|{worktree}|{worktree}/load_environment"


def test_make_in_the_container_passes_the_arguments_through(main):
    result = _make_in_container(main, 'printf "[%s]\\n" "two words" "a;b"')

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-2:] == ["[two words]", "[a;b]"]
