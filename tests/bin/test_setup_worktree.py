"""Tests for bin/setup-worktree.sh, which gives a git worktree the integration repositories,
integration test links, local/ and .worktreeinclude files that the main checkout has outside of git.

Each test builds a throwaway main checkout with one integration repository and runs the real
script from a worktree of it.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "bin" / "setup-worktree.sh"
LINK = "test_external_integration_ext"

pytestmark = pytest.mark.unit


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.com", *args],
        cwd=cwd, capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def _run(checkout: Path) -> subprocess.CompletedProcess:
    # through bash, because the dev container mounts /tmp noexec
    return subprocess.run(
        ["bash", str(checkout / "bin" / "setup-worktree.sh")], capture_output=True, text=True, timeout=60
    )


def _add_worktree(main: Path, name: str) -> Path:
    path = main / ".claude" / "worktrees" / name
    _git(main, "worktree", "add", "--quiet", "--detach", str(path))
    return path


@pytest.fixture
def main(tmp_path) -> Path:
    """a main checkout holding the script, one integration repository and its test link"""
    main = tmp_path / "main"
    (main / "bin").mkdir(parents=True)
    shutil.copy2(SCRIPT, main / "bin" / "setup-worktree.sh")
    (main / "tests").mkdir()
    (main / "tests" / "__init__.py").touch()
    (main / ".gitignore").write_text("integrations/\nlocal\ntests/test_external_integration_*\n")
    _git(main, "init", "--quiet", "--initial-branch=main")
    _git(main, "add", ".")
    _git(main, "commit", "--quiet", "-m", "initial")

    ext = main / "integrations" / "ext"
    (ext / "tests").mkdir(parents=True)
    (ext / "tests" / "test_ext.py").touch()
    _git(ext, "init", "--quiet", "--initial-branch=main")
    _git(ext, "add", ".")
    _git(ext, "commit", "--quiet", "-m", "initial")

    (main / "tests" / LINK).symlink_to("../integrations/ext/tests")
    return main


def test_is_executable():
    # the SessionStart hook in .claude/settings.json runs it directly
    assert os.access(SCRIPT, os.X_OK)


def test_sets_up_a_worktree(main):
    worktree = _add_worktree(main, "wt")

    result = _run(worktree)

    assert result.returncode == 0, result.stderr
    integration = worktree / "integrations" / "ext"
    assert _git(integration, "rev-parse", "HEAD") == _git(main / "integrations" / "ext", "rev-parse", "HEAD")
    # detached, so the main checkout's branch stays free to check out anywhere
    assert subprocess.run(["git", "symbolic-ref", "-q", "HEAD"], cwd=integration).returncode != 0
    assert os.readlink(worktree / "tests" / LINK) == "../integrations/ext/tests"
    assert (worktree / "tests" / LINK / "test_ext.py").exists()
    # relative, so it resolves wherever the main checkout is mounted
    assert os.readlink(worktree / "local") == "../../../local"
    assert (worktree / "local").resolve() == (main / "local").resolve()
    assert "integrations/ext: new worktree" in result.stdout
    assert "tests: linked 1" in result.stdout
    assert "local: linked" in result.stdout


def test_a_second_run_changes_nothing_and_prints_nothing(main):
    worktree = _add_worktree(main, "wt")
    _run(worktree)

    result = _run(worktree)

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def test_by_hand_does_not_wait_for_stdin(main):
    # a background shell or another tool can leave stdin open with nothing ever written to it
    worktree = _add_worktree(main, "wt")
    read_end, write_end = os.pipe()
    process = subprocess.Popen(["bash", str(worktree / "bin" / "setup-worktree.sh")], stdin=read_end,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert process.wait(timeout=30) == 0
    except subprocess.TimeoutExpired:
        pytest.fail("the script is still waiting for stdin")
    finally:
        process.kill()
        process.wait(timeout=10)
        os.close(read_end)
        os.close(write_end)

    assert (worktree / "local").is_symlink()


def _run_hook(script_checkout: Path, hook_input: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(script_checkout / "bin" / "setup-worktree.sh"), "--hook"],
                          input=hook_input, capture_output=True, text=True, timeout=60)


def test_hook_sets_up_the_directory_its_input_names(main):
    # the desktop app runs a worktree session's hooks from the main checkout
    worktree = _add_worktree(main, "wt")

    result = _run_hook(main, json.dumps({"cwd": str(worktree)}))

    assert result.returncode == 0, result.stderr
    assert (worktree / "local").is_symlink()


@pytest.mark.parametrize("hook_input", ["", "not json", "{}"])
def test_hook_without_a_usable_cwd_sets_up_its_own_checkout(main, hook_input):
    worktree = _add_worktree(main, "wt")

    result = _run_hook(worktree, hook_input)

    assert result.returncode == 0, result.stderr
    assert (worktree / "local").is_symlink()


def test_the_session_start_hook_runs_in_hook_mode():
    settings = json.loads((SCRIPT.parents[1] / ".claude" / "settings.json").read_text())
    commands = [hook["command"] for group in settings["hooks"]["SessionStart"] for hook in group["hooks"]
                if "setup-worktree.sh" in hook["command"]]

    assert len(commands) == 1
    assert commands[0].endswith("--hook")


def test_does_nothing_in_the_main_checkout(main):
    result = _run(main)

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert not (main / "local").exists()
    assert len(_git(main / "integrations" / "ext", "worktree", "list").splitlines()) == 1


def test_does_nothing_outside_a_git_repository(tmp_path):
    checkout = tmp_path / "plain"
    (checkout / "bin").mkdir(parents=True)
    shutil.copy2(SCRIPT, checkout / "bin" / "setup-worktree.sh")

    # the ceiling keeps git from finding a repository above tmp_path
    result = subprocess.run(
        ["bash", str(checkout / "bin" / "setup-worktree.sh")],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "GIT_CEILING_DIRECTORIES": str(tmp_path)},
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert result.stderr == ""
    assert not (checkout / "local").exists()


def test_leaves_an_existing_local_directory_alone(main):
    worktree = _add_worktree(main, "wt")
    (worktree / "local").mkdir()

    result = _run(worktree)

    assert result.returncode == 0, result.stderr
    assert not (worktree / "local").is_symlink()
    assert "local: linked" not in result.stdout


def test_prunes_the_worktree_of_a_deleted_worktree(main):
    worktree = _add_worktree(main, "wt")
    deleted = _add_worktree(main, "deleted")
    _run(deleted)
    # removing the directory without `git worktree remove`, the way deleting a session's worktree
    # does, leaves the integration repository a record of it
    shutil.rmtree(deleted)

    _run(worktree)

    assert str(deleted) not in _git(main / "integrations" / "ext", "worktree", "list")


def test_refuses_an_absolute_test_link(main):
    (main / "tests" / LINK).unlink()
    (main / "tests" / LINK).symlink_to(main / "integrations" / "ext" / "tests")
    worktree = _add_worktree(main, "wt")

    result = _run(worktree)

    assert result.returncode == 1
    assert "absolute" in result.stderr
    assert not (worktree / "tests" / LINK).exists()


def _with_worktree_include(main: Path, *entries: str):
    (main / ".worktreeinclude").write_text("# a comment\n\n" + "".join(f"{entry}\n" for entry in entries))
    _git(main, "add", ".worktreeinclude")
    _git(main, "commit", "--quiet", "-m", "worktreeinclude")


@pytest.mark.parametrize("location", ["inside", "outside"])
def test_copies_what_worktreeinclude_names(main, tmp_path, location):
    (main / "ssl").mkdir()
    (main / "ssl" / "ca.pem").write_text("the certificate")
    (main / "ssl" / "key.pem").write_text("the key")
    (main / "ssl" / "key.pem").chmod(0o600)
    _with_worktree_include(main, "ssl/")
    worktree = _add_worktree(main, "wt") if location == "inside" else tmp_path / "elsewhere" / "wt"
    if location == "outside":
        _git(main, "worktree", "add", "--quiet", "--detach", str(worktree))

    result = _run(worktree)

    assert result.returncode == 0, result.stderr
    assert (worktree / "ssl" / "ca.pem").read_text() == "the certificate"
    assert (worktree / "ssl" / "key.pem").stat().st_mode & 0o777 == 0o600
    assert not (worktree / "ssl").is_symlink()
    assert "ssl: copied" in result.stdout


def test_leaves_a_worktreeinclude_path_the_worktree_already_has(main):
    (main / "ssl").mkdir()
    (main / "ssl" / "new.pem").touch()
    _with_worktree_include(main, "ssl/")
    worktree = _add_worktree(main, "wt")
    (worktree / "ssl").mkdir()
    (worktree / "ssl" / "existing.pem").touch()

    result = _run(worktree)

    assert result.returncode == 0, result.stderr
    assert sorted(path.name for path in (worktree / "ssl").iterdir()) == ["existing.pem"]
    assert "ssl: copied" not in result.stdout


def test_skips_a_worktreeinclude_path_the_main_checkout_lacks(main):
    _with_worktree_include(main, "ssl/")
    worktree = _add_worktree(main, "wt")

    result = _run(worktree)

    assert result.returncode == 0, result.stderr
    assert not (worktree / "ssl").exists()


def test_reports_a_worktreeinclude_path_it_cannot_copy(main):
    (main / "ssl").mkdir()
    (main / "ssl" / "ca.pem").touch()
    _with_worktree_include(main, "ssl/")
    worktree = _add_worktree(main, "wt")
    (main / "ssl" / "ca.pem").chmod(0o000)

    result = _run(worktree)

    assert result.returncode == 1
    assert "ssl: copied" not in result.stdout
    assert "ca.pem" in result.stderr
