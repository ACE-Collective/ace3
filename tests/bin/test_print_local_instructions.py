"""Tests for bin/print-local-instructions.sh, which hands the main checkout's AGENTS.local.md to a
session in the main checkout or any of its worktrees."""

import json
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "bin" / "print-local-instructions.sh"

pytestmark = pytest.mark.unit


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example.com", *args],
                   cwd=cwd, capture_output=True, check=True)


def _run(cwd: Path) -> subprocess.CompletedProcess:
    # through bash, because the dev container mounts /tmp noexec
    return subprocess.run(["bash", str(SCRIPT)], cwd=cwd, capture_output=True, text=True, timeout=30)


@pytest.fixture
def main(tmp_path) -> Path:
    main = tmp_path / "main"
    main.mkdir()
    _git(main, "init", "--quiet", "--initial-branch=main")
    _git(main, "commit", "--quiet", "--allow-empty", "-m", "initial")
    return main


def test_is_executable():
    # the SessionStart hooks run it directly
    assert os.access(SCRIPT, os.X_OK)


def test_prints_the_main_checkouts_file_from_a_subdirectory(main):
    (main / "AGENTS.local.md").write_text("Never commit.\n")
    (main / "sub").mkdir()

    result = _run(main / "sub")

    assert result.returncode == 0, result.stderr
    assert result.stdout == "Never commit.\n"


def test_prints_the_main_checkouts_file_in_a_worktree(main, tmp_path):
    # a worktree has no copy of the untracked file, which is why the hook reads the main checkout's
    (main / "AGENTS.local.md").write_text("Never commit.\n")
    worktree = tmp_path / "elsewhere" / "wt"
    _git(main, "worktree", "add", "--quiet", "--detach", str(worktree))
    (worktree / "AGENTS.local.md").write_text("the worktree's own copy\n")

    result = _run(worktree)

    assert result.returncode == 0, result.stderr
    assert result.stdout == "Never commit.\n"


def test_prints_nothing_without_the_file(main):
    result = _run(main)

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def test_prints_nothing_outside_a_git_repository(tmp_path):
    result = _run(tmp_path)

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("hooks_file", [".claude/settings.json", ".codex/hooks.json"])
def test_each_tools_session_start_hook_runs_it(hooks_file):
    settings = json.loads((SCRIPT.parents[1] / hooks_file).read_text())
    commands = [hook["command"] for group in settings["hooks"]["SessionStart"] for hook in group["hooks"]]

    assert sum("print-local-instructions.sh" in command for command in commands) == 1
