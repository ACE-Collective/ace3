import os
import shutil
import signal
import uuid

import pytest

from saq.environment import get_data_dir

# a tool that never finishes on its own
HANG = "exec sleep 60"


@pytest.fixture
def fake_tools(monkeypatch):
    """Installs shell scripts in place of the external tools a module runs: fake_tools({"upx": HANG})
    puts an upx that never finishes first on the PATH and returns the directory it is in. Every
    script records its pid in <dir>/pids before it runs its body; anything still running at the end
    of the test is killed. The scripts live under the data directory because /tmp is noexec."""
    tool_dir = os.path.join(get_data_dir(), f"fake-tools-{uuid.uuid4()}")
    os.makedirs(tool_dir)
    pid_file = os.path.join(tool_dir, "pids")

    def _install(tools: dict[str, str]) -> str:
        for name, body in tools.items():
            path = os.path.join(tool_dir, name)
            with open(path, "w") as fp:
                fp.write(f"#!/bin/sh\necho $$ >> {pid_file}\n{body}\n")
            os.chmod(path, 0o755)

        monkeypatch.setenv("PATH", f"{tool_dir}{os.pathsep}{os.environ['PATH']}")
        return tool_dir

    yield _install

    if os.path.exists(pid_file):
        with open(pid_file) as fp:
            for line in fp:
                try:
                    os.kill(int(line), signal.SIGKILL)
                except ProcessLookupError:
                    pass  # it finished, or was killed and reaped as it should be

    shutil.rmtree(tool_dir, ignore_errors=True)


def fake_tool_pids(tool_dir: str) -> list[int]:
    """The pids of the fake tools that ran from tool_dir."""
    pid_file = os.path.join(tool_dir, "pids")
    if not os.path.exists(pid_file):
        return []

    with open(pid_file) as fp:
        return [int(line) for line in fp if line.strip()]
