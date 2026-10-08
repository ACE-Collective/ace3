"""The sandbox as any caller uses it, with its own config and working directory root."""

import datetime
import os
import uuid

import pytest

from saq.configuration.schema import SandboxConfig
from saq.environment import get_base_dir
from saq.sandbox.launcher import NET_ABI, landlock_abi
from saq.sandbox.runner import (
    build_sandbox_argv,
    create_workdir,
    landlock_available,
    run_sandboxed,
    sandbox_python,
    sweep_stale_workdirs,
)

PYTHON = sandbox_python()


def _run_python(code: str, workdir: str, *args: str, config: SandboxConfig | None = None):
    argv = build_sandbox_argv([PYTHON, "-I", "-c", code, *args], workdir, config or SandboxConfig(), datetime.timedelta(seconds=30))
    return run_sandboxed(argv, None, {"PATH": "/usr/bin:/bin", "HOME": workdir, "TMPDIR": workdir}, workdir, datetime.timedelta(seconds=30), 1024 * 1024)


@pytest.mark.unit
def test_default_config_allows_no_tcp():
    # a caller that does not name ports gets none; the hunt config is the one that opens 443 and 53
    assert SandboxConfig().allowed_tcp_ports == []
    argv = build_sandbox_argv(["/bin/true"], "/nonexistent", SandboxConfig(), datetime.timedelta(seconds=5))
    assert "--tcp-ports=" in argv[:argv.index("--")]


@pytest.mark.unit
def test_workdir_is_created_under_the_callers_root(tmp_path):
    root = str(tmp_path / "svs")
    with create_workdir(root) as workdir:
        assert os.path.dirname(workdir) == root
        assert os.path.isdir(workdir)

    assert not os.path.exists(workdir)


@pytest.mark.unit
@pytest.mark.skipif(not landlock_available(), reason="landlock is unavailable")
def test_command_writes_its_workdir_and_cannot_read_saq_home(tmp_path):
    code = (
        "import os, sys\n"
        "open('out.txt', 'w').write('ok')\n"
        "try:\n"
        "    os.listdir(sys.argv[1])\n"
        "    print('read')\n"
        "except PermissionError:\n"
        "    print('refused')"
    )
    with create_workdir(str(tmp_path)) as workdir:
        result = _run_python(code, workdir, get_base_dir())
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "refused"
        with open(os.path.join(workdir, "out.txt")) as fp:
            assert fp.read() == "ok"


@pytest.mark.unit
@pytest.mark.skipif(landlock_abi() < NET_ABI, reason=f"TCP port rules need Landlock ABI {NET_ABI} (Linux 6.7)")
def test_default_config_refuses_every_tcp_connection(tmp_path):
    code = (
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('127.0.0.1', 443), timeout=5)\n"
        "    print('connected')\n"
        "except PermissionError:\n"
        "    print('refused')\n"
        "except OSError:\n"
        "    print('allowed')"
    )
    with create_workdir(str(tmp_path)) as workdir:
        result = _run_python(code, workdir)
        assert result.stdout.strip() == "refused", result.stderr


@pytest.mark.unit
def test_sweep_removes_only_stale_workdirs(tmp_path):
    # a temp directory, not a real sandbox root: those sit under data_unittest/, a bind mount in the
    # dev container, where a mode-000 directory cannot be chmodded from inside the container -- it
    # would outlive a failed sweep and break every later data directory reset
    root = str(tmp_path)
    stale = os.path.join(root, f"cmd-stale-{uuid.uuid4().hex}")
    fresh = os.path.join(root, f"cmd-fresh-{uuid.uuid4().hex}")
    os.makedirs(os.path.join(stale, "locked"))
    os.makedirs(fresh)
    # a command may leave a directory it made unwritable
    os.chmod(os.path.join(stale, "locked"), 0)
    old = (datetime.datetime.now() - datetime.timedelta(days=2)).timestamp()
    os.utime(stale, (old, old))

    sweep_stale_workdirs(root)

    assert not os.path.exists(stale)
    assert os.path.exists(fresh)


@pytest.mark.unit
def test_sweep_of_a_missing_root_is_a_no_op(tmp_path):
    sweep_stale_workdirs(str(tmp_path / "never-created"))
