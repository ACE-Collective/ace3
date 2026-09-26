import datetime
import json
import os
import shutil
import sys
import tempfile
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from saq.collectors.hunter.correlation import sandbox
from saq.collectors.hunter.correlation.commands import execute_command
from saq.collectors.hunter.correlation.sandbox import (
    get_hunt_source_roots,
    get_read_dirs,
    get_read_files,
    get_sandbox_config,
    get_sandbox_root,
    sweep_stale_workdirs,
)
from saq.collectors.hunter.correlation.schema import CommandConfig
from saq.collectors.hunter.loader import get_compiled_hunt_dir
from saq.environment import get_base_dir, get_data_dir
from saq.util import local_time
from tests.saq.helpers import wait_for_condition

PYTHON = sys.executable


def _run(cmd: CommandConfig, tmpdir, event: dict | None = None, transform_type: str = "event") -> str:
    return execute_command(cmd, event or {}, [], transform_type, [], local_time(), str(tmpdir))


def _python(code: str, *args: str, **kwargs) -> CommandConfig:
    return CommandConfig(type="executable", path=PYTHON, args=["-c", code, *args], **kwargs)


def _limits(**overrides):
    """Patch the sandbox limits for one test."""
    return patch(
        "saq.collectors.hunter.correlation.commands.get_sandbox_config",
        return_value=get_sandbox_config().model_copy(update=overrides),
    )


def _processes_with_marker(marker: str) -> list[int]:
    """pids of live (non-zombie) processes whose command line contains marker"""
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as fp:
                if marker.encode() not in fp.read():
                    continue
            with open(f"/proc/{entry}/stat") as fp:
                if fp.read().rsplit(")", 1)[1].split()[0] == "Z":
                    continue
        except OSError:
            continue
        pids.append(int(entry))
    return pids


_PROBE = """
import json, os, sys
results = {}
for path in sys.argv[1:]:
    try:
        if os.path.isdir(path):
            os.listdir(path)
        else:
            open(path, "rb").read(1)
        results[path] = "readable"
    except OSError as e:
        results[path] = type(e).__name__
print(json.dumps(results))
"""


@pytest.mark.unit
class TestReadAllowlist:
    def test_allowlist_never_names_a_secret_location(self):
        forbidden_roots = [
            os.path.realpath(get_base_dir()),
            os.path.realpath(get_data_dir()),
            "/auth",
            "/home",
            "/proc",
            "/tmp",
            "/docker-entrypoint-initdb.d",
            "/ace-sql-readonly",
        ]
        for path in get_read_dirs() + get_read_files():
            real = os.path.realpath(path)
            for root in forbidden_roots:
                assert os.path.commonpath([real, root]) != root, f"{path} is under {root}"

        assert "/etc" not in get_read_dirs()
        assert "/etc/environment" not in get_read_files()

    def test_secret_locations_are_unreadable(self, tmpdir):
        # a stand-in secret inside the data dir, plus the real locations that exist here
        secret_dir = os.path.join(get_data_dir(), f"sandbox-test-{uuid.uuid4().hex}")
        os.makedirs(secret_dir)
        secret = os.path.join(secret_dir, "password")
        with open(secret, "w") as fp:
            fp.write("hunter2")

        targets = [
            secret,
            os.path.join(get_base_dir(), "etc"),
            "/etc/environment",
            "/proc/1/environ",
            f"/proc/{os.getpid()}/environ",
            "/tmp",
            os.path.expanduser("~"),
            "/auth",
            "/docker-entrypoint-initdb.d",
        ]
        targets = [path for path in targets if os.path.exists(path)]

        try:
            results = json.loads(_run(_python(_PROBE, "/etc/hosts", *targets), tmpdir))
        finally:
            os.remove(secret)
            os.rmdir(secret_dir)

        # the probe itself works: an allowed file is readable
        assert results.pop("/etc/hosts") == "readable"
        assert results == {path: "PermissionError" for path in targets}


@pytest.mark.unit
class TestWrites:
    def test_cannot_delete_or_write_outside_workdir(self, tmpdir):
        target_dir = os.path.join(get_data_dir(), f"sandbox-test-{uuid.uuid4().hex}")
        os.makedirs(target_dir)
        keep = os.path.join(target_dir, "keep")
        with open(keep, "w") as fp:
            fp.write("data")

        code = """
import os, shutil, sys
target = sys.argv[1]
errors = []
for attempt in (
    lambda: shutil.rmtree(target),
    lambda: os.remove(os.path.join(target, "keep")),
    lambda: open(os.path.join(target, "keep"), "w").write("clobbered"),
    lambda: open(os.path.join(target, "new"), "w").write("x"),
):
    try:
        attempt()
        errors.append("allowed")
    except OSError as e:
        errors.append(type(e).__name__)
print(",".join(errors))
"""
        try:
            result = _run(_python(code, target_dir), tmpdir)
            assert result.strip() == ",".join(["PermissionError"] * 4)
            with open(keep) as fp:
                assert fp.read() == "data"
            assert os.listdir(target_dir) == ["keep"]
        finally:
            os.remove(keep)
            os.rmdir(target_dir)

    def test_workdir_is_writable_and_is_home_and_tmpdir(self, tmpdir):
        code = """
import json, os, tempfile
with open("out.txt", "w") as fp:
    fp.write("x")
with tempfile.NamedTemporaryFile() as fp:
    temp_name = fp.name
os.makedirs("sub/dir")
os.rename("out.txt", "sub/dir/out.txt")
print(json.dumps({"cwd": os.getcwd(), "home": os.environ["HOME"], "tmpdir": os.environ["TMPDIR"], "temp": temp_name}))
"""
        result = json.loads(_run(_python(code), tmpdir))
        assert result["home"] == result["cwd"] == result["tmpdir"]
        assert result["temp"].startswith(result["cwd"])
        assert os.path.dirname(result["cwd"]) == get_sandbox_root()
        # the working directory is removed afterwards
        assert not os.path.exists(result["cwd"])

    def test_user_env_can_override_home(self, tmpdir):
        cmd = _python("import os; print(os.environ['HOME'])", env={"HOME": "/nowhere"})
        assert _run(cmd, tmpdir).strip() == "/nowhere"


@pytest.mark.unit
class TestLimits:
    def test_memory_limit(self, tmpdir):
        with _limits(memory_limit=256 * 1024 ** 2):
            with pytest.raises(RuntimeError, match="MemoryError"):
                _run(_python("x = bytearray(512 * 1024 ** 2)"), tmpdir)

    def test_file_size_limit(self, tmpdir):
        with _limits(file_size_limit=1024 ** 2):
            with pytest.raises(RuntimeError, match="exited with code"):
                _run(_python("open('big', 'wb').write(b'x' * 2 * 1024 ** 2)"), tmpdir)

    def test_output_limit(self, tmpdir):
        with _limits(max_output_bytes=1024 ** 2):
            with pytest.raises(RuntimeError, match="more than 1048576 bytes"):
                _run(_python("import sys\nwhile True: sys.stdout.write('x' * 65536)"), tmpdir)

    def test_stdin_is_empty_without_input(self, tmpdir):
        cmd = _python("import sys; print(len(sys.stdin.read()))", timeout="10s")
        assert _run(cmd, tmpdir).strip() == "0"

    def test_stdin_input_still_delivered(self, tmpdir):
        cmd = _python("import sys; print(sys.stdin.read())", stdin=True)
        assert json.loads(_run(cmd, tmpdir, event={"a": 1})) == {"a": 1}


@pytest.mark.unit
class TestProcessCleanup:
    _SPAWN = """
import subprocess, sys
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)", sys.argv[1]], {redirect})
print(child.pid, flush=True)
{after}
"""

    def test_background_process_killed_after_exit(self, tmpdir):
        marker = f"sandbox-marker-{uuid.uuid4().hex}"
        code = self._SPAWN.format(redirect="stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL", after="")
        _run(_python(code, marker), tmpdir)
        wait_for_condition(lambda: not _processes_with_marker(marker), timeout=10)

    def test_background_process_killed_after_timeout(self, tmpdir):
        marker = f"sandbox-marker-{uuid.uuid4().hex}"
        # the child inherits stdout, so it would also hold the pipe open if it survived
        code = self._SPAWN.format(redirect="", after="import time; time.sleep(300)")
        with pytest.raises(RuntimeError, match="timed out"):
            _run(_python(code, marker, timeout="2s"), tmpdir)
        wait_for_condition(lambda: not _processes_with_marker(marker), timeout=10)


@pytest.fixture
def hunt_repo(tmp_path):
    """A stand-in hunt repository, registered as the only hunt source root."""
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    with patch("saq.collectors.hunter.correlation.sandbox.get_hunt_source_roots", return_value=[str(repo)]):
        yield repo


@pytest.mark.unit
class TestStaging:
    def test_script_runs_with_its_files(self, hunt_repo, tmpdir):
        script = hunt_repo / "scripts" / "tool.py"
        script.write_text(
            f"#!{PYTHON}\n"
            "import json\nfrom pathlib import Path\n"
            "print(json.load(open(Path(__file__).parent / 'data' / 'values.json'))['value'])\n"
        )
        script.chmod(0o755)
        (hunt_repo / "scripts" / "data").mkdir()
        (hunt_repo / "scripts" / "data" / "values.json").write_text('{"value": "staged"}')

        cmd = CommandConfig(
            type="executable",
            path=str(script),
            files=[str(hunt_repo / "scripts" / "data" / "values.json")],
        )
        assert _run(cmd, tmpdir).strip() == "staged"

    def test_file_outside_the_hunt_repositories_is_rejected(self, hunt_repo, tmp_path, tmpdir):
        secret = tmp_path / "secret"
        secret.write_text("hunter2")
        cmd = CommandConfig(type="executable", path="/usr/bin/cat", args=["secret"], files=[str(secret)])
        with pytest.raises(RuntimeError, match="outside the hunt repositories"):
            _run(cmd, tmpdir)

    def test_symlink_out_of_the_repository_is_rejected(self, hunt_repo, tmp_path, tmpdir):
        secret = tmp_path / "secret"
        secret.write_text("hunter2")
        link = hunt_repo / "scripts" / "innocent.json"
        link.symlink_to(secret)
        cmd = CommandConfig(type="executable", path="/usr/bin/cat", args=["innocent.json"], files=[str(link)])
        with pytest.raises(RuntimeError, match="outside the hunt repositories"):
            _run(cmd, tmpdir)

    def test_script_outside_the_hunt_repositories_is_rejected(self, hunt_repo, tmp_path, tmpdir):
        script = tmp_path / "elsewhere.py"
        script.write_text(f"#!{PYTHON}\nprint('ran')\n")
        script.chmod(0o755)
        cmd = CommandConfig(type="executable", path=str(script))
        with pytest.raises(RuntimeError, match="outside the hunt repositories"):
            _run(cmd, tmpdir)

    def test_validation_api_script_runs_but_reads_nothing_of_ace(self, tmpdir):
        """What an agent submits through /api/hunt/validate is materialized under the compiled hunt
        dir: it must be stageable from there, and still see neither secrets nor other submissions."""
        compiled_dir = tempfile.mkdtemp(dir=get_compiled_hunt_dir())
        other_submission = tempfile.mkdtemp(dir=get_compiled_hunt_dir())
        try:
            script = os.path.join(compiled_dir, "scripts", "probe.py")
            os.makedirs(os.path.dirname(script))
            with open(script, "w") as fp:
                fp.write(f"#!{PYTHON}\n{_PROBE}")
            os.chmod(script, 0o755)

            targets = [compiled_dir, other_submission, os.path.join(get_base_dir(), "etc")]
            results = json.loads(_run(CommandConfig(type="executable", path=script, args=["/etc/hosts", *targets]), tmpdir))
        finally:
            shutil.rmtree(compiled_dir)
            shutil.rmtree(other_submission)

        assert results.pop("/etc/hosts") == "readable"
        assert results == {path: "PermissionError" for path in targets}

    def test_bare_command_name_resolves_on_path(self, tmpdir):
        cmd = CommandConfig(type="executable", path="echo", args=["hello"])
        assert _run(cmd, tmpdir).strip() == "hello"


@pytest.mark.unit
class TestHuntSourceRoots:
    def _config(self, *rule_dirs):
        return SimpleNamespace(hunt_types=[SimpleNamespace(rule_dirs=list(rule_dirs))])

    def test_git_dir_preferred_over_rule_dir(self, tmp_path):
        entry = SimpleNamespace(rule_dir=str(tmp_path / "repo" / "hunts"), git_dir=str(tmp_path / "repo"))
        with patch("saq.collectors.hunter.correlation.sandbox.get_config", return_value=self._config(entry)):
            roots = get_hunt_source_roots()
        assert str(tmp_path / "repo") in roots
        assert str(tmp_path / "repo" / "hunts") not in roots

    def test_root_containing_saq_home_is_ignored(self):
        entry = SimpleNamespace(rule_dir="signatures/hunts", git_dir=".")
        with patch("saq.collectors.hunter.correlation.sandbox.get_config", return_value=self._config(entry)):
            roots = get_hunt_source_roots()
        assert os.path.realpath(get_base_dir()) not in roots
        assert "/" not in roots


@pytest.mark.unit
class TestFailClosed:
    def test_no_landlock_means_no_execution(self, tmpdir):
        with patch("saq.collectors.hunter.correlation.commands.landlock_available", return_value=False), \
             patch("saq.collectors.hunter.correlation.commands.run_sandboxed") as run_sandboxed:
            with pytest.raises(RuntimeError, match="landlock is unavailable"):
                _run(_python("print('ran')"), tmpdir)
        run_sandboxed.assert_not_called()

    def test_landlock_is_available_here(self):
        # the rest of this file proves nothing if the probe is wrong
        assert sandbox.landlock_available()


@pytest.mark.unit
class TestSweep:
    def test_removes_only_stale_workdirs(self):
        root = get_sandbox_root()
        stale = os.path.join(root, f"cmd-stale-{uuid.uuid4().hex}")
        fresh = os.path.join(root, f"cmd-fresh-{uuid.uuid4().hex}")
        os.makedirs(os.path.join(stale, "locked"))
        os.makedirs(fresh)
        # a command may leave a directory it made unwritable
        os.chmod(os.path.join(stale, "locked"), 0)
        old = (datetime.datetime.now() - datetime.timedelta(days=2)).timestamp()
        os.utime(stale, (old, old))

        try:
            sweep_stale_workdirs()
            assert not os.path.exists(stale)
            assert os.path.exists(fresh)
        finally:
            os.rmdir(fresh)
