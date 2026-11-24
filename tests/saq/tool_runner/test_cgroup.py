import os
import subprocess

import pytest

from saq.tool_runner import cgroup as cgroup_module
from saq.tool_runner.cgroup import TASKS_LIMIT, CgroupUnavailable, RunCgroups, memory_budget, own_cgroup


def _proc_cgroup(tmp_path, path: str) -> str:
    proc = tmp_path / "cgroup"
    proc.write_text(f"0::{path}\n")
    return str(proc)


def _fake_hierarchy(tmp_path, subtree_control: str | None = "memory pids") -> str:
    root = tmp_path / "root"
    (root / "tools" / "service").mkdir(parents=True)
    if subtree_control is not None:
        (root / "tools" / "cgroup.subtree_control").write_text(f"{subtree_control}\n")
    return str(root)


@pytest.mark.unit
def test_own_cgroup_is_the_v2_entry(tmp_path):
    proc = tmp_path / "cgroup"
    proc.write_text("1:name=systemd:/legacy\n0::/tools/service\n")

    assert own_cgroup(str(proc)) == "/tools/service"


@pytest.mark.unit
def test_own_cgroup_without_a_v2_hierarchy(tmp_path):
    proc = tmp_path / "cgroup"
    proc.write_text("1:name=systemd:/legacy\n")

    with pytest.raises(CgroupUnavailable, match="not in a cgroup v2 hierarchy"):
        own_cgroup(str(proc))


@pytest.mark.unit
def test_the_delegated_subtree_is_the_parent_of_this_process_cgroup(tmp_path):
    root = _fake_hierarchy(tmp_path)

    cgroups = RunCgroups.delegated(root, _proc_cgroup(tmp_path, "/tools/service"))

    assert cgroups.parent == os.path.join(root, "tools")


@pytest.mark.unit
def test_a_process_in_the_containers_root_cgroup_was_not_delegated_one(tmp_path):
    with pytest.raises(CgroupUnavailable, match="delegate-cgroup.sh"):
        RunCgroups.delegated(_fake_hierarchy(tmp_path), _proc_cgroup(tmp_path, "/"))


@pytest.mark.unit
@pytest.mark.parametrize("subtree_control,message", [
    (None, "cannot read the controllers"),
    ("memory", "does not enable the pids controller"),
    ("", "does not enable the memory, pids controller"),
])
def test_a_subtree_without_the_controllers_is_refused(tmp_path, subtree_control, message):
    root = _fake_hierarchy(tmp_path, subtree_control)

    with pytest.raises(CgroupUnavailable, match=message):
        RunCgroups.delegated(root, _proc_cgroup(tmp_path, "/tools/service"))


@pytest.mark.unit
def test_a_subtree_this_user_cannot_write_is_refused(tmp_path):
    root = _fake_hierarchy(tmp_path)
    os.chmod(os.path.join(root, "tools"), 0o500)
    try:
        with pytest.raises(CgroupUnavailable, match="not writable"):
            RunCgroups.delegated(root, _proc_cgroup(tmp_path, "/tools/service"))
    finally:
        os.chmod(os.path.join(root, "tools"), 0o700)


@pytest.mark.unit
def test_the_memory_budget_is_the_containers_limit(tmp_path):
    (tmp_path / "memory.max").write_text("1073741824\n")

    assert memory_budget(str(tmp_path), "/nonexistent") == 1024 ** 3


@pytest.mark.unit
@pytest.mark.parametrize("limit", ["max\n", None])
def test_without_a_container_limit_the_budget_is_the_hosts_memory(tmp_path, limit):
    if limit is not None:
        (tmp_path / "memory.max").write_text(limit)
    meminfo = tmp_path / "meminfo"
    meminfo.write_text("MemTotal:       65536 kB\nMemFree:        1024 kB\n")

    assert memory_budget(str(tmp_path), str(meminfo)) == 65536 * 1024


@pytest.mark.unit
def test_a_run_cgroup_has_the_limits():
    cgroups = RunCgroups.delegated()
    path = cgroups.create(256 * 1024 ** 2)
    try:
        def read(name: str) -> str:
            with open(os.path.join(path, name)) as fp:
                return fp.read().strip()

        assert os.path.basename(path).startswith(f"run-{os.getpid()}-")
        assert read("memory.max") == str(256 * 1024 ** 2)
        assert read("memory.oom.group") == "1"
        assert read("pids.max") == str(TASKS_LIMIT)
        if os.path.exists(os.path.join(path, "memory.swap.max")):
            assert read("memory.swap.max") == "0"
        assert not cgroups.oom_killed(path)
    finally:
        cgroups.remove(path)

    assert not os.path.exists(path)


@pytest.mark.unit
def test_two_runners_in_one_process_do_not_share_a_cgroup():
    first, second = RunCgroups.delegated(), RunCgroups.delegated()
    paths = [first.create(64 * 1024 ** 2), second.create(64 * 1024 ** 2)]
    try:
        assert paths[0] != paths[1]
    finally:
        for path in paths:
            first.remove(path)


@pytest.mark.unit
def test_removing_a_cgroup_kills_what_is_in_it():
    cgroups = RunCgroups.delegated()
    path = cgroups.create(64 * 1024 ** 2)
    process = subprocess.Popen(["/usr/bin/sleep", "60"])
    try:
        with open(os.path.join(path, "cgroup.procs"), "w") as fp:
            fp.write(str(process.pid))

        cgroups.remove(path)

        assert process.wait(timeout=10) == -9
        assert not os.path.exists(path)
    finally:
        process.kill()
        process.wait()


@pytest.mark.unit
def test_a_failure_setting_the_limits_leaves_no_cgroup(monkeypatch):
    cgroups = RunCgroups.delegated()
    before = set(os.listdir(cgroups.parent))
    write = cgroup_module._write

    def failing(path, name, value):
        if name == "pids.max":
            raise OSError("no pids controller")
        write(path, name, value)

    monkeypatch.setattr(cgroup_module, "_write", failing)

    with pytest.raises(OSError, match="no pids controller"):
        cgroups.create(64 * 1024 ** 2)

    assert set(os.listdir(cgroups.parent)) == before


@pytest.mark.unit
def test_sweep_removes_the_cgroups_of_a_runner_that_is_gone(caplog):
    cgroups = RunCgroups.delegated()
    # a pid no process has: pid_max is at most 2^22
    stale = os.path.join(cgroups.parent, "run-4194305-1")
    os.mkdir(stale)
    live = cgroups.create(64 * 1024 ** 2)
    try:
        cgroups.sweep()

        assert not os.path.exists(stale)
        assert os.path.exists(live)
        assert any("left behind" in record.getMessage() and stale in record.getMessage() for record in caplog.records)
    finally:
        cgroups.remove(live)
        if os.path.exists(stale):
            os.rmdir(stale)


@pytest.mark.unit
def test_sweep_leaves_what_is_not_a_run():
    # the service leaf, which holds the container's processes
    cgroups = RunCgroups.delegated()

    cgroups.sweep()

    assert os.path.isdir(os.path.join(cgroups.parent, "service"))


@pytest.mark.unit
def test_a_cgroup_that_cannot_be_removed_is_reported_by_sweep(tmp_path, caplog):
    cgroups = RunCgroups(str(tmp_path))
    # a plain directory: cgroup.kill is written, but rmdir fails on what is in it
    stale = tmp_path / "run-4194305-1"
    stale.mkdir()
    (stale / "cgroup.kill").write_text("")
    (stale / "content").write_text("x")

    cgroups.sweep()

    [record] = [r for r in caplog.records if "unable to remove the cgroup" in r.getMessage()]
    assert record.exc_info
