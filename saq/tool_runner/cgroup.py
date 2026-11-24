"""The cgroup v2 subtree the tool runner creates one cgroup per run in (docs/TOOL_SANDBOX.md).

docker/startup/delegate-cgroup.sh hands the ace user a subtree at container start: every process of
the container runs in <subtree>/service, and the subtree enables the memory and pids controllers
for its children. The runner, in that leaf, creates each run's cgroup beside it, which it may
because it owns their common parent.
"""

import errno
import itertools
import logging
import os
import time

CGROUP_ROOT = "/sys/fs/cgroup"

# what a run's cgroup must be able to limit
CONTROLLERS = ("memory", "pids")

# a run's pids.max. The kernel counts threads, and the JVM, .NET, 7z and john start one or more per
# core, so this is well above the launcher's --max-processes, which counts processes by polling and
# which a fork loop can outrun; this is the ceiling that loop hits
TASKS_LIMIT = 4096

RUN_PREFIX = "run-"

# numbers the runs of every runner in the process: the test suite runs more than one
_run_ids = itertools.count(1)

# how long removing a run's cgroup waits for the processes cgroup.kill killed to be gone
_REMOVE_SECONDS = 5


class CgroupUnavailable(RuntimeError):
    """This process cannot create cgroups for the runs (the container was not started by
    delegate-cgroup.sh)."""


def own_cgroup(proc_path: str = "/proc/self/cgroup") -> str:
    """This process's cgroup v2 path, relative to the hierarchy's root ("/tools/service")."""
    with open(proc_path) as fp:
        for line in fp:
            if line.startswith("0::"):
                return line[3:].strip()

    raise CgroupUnavailable("this process is not in a cgroup v2 hierarchy")


def _read(path: str, name: str) -> str:
    with open(os.path.join(path, name)) as fp:
        return fp.read()


def _write(path: str, name: str, value: str):
    with open(os.path.join(path, name), "w") as fp:
        fp.write(value)


def memory_budget(root: str = CGROUP_ROOT, meminfo_path: str = "/proc/meminfo") -> int:
    """The memory the container may use, in bytes: its memory.max, or the host's memory when it has none."""
    try:
        value = _read(root, "memory.max").strip()
    except FileNotFoundError:
        value = "max"

    if value != "max":
        return int(value)

    with open(meminfo_path) as fp:
        for line in fp:
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024

    raise RuntimeError(f"no MemTotal in {meminfo_path}")


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass  # it exists, as someone else

    return True


class RunCgroups:
    """Creates, inspects and removes the cgroups of the runs, under parent."""

    def __init__(self, parent: str):
        self.parent = parent

    @classmethod
    def delegated(cls, root: str = CGROUP_ROOT, proc_path: str = "/proc/self/cgroup") -> "RunCgroups":
        """The subtree delegate-cgroup.sh made for this process: the parent of its own cgroup. Raises
        CgroupUnavailable, saying what is missing, when this process cannot create cgroups there."""
        own = own_cgroup(proc_path)
        if own == "/":
            raise CgroupUnavailable(
                "this process is in its container's root cgroup, so no cgroup subtree was delegated to it: "
                "start the container with docker/startup/delegate-cgroup.sh")

        parent = os.path.join(root, os.path.dirname(own).lstrip("/"))
        try:
            enabled = _read(parent, "cgroup.subtree_control").split()
        except OSError as e:
            raise CgroupUnavailable(f"cannot read the controllers {parent} enables: {e}") from e

        missing = [controller for controller in CONTROLLERS if controller not in enabled]
        if missing:
            raise CgroupUnavailable(f"{parent} does not enable the {', '.join(missing)} controller for its children")

        if not os.access(parent, os.W_OK):
            raise CgroupUnavailable(f"{parent} is not writable by this user, so no cgroup subtree was delegated to it")

        return cls(parent)

    def create(self, memory_max: int) -> str:
        """A new cgroup for one run: at most memory_max bytes of memory and no swap, an OOM kills all of
        it, and at most TASKS_LIMIT threads. Its name carries this process's pid, which is how sweep()
        tells a run of a runner that is gone."""
        path = os.path.join(self.parent, f"{RUN_PREFIX}{os.getpid()}-{next(_run_ids)}")
        os.mkdir(path)
        try:
            _write(path, "memory.max", str(memory_max))
            # without it the tool's memory past memory.max would go to swap
            if os.path.exists(os.path.join(path, "memory.swap.max")):
                _write(path, "memory.swap.max", "0")
            # an OOM kills every process of the tool, not one of them
            _write(path, "memory.oom.group", "1")
            _write(path, "pids.max", str(TASKS_LIMIT))
        except BaseException:
            self.remove(path)
            raise

        return path

    def oom_killed(self, path: str) -> bool:
        """Whether the kernel killed a process of the run for going over memory.max."""
        for line in _read(path, "memory.events").splitlines():
            name, _, count = line.partition(" ")
            if name == "oom_kill":
                return int(count) > 0

        return False

    def remove(self, path: str):
        """Kill whatever is left in the cgroup, and remove it."""
        try:
            _write(path, "cgroup.kill", "1")
        except FileNotFoundError:
            return  # already removed: nothing is left to kill

        give_up = time.monotonic() + _REMOVE_SECONDS
        while True:
            try:
                os.rmdir(path)
                return
            except FileNotFoundError:
                return  # removed since the kill, which is what this was for
            except OSError as e:
                # EBUSY until the killed processes have exited
                if e.errno != errno.EBUSY or time.monotonic() > give_up:
                    raise

            time.sleep(0.01)

    def sweep(self):
        """Remove the cgroups left by a runner that died mid-run, and kill what is still in them. Those of a
        runner that is still running (another test session's, in dev) are left alone."""
        for entry in os.scandir(self.parent):
            if not entry.is_dir() or not entry.name.startswith(RUN_PREFIX):
                continue

            pid = entry.name[len(RUN_PREFIX):].partition("-")[0]
            if pid.isdigit() and _alive(int(pid)):
                continue

            logging.info("removing the cgroup %s a tool runner left behind", entry.path)
            try:
                self.remove(entry.path)
            except OSError as e:
                logging.error("unable to remove the cgroup %s a tool runner left behind: %s", entry.path, e, exc_info=e)
