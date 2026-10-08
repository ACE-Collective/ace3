"""Stages and runs a correlate `type: executable` command inside the Landlock sandbox (saq/sandbox/).

Hunt scripts are written by analysts and by AI agents iterating through the validation API. They
are not hostile, but a mistake in one must not be able to damage ACE or put a secret in front of
whoever wrote it. saq/sandbox/runner.py says what the sandbox allows; this module adds what is
particular to hunts: where the working directories live, the limits from
`hunter.correlation.executable`, and staging, which copies the script and its declared `files:`
into the working directory, but only from the hunt repositories. If the kernel does not support
Landlock, the command fails -- it is never run unsandboxed.
"""

import logging
import os
import shutil

from saq.collectors.hunter.loader import get_compiled_hunt_dir
from saq.configuration import get_config
from saq.configuration.schema import ExecutableSandboxConfig
from saq.environment import get_base_dir, get_data_dir
from saq.sandbox.launcher import NET_ABI, SCOPE_ABI, landlock_abi
from saq.sandbox.runner import get_read_dirs, landlock_available, sweep_stale_workdirs
from saq.util import abs_path


def get_sandbox_config() -> ExecutableSandboxConfig:
    return get_config().hunter.correlation.executable


def get_sandbox_root() -> str:
    """The directory that holds every execution's working directory."""
    path = os.path.join(get_data_dir(), get_sandbox_config().work_dir)
    os.makedirs(path, exist_ok=True)
    return path


def _is_under(path: str, root: str) -> bool:
    return os.path.commonpath([path, root]) == root


def _is_under_any(path: str, roots: list[str]) -> bool:
    return any(_is_under(path, root) for root in roots)


def get_hunt_source_roots() -> list[str]:
    """Directories a script or a `files:` entry may be staged from.

    These are the hunt repositories (each hunt type rule dir's git_dir, or the rule dir itself)
    and the directory the validation API materializes compiled hunts into. Staging happens outside
    the sandbox, so without this check `files: [/auth/passwords/...]` would copy a secret into the
    working directory where the script can read it. A root that contains SAQ_HOME (for example a
    git_dir of `.`) would expose the whole installation and is ignored.
    """
    candidates = [get_compiled_hunt_dir()]
    for hunt_type in get_config().hunt_types:
        for entry in hunt_type.rule_dirs:
            candidates.append(abs_path(entry.git_dir or entry.rule_dir))

    saq_home = os.path.realpath(get_base_dir())
    roots = []
    for candidate in candidates:
        root = os.path.realpath(candidate)
        if _is_under(saq_home, root):
            logging.warning("ignoring hunt source root %s: it contains SAQ_HOME", root)
            continue

        if root not in roots:
            roots.append(root)

    return roots


def stage_executable(path: str, files: list[str] | None, workdir: str, search_path: str | None = None) -> str:
    """Copy a command's executable and its `files:` into workdir and return the path to execute.

    The copies keep their layout relative to one another, so a script that opens
    `Path(__file__).parent / "data.json"` still finds it. An executable that already lies in the
    sandbox's readable directories (a system binary, the venv's python) runs in place and only its
    files are staged.
    """
    resolved = path
    if os.sep not in path:
        resolved = shutil.which(path, path=search_path)
        if resolved is None:
            raise RuntimeError(f"executable {path} not found")

    # Landlock checks the file a path resolves to, so /bin/echo (via the /bin -> usr/bin symlink)
    # and the venv's python (a symlink to /usr/local/bin/python3.x) are both readable in place
    read_dirs = [os.path.realpath(p) for p in get_read_dirs()]
    run_in_place = _is_under_any(os.path.realpath(resolved), read_dirs)

    sources = [] if run_in_place else [resolved]
    sources.extend(files or [])
    if not sources:
        return resolved

    roots = get_hunt_source_roots()
    real_sources = []
    for source in sources:
        real_source = os.path.realpath(source)
        if not _is_under_any(real_source, roots):
            raise RuntimeError(
                f"{source} is outside the hunt repositories; an executable and its files must live "
                "in a hunt rule directory's repository"
            )

        if not os.path.isfile(real_source):
            raise RuntimeError(f"{source} is not a file")

        real_sources.append(real_source)

    base = os.path.commonpath([os.path.dirname(source) for source in real_sources])
    staged = []
    for real_source in real_sources:
        target = os.path.join(workdir, os.path.relpath(real_source, base))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(real_source, target)
        shutil.copymode(real_source, target)
        staged.append(target)

    return resolved if run_in_place else staged[0]


def prepare_sandbox():
    """Hunter startup: report whether executable commands can run and clear out stale workdirs."""
    if landlock_available():
        abi = landlock_abi()
        logging.info("correlate executable commands run in a landlock sandbox (ABI %s) under %s", abi, get_sandbox_root())
        if get_sandbox_config().allowed_tcp_ports is not None and abi < NET_ABI:
            logging.error(
                "landlock ABI %s cannot restrict TCP ports (ABI %s, Linux 6.7, is needed): every correlate "
                "executable command will fail unless hunter.correlation.executable.allowed_tcp_ports is null",
                abi, NET_ABI,
            )
        if abi < SCOPE_ABI:
            logging.warning(
                "landlock ABI %s cannot scope signals (ABI %s, Linux 6.12, is needed): a correlate "
                "executable command can signal other processes running as this user", abi, SCOPE_ABI,
            )
    else:
        logging.error("landlock is unavailable here: every correlate executable command will fail")

    try:
        sweep_stale_workdirs(get_sandbox_root())
    except OSError as e:
        logging.warning("unable to sweep the correlation sandbox directory: %s", e)
