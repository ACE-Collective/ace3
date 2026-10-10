"""SVS's own clone of a rule repository, and exporting a commit's tree from it.

Each repository in svs.yara.repositories gets a bare mirror under svs.yara.mirror_dir, fetched
with the URL and SSH key of its `git_repo_<name>` section. It is never the checkout the yara
service loads rules from (GitManagerService's local_path), so a validation can neither change what
production scans nor see a working tree someone edited by hand.

A commit is exported with `git archive` and unpacked one member at a time with tarfile's `data`
filter, which refuses absolute paths, paths that leave the destination, links that point outside
it and device files; each refused member is recorded rather than failing the export. The export can
be capped in bytes and in members (it is not by default), since a PR controls what the commit
contains. Like any `git
archive`, it honours the commit's `.gitattributes` (`export-ignore`, `export-subst`), which a
checkout does not.
"""

import fcntl
import logging
import os
import re
import subprocess
import tarfile
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator

from saq.configuration.schema import GitRepoConfig
from saq.git import GitRepo, git_argv, kill_timed_out_process

# what an unknown sha must look like before it is handed to git
_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{7,64}$")

# how long a local git command (rev-parse, cat-file) may take
_LOCAL_COMMAND_TIMEOUT = 60

# how much of a failed git command's stderr goes into the error
_STDERR_TAIL = 4096


class RepositoryError(RuntimeError):
    """A git operation on the mirror failed; the message is safe to show (no credentials)."""


@dataclass
class ExportResult:
    members: int = 0
    bytes: int = 0
    # (path, reason) of every member that was not unpacked
    skipped: list[tuple[str, str]] = field(default_factory=list)


def is_valid_sha(value: str) -> bool:
    return bool(_SHA_PATTERN.match(value or ""))


class Mirror:
    def __init__(self, name: str, config: GitRepoConfig, mirror_root: str, fetch_timeout: int):
        self.name = name
        self.config = config
        self.path = os.path.join(mirror_root, name)
        self.fetch_timeout = fetch_timeout

    def _env(self) -> dict[str, str]:
        # the environment GitManagerService gives git (only the SSH command), and never a prompt
        # for credentials that would hang until the timeout
        return {**GitRepo(self.config).env, "GIT_TERMINAL_PROMPT": "0"}

    def _redact(self, text: str) -> str:
        # an https URL can carry a token
        return text.replace(self.config.git_url, "<url>")

    def _git(self, *args: str, timeout: float, error: str) -> str:
        with subprocess.Popen(
            git_argv("-C", self.path, *args),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._env(),
            start_new_session=True,
        ) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                kill_timed_out_process(process)
                process.communicate()
                raise RepositoryError(f"{error}: git {args[0]} timed out after {timeout} seconds") from None

        if process.returncode != 0:
            raise RepositoryError(f"{error}: {self._redact(stderr.strip()[-_STDERR_TAIL:])}")

        return stdout

    @contextmanager
    def lock(self) -> Iterator[None]:
        """Hold the mirror for one fetch and export: two validations of the same repository must
        not fetch into it at once."""
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(f"{self.path}.lock", "a") as fp:
            fcntl.flock(fp, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fp, fcntl.LOCK_UN)

    def ensure(self, branches: list[str]) -> None:
        """Create the mirror if it does not exist, point it at the configured URL and fetch the
        branches."""
        if not os.path.isdir(os.path.join(self.path, "objects")):
            os.makedirs(self.path, exist_ok=True)
            self._git("init", "--bare", "--quiet", timeout=_LOCAL_COMMAND_TIMEOUT, error="unable to create the mirror")

        remotes = self._git("remote", timeout=_LOCAL_COMMAND_TIMEOUT, error="unable to read the mirror's remotes").split()
        verb = "set-url" if "origin" in remotes else "add"
        self._git("remote", verb, "origin", self.config.git_url, timeout=_LOCAL_COMMAND_TIMEOUT,
                  error="unable to set the mirror's remote")

        refspecs = [f"+refs/heads/{branch}:refs/heads/{branch}" for branch in dict.fromkeys(branches) if branch]
        self._git("fetch", "--quiet", "--no-tags", "origin", *refspecs, timeout=self.fetch_timeout,
                  error=f"unable to fetch {', '.join(dict.fromkeys(branches))} of repository {self.name}")

    def fetch_commit(self, sha: str) -> None:
        """Fetch one commit by id, for a commit no fetched branch contains any more. Most servers
        allow it for a reachable commit."""
        self._git("fetch", "--quiet", "--no-tags", "origin", sha, timeout=self.fetch_timeout,
                  error=f"unable to fetch commit {sha} of repository {self.name}")

    def resolve(self, sha: str) -> str | None:
        """The full id of the commit sha names, or None if the mirror does not have it."""
        if not is_valid_sha(sha):
            raise RepositoryError(f"{sha!r} is not a commit id")

        try:
            return self._git("rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}", timeout=_LOCAL_COMMAND_TIMEOUT,
                             error=f"commit {sha} not found").strip()
        except RepositoryError:
            return None

    def export(self, sha: str, dest: str, *, max_bytes: int | None, max_members: int | None, timeout: float) -> ExportResult:
        """Unpack the tree of the commit (a full id from resolve()) into dest, which must exist."""
        result = ExportResult()
        timed_out = threading.Event()
        error = None
        with tempfile.TemporaryFile() as stderr, subprocess.Popen(
            git_argv("-C", self.path, "archive", "--format=tar", sha),
            stdout=subprocess.PIPE,
            stderr=stderr,
            env=self._env(),
            start_new_session=True,
        ) as process:
            def _expire():
                timed_out.set()
                kill_timed_out_process(process)

            timer = threading.Timer(timeout, _expire)
            timer.start()
            try:
                self._unpack(process.stdout, dest, result, max_bytes=max_bytes, max_members=max_members)
                # the padding after the end of the archive
                process.stdout.read()
            except (tarfile.TarError, RepositoryError) as e:
                error = str(e)
                kill_timed_out_process(process)
            finally:
                timer.cancel()
                process.wait()

            stderr.seek(0)
            message = stderr.read()[-_STDERR_TAIL:].decode(errors="replace").strip()

        if timed_out.is_set():
            raise RepositoryError(f"exporting commit {sha} timed out after {timeout} seconds")

        if error is not None:
            raise RepositoryError(f"unable to export commit {sha}: {error}")

        if process.returncode != 0:
            raise RepositoryError(f"unable to export commit {sha}: {self._redact(message)}")

        return result

    @staticmethod
    def _unpack(stream, dest: str, result: ExportResult, *, max_bytes: int | None, max_members: int | None) -> None:
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            for member in archive:
                result.members += 1
                if max_members is not None and result.members > max_members:
                    raise RepositoryError(f"the commit has more than {max_members} files and directories "
                                          "(svs.yara.max_archive_members)")

                if member.isfile():
                    result.bytes += member.size
                    if max_bytes is not None and result.bytes > max_bytes:
                        raise RepositoryError(f"the commit is larger than {max_bytes} bytes (svs.yara.max_archive_bytes)")

                # pax_global_header carries the commit id, nothing to unpack
                if member.type in (tarfile.XGLTYPE, tarfile.XHDTYPE):
                    continue

                try:
                    archive.extract(member, dest, filter="data")
                except (tarfile.FilterError, OSError) as e:
                    result.skipped.append((member.name, str(e)))
                    logging.info("svs export skipped %s: %s", member.name, e)
