"""git provenance for loaded signatures

Resolved once per load rather than once per file."""

import logging
import os
from dataclasses import dataclass

from saq.git import get_commit_hash, get_remote_url, get_repo_root
from saq.signatures.builtin import SIGNATURE_VERSION_UNKNOWN


@dataclass(frozen=True)
class GitContext:
    """The repository a set of signatures was loaded from."""

    # root of the repo, or the loaded path itself when it isn't in a repo
    root: str
    git_remote: str | None
    version: str

    @classmethod
    def resolve(cls, path: str) -> "GitContext":
        """Resolves the git provenance of path. A path that is not inside a git
        repo is not an error: the version falls back to SIGNATURE_VERSION_UNKNOWN
        and paths are made relative to path itself."""
        # git commands need a directory to run in
        search_dir = path if os.path.isdir(path) else os.path.dirname(os.path.abspath(path))

        root = get_repo_root(search_dir)
        if not root:
            logging.debug("%s is not inside a git repo - signature versions will be unknown", path)
            return cls(root=os.path.abspath(path), git_remote=None, version=SIGNATURE_VERSION_UNKNOWN)

        return cls(
            root=root,
            git_remote=get_remote_url(root),
            version=get_commit_hash(root) or SIGNATURE_VERSION_UNKNOWN,
        )

    def relative_path(self, path: str) -> str:
        """Returns path relative to the repo root, with posix separators."""
        return os.path.relpath(os.path.abspath(path), self.root).replace(os.sep, "/")
