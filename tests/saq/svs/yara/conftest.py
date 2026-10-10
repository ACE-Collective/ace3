import os
import subprocess
from typing import Optional, Union

import pytest

from saq.cas import get_cas
from saq.configuration.config import get_config, get_service_config
from saq.configuration.schema import GitRepoConfig
from saq.constants import SERVICE_YARA_SCANNER
from saq.svs.capture import capture_hold
from tests.saq.svs.conftest import capture_rows, graded_alert

REPOSITORY = "svs_rules"

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "unittest", "GIT_AUTHOR_EMAIL": "unittest@localhost",
    "GIT_COMMITTER_NAME": "unittest", "GIT_COMMITTER_EMAIL": "unittest@localhost",
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "PATH": os.environ["PATH"],
}


def git(cwd: str, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, env=_GIT_ENV, check=True, capture_output=True, text=True).stdout


class RuleRepo:
    """A rule repository: a bare origin, and a working clone that commits and pushes to it."""

    def __init__(self, root: str):
        self.origin = os.path.join(root, "origin")
        self.work = os.path.join(root, "work")
        os.makedirs(self.origin)
        os.makedirs(self.work)
        git(self.origin, "init", "--bare", "--quiet", "-b", "main")
        git(self.work, "init", "--quiet", "-b", "main")
        git(self.work, "remote", "add", "origin", self.origin)

    def commit(self, files: dict[str, Optional[Union[str, bytes]]], *, branch: str = "main",
               symlinks: Optional[dict[str, str]] = None) -> str:
        """Write (or, for None, delete) the files, commit them on branch and push. Returns the
        commit id."""
        if git(self.work, "symbolic-ref", "--short", "HEAD").strip() != branch:
            exists = bool(git(self.work, "branch", "--list", branch).strip())
            git(self.work, "checkout", "--quiet", *([] if exists else ["-b"]), branch)

        for path, content in files.items():
            full_path = os.path.join(self.work, path)
            if content is None:
                os.remove(full_path)
                continue

            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, "wb" if isinstance(content, bytes) else "w") as fp:
                fp.write(content)

        for path, target in (symlinks or {}).items():
            full_path = os.path.join(self.work, path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            os.symlink(target, full_path)

        git(self.work, "add", "-A")
        git(self.work, "commit", "--quiet", "--allow-empty", "-m", "change")
        git(self.work, "push", "--quiet", "--force", "origin", branch)
        return git(self.work, "rev-parse", "HEAD").strip()


@pytest.fixture
def rule_repo(tmp_path) -> RuleRepo:
    return RuleRepo(str(tmp_path / "repo"))


@pytest.fixture
def svs_repository(rule_repo, tmp_path, monkeypatch) -> RuleRepo:
    """rule_repo configured as the git_repo_svs_rules section SVS may validate, with the yara
    service loading its yara/ directory (the contained layout)."""
    checkout = tmp_path / "checkout"
    (checkout / "yara").mkdir(parents=True)
    get_config().add_git_repo_config(REPOSITORY, GitRepoConfig(
        name=REPOSITORY, description="svs unittest rules", local_path=str(checkout), git_url=rule_repo.origin,
        update_frequency=60, branch="main"))
    monkeypatch.setattr(get_config().svs.yara, "repositories", [REPOSITORY])
    monkeypatch.setattr(get_config().svs.yara, "mirror_dir", str(tmp_path / "mirrors"))
    monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "signature_dir", str(checkout / "yara"))
    return rule_repo


def rule(name: str, rule_uuid: Optional[str], strings: str, condition: str = "any of them", **meta) -> str:
    """The source of one rule."""
    meta_lines = [f'        uuid = "{rule_uuid}"'] if rule_uuid else []
    for key, value in meta.items():
        meta_lines.append(f'        {key} = "{value}"' if isinstance(value, str) else f"        {key} = {str(value).lower()}")

    meta_block = ("    meta:\n" + "\n".join(meta_lines) + "\n") if meta_lines else ""
    return f"rule {name} {{\n{meta_block}    strings:\n        {strings}\n    condition:\n        {condition}\n}}\n"


def stored_sample(disposition: str, content: bytes, rule_uuids: list[str], name: str = "sample.bin") -> str:
    """A file YARA matched for each of rule_uuids on an alert with this disposition, captured, with
    its bytes in the svs_samples pool. Returns its sha256."""
    alert, files = graded_alert(disposition, {name: rule_uuids}, contents={name: content})
    pool = get_cas().pool(get_config().svs.samples.pool)
    for row in capture_rows(alert.uuid):
        pool.put(content, hold=capture_hold(row.id), digest=row.sha256)

    return files[name].value.lower()
