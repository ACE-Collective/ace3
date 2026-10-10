"""SVS's mirror of a rule repository and the export of a commit (saq.svs.yara.repository)."""

import os

import pytest

from saq.configuration.schema import GitRepoConfig
from saq.svs.yara.repository import Mirror, RepositoryError, is_valid_sha
from tests.saq.svs.yara.conftest import git


def _mirror(rule_repo, tmp_path, url=None) -> Mirror:
    config = GitRepoConfig(name="rules", description="", local_path=str(tmp_path / "checkout"),
                           git_url=url or rule_repo.origin, update_frequency=60, branch="main")
    return Mirror("rules", config, str(tmp_path / "mirrors"), fetch_timeout=60)


def _export(mirror, sha, dest, **kwargs):
    os.makedirs(dest, exist_ok=True)
    options = dict(max_bytes=1024 ** 2, max_members=100, timeout=60)
    options.update(kwargs)
    return mirror.export(sha, str(dest), **options)


@pytest.mark.unit
def test_is_valid_sha():
    assert is_valid_sha("a" * 40)
    assert is_valid_sha("ABCDEF1")
    assert not is_valid_sha("main")
    assert not is_valid_sha("--upload-pack=x")
    assert not is_valid_sha("")


@pytest.mark.unit
def test_fetch_resolve_and_export(rule_repo, tmp_path):
    base = rule_repo.commit({"yara/acme/a.yar": "rule a { condition: false }\n"})
    head = rule_repo.commit({"yara/acme/b.yar": "rule b { condition: false }\n"}, branch="feature")

    mirror = _mirror(rule_repo, tmp_path)
    with mirror.lock():
        mirror.ensure(["feature", "main"])

    assert mirror.resolve(base) == base
    assert mirror.resolve(head[:12]) == head
    assert mirror.resolve("0" * 40) is None

    result = _export(mirror, base, tmp_path / "base")
    assert (tmp_path / "base" / "yara" / "acme" / "a.yar").exists()
    assert not (tmp_path / "base" / "yara" / "acme" / "b.yar").exists()
    assert result.skipped == []

    _export(mirror, head, tmp_path / "head")
    assert (tmp_path / "head" / "yara" / "acme" / "b.yar").exists()

    # a second ensure updates the existing mirror
    newer = rule_repo.commit({"yara/acme/c.yar": "rule c { condition: false }\n"}, branch="feature")
    mirror.ensure(["feature", "main"])
    assert mirror.resolve(newer) == newer


@pytest.mark.unit
def test_a_commit_no_branch_contains_is_fetched_by_id(rule_repo, tmp_path):
    rule_repo.commit({"a.yar": "rule a { condition: false }\n"})
    orphaned = rule_repo.commit({"b.yar": "rule b { condition: false }\n"}, branch="gone")
    # the branch is deleted, but origin still has the commit
    git(rule_repo.work, "push", "--quiet", "origin", "--delete", "gone")
    git(rule_repo.origin, "config", "uploadpack.allowAnySHA1InWant", "true")

    mirror = _mirror(rule_repo, tmp_path)
    mirror.ensure(["main"])
    assert mirror.resolve(orphaned) is None
    mirror.fetch_commit(orphaned)
    assert mirror.resolve(orphaned) == orphaned


@pytest.mark.unit
def test_an_escaping_symlink_is_skipped_and_recorded(rule_repo, tmp_path):
    sha = rule_repo.commit(
        {"yara/acme/a.yar": "rule a { condition: false }\n"},
        symlinks={"yara/acme/passwd.yar": "/etc/passwd", "yara/acme/up.yar": "../../../../outside.yar",
                  "yara/acme/inside.yar": "a.yar"})
    mirror = _mirror(rule_repo, tmp_path)
    mirror.ensure(["main"])
    result = _export(mirror, sha, tmp_path / "tree")

    assert sorted(path for path, _ in result.skipped) == ["yara/acme/passwd.yar", "yara/acme/up.yar"]
    assert not os.path.lexists(tmp_path / "tree" / "yara" / "acme" / "passwd.yar")
    assert os.path.islink(tmp_path / "tree" / "yara" / "acme" / "inside.yar")


@pytest.mark.unit
def test_the_export_is_capped(rule_repo, tmp_path):
    sha = rule_repo.commit({f"yara/acme/{index}.yar": "x" * 1000 for index in range(10)})
    mirror = _mirror(rule_repo, tmp_path)
    mirror.ensure(["main"])

    with pytest.raises(RepositoryError, match="max_archive_bytes"):
        _export(mirror, sha, tmp_path / "bytes", max_bytes=5000)

    with pytest.raises(RepositoryError, match="max_archive_members"):
        _export(mirror, sha, tmp_path / "members", max_members=5)

    _export(mirror, sha, tmp_path / "fits", max_bytes=10000, max_members=20)

    # no limit when unset
    result = _export(mirror, sha, tmp_path / "uncapped", max_bytes=None, max_members=None)
    assert result.bytes == 10000
    assert len(os.listdir(tmp_path / "uncapped" / "yara" / "acme")) == 10


@pytest.mark.unit
def test_a_failing_fetch_does_not_show_the_url(rule_repo, tmp_path):
    secret_url = "https://user:token@127.0.0.1:1/rules.git"
    mirror = _mirror(rule_repo, tmp_path, url=secret_url)
    with pytest.raises(RepositoryError) as error:
        mirror.ensure(["main"])

    assert "token" not in str(error.value)


@pytest.mark.unit
def test_an_unknown_commit_is_refused_before_git_sees_it(rule_repo, tmp_path):
    mirror = _mirror(rule_repo, tmp_path)
    with pytest.raises(RepositoryError, match="not a commit id"):
        mirror.resolve("HEAD~1")
