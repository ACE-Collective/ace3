"""tests for the yara scanner service configuration

get_validated_git_repo_dirs is the guard in front of a sharp edge in the yara
scanner library: a directory declared as a git repo that isn't one is tracked as
neither a repository nor a directory, so none of its rules are ever scanned."""

import logging
import os
import subprocess

import pytest

from saq.configuration.config import get_service_config
from saq.constants import SERVICE_YARA_SCANNER
from saq.yara_scanning_service import get_validated_git_repo_dirs


def _init_repo_with_commit(path: str):
    """init a git repo at path with one commit"""
    env = dict(os.environ)
    env["GIT_AUTHOR_NAME"] = env["GIT_COMMITTER_NAME"] = "test"
    env["GIT_AUTHOR_EMAIL"] = env["GIT_COMMITTER_EMAIL"] = "test@example.com"
    subprocess.run(["git", "init", path], check=True, capture_output=True)
    with open(os.path.join(path, "README"), "w") as fp:
        fp.write("rules\n")
    subprocess.run(["git", "-C", path, "add", "."], check=True, capture_output=True, env=env)
    subprocess.run(["git", "-C", path, "commit", "-m", "init"], check=True, capture_output=True, env=env)


@pytest.fixture
def signature_dir(tmp_path, monkeypatch) -> str:
    """A signature_dir that is itself inside a git repo, holding one rule
    directory - signatures/yara/bv, the layout the real signatures repo uses,
    and the case the upstream fix exists for."""
    repo = str(tmp_path / "signatures")
    os.makedirs(repo)
    _init_repo_with_commit(repo)

    result = os.path.join(repo, "yara")
    os.makedirs(os.path.join(result, "bv"))

    monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "signature_dir", result)
    return result


@pytest.fixture
def plain_signature_dir(tmp_path, monkeypatch) -> str:
    """A signature_dir outside any git repo, holding one rule directory that is
    its own clone and one that is not versioned at all."""
    result = str(tmp_path / "yara")
    os.makedirs(result)
    _init_repo_with_commit(os.path.join(result, "cloned"))
    os.makedirs(os.path.join(result, "local_only"))

    monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "signature_dir", result)
    return result


def _set_git_repo_dirs(monkeypatch, value: list[str]):
    monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "git_repo_dirs", value)


@pytest.mark.unit
def test_no_git_repo_dirs_configured(signature_dir, monkeypatch, caplog):
    _set_git_repo_dirs(monkeypatch, [])

    with caplog.at_level(logging.ERROR):
        assert get_validated_git_repo_dirs() == []

    assert not caplog.records


@pytest.mark.unit
def test_directory_in_a_git_repo_is_kept(signature_dir, monkeypatch, caplog):
    _set_git_repo_dirs(monkeypatch, ["bv"])

    with caplog.at_level(logging.ERROR):
        # a rule directory does not have to be the root of the repo
        assert get_validated_git_repo_dirs() == ["bv"]

    assert not caplog.records


@pytest.mark.unit
@pytest.mark.parametrize("entry", ["bv", "./bv", "ABSOLUTE"])
def test_entries_resolve_the_same_way_the_scanner_resolves_them(signature_dir, monkeypatch, entry):
    if entry == "ABSOLUTE":
        entry = os.path.join(signature_dir, "bv")

    _set_git_repo_dirs(monkeypatch, [entry])

    # the entry is returned as configured - the library resolves it the same way
    assert get_validated_git_repo_dirs() == [entry]


@pytest.mark.unit
def test_directory_not_in_a_git_repo_is_dropped(plain_signature_dir, monkeypatch, caplog):
    _set_git_repo_dirs(monkeypatch, ["cloned", "local_only"])

    with caplog.at_level(logging.ERROR):
        # dropping it means its rules are still scanned, just without a version -
        # passing it through would stop them being scanned at all
        assert get_validated_git_repo_dirs() == ["cloned"]

    assert any("local_only" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_missing_directory_is_dropped(signature_dir, monkeypatch, caplog):
    _set_git_repo_dirs(monkeypatch, ["bv", "does_not_exist"])

    with caplog.at_level(logging.ERROR):
        assert get_validated_git_repo_dirs() == ["bv"]

    assert any("does_not_exist" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_a_file_is_dropped(signature_dir, monkeypatch, caplog):
    with open(os.path.join(signature_dir, "loose.yar"), "w") as fp:
        fp.write("rule x { condition: false }\n")

    _set_git_repo_dirs(monkeypatch, ["loose.yar"])

    with caplog.at_level(logging.ERROR):
        assert get_validated_git_repo_dirs() == []

    assert any("loose.yar" in r.getMessage() for r in caplog.records)
