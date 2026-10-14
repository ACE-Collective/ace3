"""The Atomic Red Team test catalog (saq.svs.catalog, docs/SVS_RUNS.md)."""

import json
import logging
import os
import time
from argparse import Namespace

import pytest
import yaml

from saq.cli.commands.svs import cli_catalog_refresh, cli_catalog_status
from saq.configuration.config import get_config
from saq.configuration.schema import GitRepoConfig
from saq.database.model import SVSCatalogRepository, SVSCatalogTest
from saq.database.pool import get_db
from saq.svs import catalog
from saq.svs import service as svs_service
from saq.svs.catalog import content_hash, parse_atomics, refresh_catalog, refresh_repository
from saq.svs.service import SVSService
from tests.saq.svs.yara.conftest import git

REPOSITORY = "art_unittest"

GUID_A = "aaaaaaaa-1111-4111-8111-111111111111"
GUID_B = "bbbbbbbb-2222-4222-8222-222222222222"
GUID_C = "cccccccc-3333-4333-8333-333333333333"


def _test(name: str, guid: str | None, platforms=("windows",), executor="powershell", command="whoami") -> dict:
    test = {
        "name": name,
        "description": f"{name} does a thing\n",
        "supported_platforms": list(platforms),
        "input_arguments": {"output_file": {"description": "where", "type": "path", "default": "out.txt"}},
        "executor": {"name": executor, "command": command, "elevation_required": False},
    }
    if guid is not None:
        test["auto_generated_guid"] = guid
    return test


def _atomic(technique: str, display_name: str, *tests: dict) -> str:
    return yaml.safe_dump({"attack_technique": technique, "display_name": display_name, "atomic_tests": list(tests)})


def _write(root, files: dict) -> None:
    for path, content in files.items():
        full_path = os.path.join(root, path)
        if content is None:
            os.remove(full_path)
            continue
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w") as fp:
            fp.write(content)


class Checkout:
    """An ART checkout, as service_git keeps one at local_path."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(path)
        git(path, "init", "--quiet", "-b", "master")

    def commit(self, files: dict) -> str:
        _write(self.path, files)
        git(self.path, "add", "-A")
        git(self.path, "commit", "--quiet", "--allow-empty", "-m", "change")
        return git(self.path, "rev-parse", "HEAD").strip()


@pytest.fixture
def checkout(tmp_path, monkeypatch) -> Checkout:
    result = Checkout(str(tmp_path / "atomic-red-team"))
    get_config().add_git_repo_config(REPOSITORY, GitRepoConfig(
        name=REPOSITORY, description="unittest atomics", local_path=result.path,
        git_url="https://example.invalid/atomic-red-team.git", update_frequency=60, branch="master"))
    monkeypatch.setattr(get_config().svs.catalog, "repositories", [REPOSITORY])
    return result


def _tests() -> dict[str, SVSCatalogTest]:
    db = get_db()
    db.expire_all()
    return {test.guid: test for test in db.query(SVSCatalogTest)}


def _repository() -> SVSCatalogRepository:
    db = get_db()
    db.expire_all()
    return db.query(SVSCatalogRepository).filter(SVSCatalogRepository.name == REPOSITORY).one()


#
# parsing
#

@pytest.mark.unit
def test_parse_atomics(tmp_path):
    _write(tmp_path, {
        "atomics/T1059.001/T1059.001.yaml": _atomic("T1059.001", "PowerShell",
                                                    _test("Mimikatz", GUID_A), _test("No guid", None)),
        "atomics/T1003/T1003.yaml": _atomic("T1003", "OS Credential Dumping", _test("Dump", GUID_B.upper(), ("Linux",), "sh")),
        # the same guid again: the first file read keeps it
        "atomics/T1105/T1105.yaml": _atomic("T1105", "Ingress Tool Transfer", _test("Copy", GUID_A)),
        "atomics/T1106/T1106.yaml": "{not yaml: [",
        "atomics/T1107/T1107.yaml": "just a string\n",
        # not atomic files
        "atomics/Indexes/index.yaml": _atomic("T9999", "x", _test("ignored", GUID_C)),
        "atomics/T1059.001/src/helper.yaml": _atomic("T9999", "x", _test("ignored", GUID_C)),
    })

    result = parse_atomics(str(tmp_path))

    assert [(e.guid, e.technique, e.name) for e in result.entries] == [
        (GUID_B, "T1003", "Dump"),
        (GUID_A, "T1059.001", "Mimikatz"),
    ]
    dump = result.entries[0]
    assert dump.technique_name == "OS Credential Dumping"
    assert dump.platforms == ("linux",) and dump.executor == "sh"
    assert dump.path == "atomics/T1003/T1003.yaml"
    assert dump.description == "Dump does a thing"
    assert dump.content_hash == content_hash(dump.test)

    reasons = {(path, name): reason for path, name, reason in result.skipped}
    assert reasons[("atomics/T1059.001/T1059.001.yaml", "No guid")] == "no auto_generated_guid"
    assert "used by an earlier test" in reasons[("atomics/T1105/T1105.yaml", "Copy")]
    assert reasons[("atomics/T1106/T1106.yaml", None)].startswith("unreadable")
    assert reasons[("atomics/T1107/T1107.yaml", None)].startswith("not an atomic file")


@pytest.mark.unit
def test_the_content_hash_follows_the_test_only():
    assert content_hash({"a": 1, "b": [1, 2]}) == content_hash({"b": [1, 2], "a": 1})
    assert content_hash({"a": 1}) != content_hash({"a": 2})


#
# refreshing
#

@pytest.mark.integration
def test_refresh_reads_the_tests(checkout, caplog):
    commit = checkout.commit({
        "atomics/T1059.001/T1059.001.yaml": _atomic("T1059.001", "PowerShell", _test("Mimikatz", GUID_A),
                                                    _test("No guid", None)),
    })

    with caplog.at_level(logging.INFO):
        result = refresh_repository(REPOSITORY)

    assert result.refreshed and result.error is None
    assert (result.commit, result.tests, result.added, len(result.skipped)) == (commit, 1, 1, 1)

    test = _tests()[GUID_A]
    assert (test.repository, test.technique, test.technique_name, test.name) == (REPOSITORY, "T1059.001", "PowerShell", "Mimikatz")
    assert json.loads(test.platforms) == ["windows"] and test.executor == "powershell"
    assert json.loads(test.test)["executor"]["command"] == "whoami"
    assert test.commit == commit and test.removed_at is None

    repository = _repository()
    assert (repository.commit, repository.test_count, repository.skipped_count, repository.error) == (commit, 1, 1, None)

    skipped = [r for r in caplog.records if r.getMessage().startswith("svs catalog skipped")]
    assert skipped[0].levelno == logging.WARNING and skipped[0].test_name == "No guid"
    done = [r for r in caplog.records if r.getMessage() == f"svs catalog of {REPOSITORY} refreshed"]
    assert done[0].tests == 1 and done[0].added == 1 and done[0].commit == commit


@pytest.mark.integration
def test_refresh_reads_again_only_when_the_commit_changes(checkout, monkeypatch):
    checkout.commit({"atomics/T1003/T1003.yaml": _atomic("T1003", "OS Credential Dumping", _test("Dump", GUID_A))})
    assert refresh_repository(REPOSITORY).refreshed

    parsed = []
    monkeypatch.setattr(catalog, "parse_atomics", lambda root: parsed.append(root) or catalog.ParseResult())
    assert not refresh_repository(REPOSITORY).refreshed
    assert parsed == []

    # --force reads it anyway (and here finds nothing, so the test is removed)
    assert refresh_repository(REPOSITORY, force=True).refreshed
    assert parsed


@pytest.mark.integration
def test_changes_removals_and_returns(checkout):
    first = checkout.commit({
        "atomics/T1003/T1003.yaml": _atomic("T1003", "OS Credential Dumping", _test("Dump", GUID_A), _test("Keep", GUID_B)),
    })
    refresh_repository(REPOSITORY)
    before = {guid: (test.content_hash, test.updated_at) for guid, test in _tests().items()}

    # B unchanged, A changed, C added; then A removed
    second = checkout.commit({
        "atomics/T1003/T1003.yaml": _atomic("T1003", "OS Credential Dumping", _test("Dump", GUID_A, command="id"),
                                            _test("Keep", GUID_B)),
        "atomics/T1105/T1105.yaml": _atomic("T1105", "Ingress Tool Transfer", _test("Copy", GUID_C)),
    })
    result = refresh_repository(REPOSITORY)
    assert (result.added, result.changed, result.removed) == (1, 1, 0)
    tests = _tests()
    assert tests[GUID_A].commit == second and tests[GUID_A].content_hash != before[GUID_A][0]
    # a test the commit didn't change keeps the commit it was first read from, and its updated_at
    assert tests[GUID_B].commit == first and tests[GUID_B].updated_at == before[GUID_B][1]

    checkout.commit({
        "atomics/T1003/T1003.yaml": _atomic("T1003", "OS Credential Dumping", _test("Keep", GUID_B)),
        "atomics/T1105/T1105.yaml": None,
    })
    result = refresh_repository(REPOSITORY)
    assert result.removed == 2
    tests = _tests()
    # a test that disappears keeps its row, so its runs keep their test
    assert tests[GUID_A].removed_at is not None and tests[GUID_C].removed_at is not None
    assert tests[GUID_B].removed_at is None
    assert _repository().test_count == 1

    # and comes back
    checkout.commit({"atomics/T1105/T1105.yaml": _atomic("T1105", "Ingress Tool Transfer", _test("Copy", GUID_C))})
    refresh_repository(REPOSITORY)
    assert _tests()[GUID_C].removed_at is None


@pytest.mark.integration
def test_a_guid_of_another_repository_is_not_taken(checkout, tmp_path, monkeypatch):
    other = Checkout(str(tmp_path / "custom-atomics"))
    get_config().add_git_repo_config("custom_atomics", GitRepoConfig(
        name="custom_atomics", description="custom", local_path=other.path,
        git_url="https://example.invalid/custom.git", update_frequency=60, branch="master"))
    monkeypatch.setattr(get_config().svs.catalog, "repositories", [REPOSITORY, "custom_atomics"])
    checkout.commit({"atomics/T1003/T1003.yaml": _atomic("T1003", "OS Credential Dumping", _test("Dump", GUID_A))})
    other.commit({"atomics/T1003/T1003.yaml": _atomic("T1003", "OS Credential Dumping", _test("Copy of dump", GUID_A))})

    results = refresh_catalog()

    assert [result.tests for result in results] == [1, 0]
    assert "belongs to a test of art_unittest" in results[1].skipped[0][2]
    assert _tests()[GUID_A].name == "Dump"


@pytest.mark.integration
def test_a_commit_that_moves_while_reading_stores_nothing(checkout, monkeypatch):
    checkout.commit({"atomics/T1003/T1003.yaml": _atomic("T1003", "OS Credential Dumping", _test("Dump", GUID_A))})
    commits = iter(["1" * 40, "2" * 40])
    monkeypatch.setattr(catalog, "get_commit_hash", lambda path: next(commits))

    result = refresh_repository(REPOSITORY)

    assert not result.refreshed and result.error is None
    assert _tests() == {}


@pytest.mark.integration
@pytest.mark.parametrize("setup, message", [
    ("unlisted", "is not in svs.catalog.repositories"),
    ("no_section", "no git_repo section is named nowhere"),
    ("no_checkout", "does not exist yet; is service_git running?"),
])
def test_refresh_errors_are_recorded(checkout, monkeypatch, setup, message):
    name = REPOSITORY
    if setup == "unlisted":
        monkeypatch.setattr(get_config().svs.catalog, "repositories", [])
    elif setup == "no_section":
        name = "nowhere"
        monkeypatch.setattr(get_config().svs.catalog, "repositories", [name])
    else:
        get_config().get_git_repo_config(REPOSITORY).local_path = checkout.path + "-missing"

    result = refresh_repository(name)

    assert not result.refreshed and message in result.error
    db = get_db()
    db.expire_all()
    row = db.query(SVSCatalogRepository).filter(SVSCatalogRepository.name == name).one()
    assert message in row.error and row.commit is None


@pytest.mark.integration
def test_an_error_keeps_the_tests_and_clears_on_the_next_success(checkout, monkeypatch):
    checkout.commit({"atomics/T1003/T1003.yaml": _atomic("T1003", "OS Credential Dumping", _test("Dump", GUID_A))})
    refresh_repository(REPOSITORY)

    def broken(root):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(catalog, "parse_atomics", broken)
    checkout.commit({"atomics/T1003/T1003.yaml": _atomic("T1003", "OS Credential Dumping", _test("Dump", GUID_A, command="id"))})
    result = refresh_repository(REPOSITORY)
    assert result.error == "refresh failed: disk on fire"
    assert _repository().error == "refresh failed: disk on fire"
    assert GUID_A in _tests()

    monkeypatch.undo()
    monkeypatch.setattr(get_config().svs.catalog, "repositories", [REPOSITORY])
    # the failed commit is read on the next refresh, not skipped as already read
    assert refresh_repository(REPOSITORY).refreshed
    assert _repository().error is None


#
# service_svs
#

@pytest.mark.integration
def test_the_service_refreshes_the_catalog(checkout):
    checkout.commit({"atomics/T1003/T1003.yaml": _atomic("T1003", "OS Credential Dumping", _test("Dump", GUID_A))})

    SVSService().start_single_threaded()

    assert GUID_A in _tests()


@pytest.mark.integration
def test_the_refresher_runs_until_stopped_and_survives_a_failure(checkout, monkeypatch):
    calls = []

    def flaky(**kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("database went away")
        return []

    monkeypatch.setattr(svs_service, "refresh_catalog", flaky)
    monkeypatch.setattr(get_config().svs.catalog, "refresh_interval_seconds", 0.05)
    monkeypatch.setattr(svs_service, "is_primary_node", lambda: True)
    service = SVSService()
    service.start()
    try:
        deadline = time.time() + 10
        while len(calls) < 2 and time.time() < deadline:
            time.sleep(0.05)
        assert len(calls) >= 2 and service.catalog.thread.is_alive()
    finally:
        service.stop()
        service.wait()
    assert not service.catalog.thread.is_alive()


@pytest.mark.integration
def test_the_refresher_stays_idle_off_the_primary_node(monkeypatch):
    monkeypatch.setattr(svs_service, "is_primary_node", lambda: False)
    service = SVSService()
    service.start()
    assert service.catalog is None
    service.stop()


#
# ace svs catalog
#

@pytest.mark.integration
def test_cli_refresh_and_status(checkout, capsys):
    commit = checkout.commit({
        "atomics/T1003/T1003.yaml": _atomic("T1003", "OS Credential Dumping", _test("Dump", GUID_A), _test("No guid", None)),
    })

    assert cli_catalog_refresh(Namespace(repository=None, force=False)) == 0
    out = capsys.readouterr().out
    assert f"{REPOSITORY} @ {commit[:12]}: 1 tests (1 added, 0 changed, 0 removed, 1 skipped)" in out
    assert "skipped atomics/T1003/T1003.yaml (No guid): no auto_generated_guid" in out

    assert cli_catalog_refresh(Namespace(repository=REPOSITORY, force=False)) == 0
    assert "already read (--force to read it again)" in capsys.readouterr().out

    assert cli_catalog_status(Namespace()) == 0
    assert f"{REPOSITORY}: 1 tests at {commit[:12]}" in capsys.readouterr().out


@pytest.mark.integration
def test_cli_refresh_reports_an_error(checkout, capsys, monkeypatch):
    monkeypatch.setattr(get_config().svs.catalog, "repositories", ["nowhere"])
    assert cli_catalog_refresh(Namespace(repository=None, force=False)) == 1
    assert "no git_repo section is named nowhere" in capsys.readouterr().out

    assert cli_catalog_status(Namespace()) == 0
    assert "nowhere: never read; last error:" in capsys.readouterr().out
