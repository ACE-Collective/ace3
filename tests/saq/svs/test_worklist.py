"""The declared-vs-measured worklist (saq.svs.worklist, docs/SVS_COVERAGE.md, *The worklist*)."""

import copy
import json
import logging
from argparse import Namespace
from datetime import datetime

import pytest
from sqlalchemy import select, update

from saq.cli.commands.svs import cli_coverage_status
from saq.database.model import SVSCoverage, SVSTechniqueWorklist, User
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.svs import coverage, expectations, windows, worklist
from saq.svs.attack import load_attack_catalog
from saq.svs.constants import WorklistKind, WorklistStatus
from saq.svs.coverage import refresh_coverage, technique_detail
from saq.svs.signatures import SignatureTags
from saq.svs.worklist import (
    InvalidResolution,
    UnknownWorklistRow,
    WorklistConflict,
    compute_worklist,
    derive_status,
    mapping_counts,
    reopen,
    resolve,
    resolve_many,
)
from tests.saq.svs.conftest import ATTACK_EXTRACT, add_catalog_test, add_test_host, write_hunt

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
SIGNATURE = "22222222-bbbb-4bbb-8bbb-222222222222"
OTHER_SIGNATURE = "44444444-dddd-4ddd-8ddd-444444444444"
T0 = datetime(2026, 10, 17, 12, 0, 0)


def _tag(uuid: str, *declared: str, counts: bool = True) -> SignatureTags:
    return SignatureTags(uuid, "hunt", f"hunt {uuid[:4]}", counts, tuple(declared), ())


def _measured(**by_signature) -> dict:
    """{signature: {technique: {(guid, platform)}}} from signature=[technique, ...]."""
    return {signature: {technique: {(GUID, "windows")} for technique in techniques}
            for signature, techniques in by_signature.items()}


def _summary(rows) -> dict[tuple[str, str], tuple[str, bool, list[str]]]:
    return {key: (row.kind, row.confirmed, json.loads(row.declared_as)) for key, row in rows.items()}


#
# deriving
#

@pytest.mark.unit
class TestDerive:
    @pytest.mark.parametrize("kind, produced, tag_present, confirmed, resolution, expected", [
        ("declared", True, True, True, None, "confirmed"),
        # confirmed wins over a resolution
        ("declared", True, True, True, "remove", "confirmed"),
        ("declared", True, True, False, None, "open"),
        ("declared", True, True, False, "keep", "kept"),
        ("declared", True, True, False, "remove", "remove_pending"),
        ("declared", False, False, False, "remove", "removed"),
        ("declared", False, False, False, "keep", "retired"),
        ("declared", False, False, False, None, "retired"),
        # the tag is still there, the signature isn't measured any more
        ("declared", False, True, False, "remove", "retired"),
        ("undeclared", True, False, False, None, "undeclared"),
        ("undeclared", False, False, False, None, "retired"),
        ("unknown", True, True, False, None, "unknown"),
        ("unknown", False, False, False, None, "retired"),
    ])
    def test_status(self, kind, produced, tag_present, confirmed, resolution, expected):
        assert derive_status(kind, produced=produced, tag_present=tag_present, confirmed=confirmed,
                             resolution=resolution) == expected

    @pytest.mark.parametrize("kind, tag_present, signature_counts, known, status, resolution, expected", [
        ("declared", True, True, True, "open", None, True),
        ("declared", True, True, True, "kept", "keep", True),
        ("declared", True, True, True, "remove_pending", "remove", False),
        ("declared", True, True, True, "confirmed", "remove", True),
        # a retired row's remove still stands
        ("declared", True, True, True, "retired", "remove", False),
        ("declared", True, True, True, "retired", None, True),
        ("declared", False, True, True, "retired", None, False),
        ("declared", True, False, True, "open", None, False),
        ("declared", True, True, False, "confirmed", None, False),
        ("undeclared", False, True, True, "undeclared", None, False),
        ("unknown", True, True, False, "unknown", None, False),
    ])
    def test_counts(self, kind, tag_present, signature_counts, known, status, resolution, expected):
        assert mapping_counts(kind, tag_present=tag_present, signature_counts=signature_counts, known=known,
                              status=status, resolution=resolution) is expected


@pytest.mark.unit
class TestCompute:
    def test_a_parent_tag_is_confirmed_by_a_sub_technique(self, attack_catalog):
        rows = compute_worklist(attack_catalog, {SIGNATURE: _tag(SIGNATURE, "T1059")},
                                _measured(**{SIGNATURE: ["T1059.001"]}), {})
        assert _summary(rows) == {(SIGNATURE, "T1059"): ("declared", True, ["T1059"])}
        row = rows[(SIGNATURE, "T1059")]
        assert (row.tag_present, row.measured, json.loads(row.measured_techniques), row.signature_name,
                row.signature_family, row.signature_counts) == (True, True, ["T1059.001"], "hunt 2222", "hunt", True)

    def test_a_sub_technique_tag_is_not_confirmed_by_its_parent(self, attack_catalog):
        rows = compute_worklist(attack_catalog, {SIGNATURE: _tag(SIGNATURE, "T1059.001")},
                                _measured(**{SIGNATURE: ["T1059"]}), {})
        assert _summary(rows) == {(SIGNATURE, "T1059"): ("undeclared", False, []),
                                  (SIGNATURE, "T1059.001"): ("declared", False, ["T1059.001"])}

    def test_a_sibling_does_not_confirm(self, attack_catalog):
        rows = compute_worklist(attack_catalog, {SIGNATURE: _tag(SIGNATURE, "T1059.001")},
                                _measured(**{SIGNATURE: ["T1059.002"]}), {})
        assert _summary(rows) == {(SIGNATURE, "T1059.001"): ("declared", False, ["T1059.001"]),
                                  (SIGNATURE, "T1059.002"): ("undeclared", False, [])}

    def test_revoked_ids_and_ids_that_meet(self, attack_catalog):
        # T1086 was revoked to T1059.001: both tags are one row
        rows = compute_worklist(attack_catalog, {SIGNATURE: _tag(SIGNATURE, "T1059.001", "T1086")},
                                _measured(**{SIGNATURE: ["T1059.001"]}), {})
        assert _summary(rows) == {(SIGNATURE, "T1059.001"): ("declared", True, ["T1059.001", "T1086"])}

    def test_unknown_ids(self, attack_catalog):
        rows = compute_worklist(attack_catalog, {SIGNATURE: _tag(SIGNATURE, "T9999", "T1234.001")},
                                _measured(**{SIGNATURE: ["T1234.001"]}), {})
        assert _summary(rows) == {
            # a custom atomic measures it: a declaration, confirmed, though the release lacks it
            (SIGNATURE, "T1234.001"): ("declared", True, ["T1234.001"]),
            (SIGNATURE, "T9999"): ("unknown", False, ["T9999"]),
        }
        assert rows[(SIGNATURE, "T1234.001")].known is False

    def test_untagged_and_unmeasured_signatures(self, attack_catalog):
        rows = compute_worklist(attack_catalog, {OTHER_SIGNATURE: _tag(OTHER_SIGNATURE, "T1547")},
                                _measured(**{SIGNATURE: ["T1547"]}), {SIGNATURE: ("yara", "Some rule")})
        # only measured signatures have rows
        assert _summary(rows) == {(SIGNATURE, "T1547"): ("undeclared", False, [])}
        row = rows[(SIGNATURE, "T1547")]
        assert (row.signature_family, row.signature_name, row.signature_counts) == ("yara", "Some rule", False)


#
# the refresh and the resolutions
#

@pytest.fixture
def tag(hunt_dir):
    """Tags a signature, a hunt, with mitre: techniques (or none) for the next refresh."""
    def set_tags(uuid: str, *techniques: str):
        write_hunt(hunt_dir, uuid, tags=[f"mitre:{technique}" for technique in techniques])
        windows.clear_cache()
    return set_tags


@pytest.fixture
def use_catalog(monkeypatch):
    def use(catalog):
        monkeypatch.setattr(coverage, "get_attack_catalog", lambda: catalog)
    return use


@pytest.fixture
def refreshable(hunt_dir, yara_dir, attack_catalog, use_catalog):
    use_catalog(attack_catalog)
    add_test_host("win10-01")


@pytest.fixture
def user_id() -> int:
    return get_db().execute(select(User.id).where(User.username == "unittest")).scalar_one()


def _expect(guid: str, signature: str, user_id: int):
    expectations.set_expectation(guid, signature, "expected", user_id, platform="windows")


def _worklist() -> dict[tuple[str, str], SVSTechniqueWorklist]:
    with private_transaction() as session:
        rows = {(row.signature_uuid, row.technique): row
                for row in session.execute(select(SVSTechniqueWorklist)).scalars()}
        session.expunge_all()
    return rows


def _statuses() -> dict[tuple[str, str], str]:
    return {key: row.status for key, row in _worklist().items()}


def _coverage(technique: str, platform: str = "windows") -> SVSCoverage:
    with private_transaction() as session:
        row = session.execute(select(SVSCoverage).where(SVSCoverage.technique == technique,
                                                        SVSCoverage.platform == platform)).scalar_one()
        session.expunge(row)
    return row


@pytest.fixture
def measured(refreshable, user_id, tag):
    """SIGNATURE is expected of a T1059.001 test, and tagged T1547, which no test measures."""
    add_catalog_test(GUID)
    _expect(GUID, SIGNATURE, user_id)
    tag(SIGNATURE, "T1547")


@pytest.mark.integration
class TestRefresh:
    def test_rows_are_written_once(self, measured):
        result = refresh_coverage("test", now=T0)
        assert (result.worklist_rows, result.worklist_changed) == (2, 2)
        rows = _worklist()
        assert _statuses() == {(SIGNATURE, "T1059.001"): "undeclared", (SIGNATURE, "T1547"): "open"}
        open_row = rows[(SIGNATURE, "T1547")]
        assert (open_row.kind, open_row.counts, open_row.measured, json.loads(open_row.measured_techniques),
                open_row.first_seen_at, open_row.status_changed_at) == (
            "declared", True, True, ["T1059.001"], T0, T0)

        before = {key: row.updated_at for key, row in rows.items()}
        again = refresh_coverage("test")
        assert again.worklist_changed == 0
        assert {key: row.updated_at for key, row in _worklist().items()} == before

    def test_remove_stops_counting_from_the_next_refresh(self, measured, user_id):
        refresh_coverage("test")
        assert _coverage("T1547").state == "manual"

        row = resolve(SIGNATURE, "t1547", "remove", "it never fires on T1547", user_id,
                      reference="https://git.example/rules/pull/7", actor="unittest", now=T0)
        assert (row.status, row.counts, row.resolution, row.reason, row.reference, row.resolved_by_user_id,
                row.resolved_at, row.status_changed_at) == (
            "remove_pending", False, "remove", "it never fires on T1547", "https://git.example/rules/pull/7",
            user_id, T0, T0)
        # coverage follows at the next refresh
        assert _coverage("T1547").state == "manual"
        refresh_coverage("test")
        assert (_coverage("T1547").state, _coverage("T1547").manual_signatures) == ("none", 0)
        assert _statuses()[(SIGNATURE, "T1547")] == "remove_pending"

        row = reopen(SIGNATURE, "T1547", user_id, actor="unittest")
        assert (row.status, row.counts, row.resolution, row.resolved_by_user_id) == ("open", True, None, None)
        refresh_coverage("test")
        assert _coverage("T1547").state == "manual"

    def test_a_confirmed_tag_counts_whatever_its_resolution(self, refreshable, user_id, tag):
        add_catalog_test(GUID)
        _expect(GUID, SIGNATURE, user_id)
        tag(SIGNATURE, "T1059")
        refresh_coverage("test")
        # resolved before measurement confirmed it
        with private_transaction() as session:
            session.execute(update(SVSTechniqueWorklist).values(resolution="remove", reason="r"))
        refresh_coverage("test")
        row = _worklist()[(SIGNATURE, "T1059")]
        assert (row.status, row.counts, row.resolution) == ("confirmed", True, "remove")
        # the tag still makes T1059 manual where no test runs
        assert _coverage("T1059", "macos").state == "manual"

    def test_the_tag_goes_and_comes_back(self, measured, user_id, tag, caplog):
        refresh_coverage("test")
        resolve(SIGNATURE, "T1547", "remove", "dropping it", user_id)

        tag(SIGNATURE)
        refresh_coverage("test")
        row = _worklist()[(SIGNATURE, "T1547")]
        assert (row.status, row.tag_present, row.counts, row.resolution) == ("removed", False, False, "remove")

        tag(SIGNATURE, "T1547")
        with caplog.at_level(logging.INFO):
            refresh_coverage("test", now=T0)
        row = _worklist()[(SIGNATURE, "T1547")]
        assert (row.status, row.tag_present, row.counts, row.resolution, row.reason, row.resolved_by_user_id) == (
            "open", True, True, None, None, None)
        assert [r for r in caplog.records if "cleared: the tag is back" in r.getMessage()]
        assert _coverage("T1547").state == "manual"

    def test_a_tag_dropped_without_a_resolution_retires(self, measured, tag):
        refresh_coverage("test")
        tag(SIGNATURE)
        refresh_coverage("test")
        assert _statuses()[(SIGNATURE, "T1547")] == "retired"
        assert _statuses()[(SIGNATURE, "T1059.001")] == "undeclared"

    def test_measurement_lost(self, measured, user_id):
        refresh_coverage("test")
        resolve(SIGNATURE, "T1547", "remove", "dropping it", user_id)
        expectations.remove_expectation(GUID, "windows", SIGNATURE, user_id)
        refresh_coverage("test")
        rows = _worklist()
        assert {key: row.status for key, row in rows.items()} == {
            (SIGNATURE, "T1059.001"): "retired", (SIGNATURE, "T1547"): "retired"}
        row = rows[(SIGNATURE, "T1547")]
        assert (row.measured, row.measured_techniques, row.resolution, row.counts) == (False, "[]", "remove", False)
        # the remove still stands
        assert _coverage("T1547").state == "none"

        # measured again: the resolution is back in force as it was
        _expect(GUID, SIGNATURE, user_id)
        refresh_coverage("test")
        assert _statuses()[(SIGNATURE, "T1547")] == "remove_pending"

    def test_an_attack_upgrade_carries_the_resolution(self, refreshable, user_id, use_catalog, attack_catalog,
                                                      tag, tmp_path, caplog):
        # in the older release T1086 is still a technique of its own
        older = copy.deepcopy(ATTACK_EXTRACT)
        older["release"] = "v98.0"
        older["revoked"].pop("T1086")
        older["techniques"]["T1086"] = {"name": "PowerShell", "parent": None, "tactics": ["TA0002"],
                                        "platforms": ["windows"], "deprecated": False}
        path = tmp_path / "v98.0.json"
        path.write_text(json.dumps(older))
        use_catalog(load_attack_catalog(path))

        add_catalog_test(GUID, technique="T1547")
        _expect(GUID, SIGNATURE, user_id)
        tag(SIGNATURE, "T1086")
        refresh_coverage("test")
        resolve(SIGNATURE, "T1086", "remove", "wrong technique", user_id, reference="https://git.example/pull/1")

        # the new release revoked T1086 to T1059.001
        use_catalog(attack_catalog)
        with caplog.at_level(logging.INFO):
            refresh_coverage("test")

        rows = _worklist()
        old, new = rows[(SIGNATURE, "T1086")], rows[(SIGNATURE, "T1059.001")]
        assert (old.status, old.resolution) == ("retired", None)
        assert (new.status, new.kind, json.loads(new.declared_as), new.resolution, new.reason, new.reference,
                new.resolved_by_user_id, new.counts) == (
            "remove_pending", "declared", ["T1086"], "remove", "wrong technique", "https://git.example/pull/1",
            user_id, False)
        (moved,) = [r for r in caplog.records if "moved from T1086 to T1059.001" in r.getMessage()]
        assert (moved.from_technique, moved.technique, moved.resolution) == ("T1086", "T1059.001", "remove")
        assert _coverage("T1059.001").manual_signatures == 0

    def test_the_drill_down_says_removed(self, measured, user_id):
        refresh_coverage("test")
        resolve(SIGNATURE, "T1547", "remove", "dropping it", user_id)
        with private_transaction() as session:
            detail = technique_detail(session, coverage.get_attack_catalog(), "T1547")
        (mapping,) = detail.manual
        assert (mapping.counts, mapping.reason) == (False, "removed")

    def test_cli_status_counts_the_worklist(self, measured, capsys):
        refresh_coverage("test")
        assert cli_coverage_status(Namespace()) == 0
        assert "worklist: 1 open, 1 undeclared" in capsys.readouterr().out


@pytest.mark.integration
class TestResolutions:
    @pytest.fixture(autouse=True)
    def rows(self, measured):
        refresh_coverage("test")

    def test_only_unconfirmed_declarations_resolve(self, user_id):
        with pytest.raises(WorklistConflict) as e:
            resolve(SIGNATURE, "T1059.001", "keep", "why", user_id)
        assert e.value.status == "undeclared"
        with pytest.raises(UnknownWorklistRow):
            resolve(SIGNATURE, "T1059.002", "keep", "why", user_id)
        row = resolve(SIGNATURE, "T1547", "keep", "a test can't reach it", user_id)
        assert (row.status, row.counts) == ("kept", True)
        # deciding again replaces the decision
        assert resolve(SIGNATURE, "T1547", "remove", "changed my mind", user_id).status == "remove_pending"

    @pytest.mark.parametrize("resolution, reason, reference, message", [
        ("maybe", "why", None, "resolution must be one of keep, remove"),
        ("keep", "  ", None, "needs a reason"),
        ("remove", "why", "ftp://example/x", "not an http"),
        ("remove", "why", "https://", "not an http"),
    ])
    def test_invalid_resolutions(self, user_id, resolution, reason, reference, message):
        with pytest.raises(InvalidResolution, match=message):
            resolve(SIGNATURE, "T1547", resolution, reason, user_id, reference=reference)

    def test_reopen(self, user_id):
        with pytest.raises(UnknownWorklistRow, match="no resolution"):
            reopen(SIGNATURE, "T1547", user_id)
        resolve(SIGNATURE, "T1547", "keep", "why", user_id)
        assert reopen(SIGNATURE, "T1547", user_id).status == "open"

    def test_audit_records(self, user_id, caplog):
        with caplog.at_level(logging.INFO):
            resolve(SIGNATURE, "T1547", "remove", "why", user_id, reference="https://x.example/1", actor="unittest")
            reopen(SIGNATURE, "T1547", user_id, actor="unittest")
        (set_record,) = [r for r in caplog.records if r.getMessage() == "AUDIT: svs worklist resolution set"]
        assert (set_record.signature_uuid, set_record.technique, set_record.resolution, set_record.reason,
                set_record.reference, set_record.actor, set_record.actor_user_id) == (
            SIGNATURE, "T1547", "remove", "why", "https://x.example/1", "unittest", user_id)
        (cleared,) = [r for r in caplog.records if r.getMessage() == "AUDIT: svs worklist resolution cleared"]
        assert (cleared.resolution, cleared.cleared_resolution, cleared.status) == (None, "remove", "open")

    def test_resolve_many(self, user_id, caplog):
        with caplog.at_level(logging.INFO):
            result = resolve_many([(SIGNATURE, "T1547"), (SIGNATURE, "T1059.001"), (OTHER_SIGNATURE, "T1547"),
                                   (SIGNATURE, "T1547")], "keep", "bulk", user_id)
        assert result.done == [(SIGNATURE, "T1547")]
        assert result.conflicts == {(SIGNATURE, "T1059.001"): "undeclared"}
        assert result.unknown == [(OTHER_SIGNATURE, "T1547")]
        assert _statuses()[(SIGNATURE, "T1547")] == "kept"
        assert len([r for r in caplog.records if r.getMessage() == "AUDIT: svs worklist resolution set"]) == 1
        with pytest.raises(InvalidResolution):
            resolve_many([(SIGNATURE, "T1547")], "keep", "", user_id)

    def test_resolving_waits_for_a_refresh(self, user_id, monkeypatch):
        # a resolution takes the refresh lock first: it can't commit in the middle of a refresh
        taken = []
        original = worklist.lock_refresh
        monkeypatch.setattr(worklist, "lock_refresh", lambda session: taken.append(True) or original(session))
        resolve(SIGNATURE, "T1547", "keep", "why", user_id)
        reopen(SIGNATURE, "T1547", user_id)
        resolve_many([(SIGNATURE, "T1547")], "keep", "why", user_id)
        assert taken == [True, True, True]


@pytest.mark.unit
def test_status_and_kind_values_match_the_model():
    columns = SVSTechniqueWorklist.__table__.columns
    assert list(columns["status"].type.enums) == [status.value for status in WorklistStatus]
    assert list(columns["kind"].type.enums) == [kind.value for kind in WorklistKind]
