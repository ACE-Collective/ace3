"""Writing analyst verdicts (saq.detection_verdicts.store) and the verdict history."""

import pytest
from sqlalchemy import select, update

from saq.configuration.config import get_config
from saq.database.model import (
    Alert,
    DetectionPoint,
    DetectionPointVerdict,
    DetectionPointVerdictHistory,
    User,
)
from saq.database.pool import get_db
from saq.detection_verdicts import store
from saq.detection_verdicts.effective import SOURCE_EXPLICIT, SOURCE_INHERITED_MULTI
from saq.detection_verdicts.query import list_alert_detection_points
from saq.detection_verdicts.store import (
    DetectionNotFound,
    VerdictNotAllowed,
    clear_verdict,
    confirm_alert,
    set_verdict,
)
from tests.saq.helpers import insert_alert_with_detections

pytestmark = pytest.mark.integration

SIG_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
SIG_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
MULTI = [{"description": "generic logo rule", "signature_uuid": SIG_A, "fqdn": "one.example.com"},
         {"description": "generic logo rule", "signature_uuid": SIG_A, "fqdn": "two.example.com"},
         {"description": "phish kit", "signature_uuid": SIG_B}]


@pytest.fixture
def user_id() -> int:
    return get_db().query(User.id).filter(User.username == "unittest").scalar()


def _hashes(alert) -> list[str]:
    return [row["content_hash"] for row in list_alert_detection_points(alert.id)]


def _history(alert) -> list[tuple]:
    get_db().expire_all()
    return [(h.content_hash, h.old_verdict, h.new_verdict) for h in get_db().execute(
        select(DetectionPointVerdictHistory)
        .where(DetectionPointVerdictHistory.alert_id == alert.id)
        .order_by(DetectionPointVerdictHistory.id)).scalars()]


def _stored(alert) -> dict[str, str]:
    get_db().expire_all()
    return {v.content_hash: v.verdict for v in get_db().execute(
        select(DetectionPointVerdict).where(DetectionPointVerdict.alert_id == alert.id)).scalars()}


def test_set_change_and_clear_record_history(user_id):
    alert = insert_alert_with_detections(MULTI, disposition="DELIVERY")
    content_hash = _hashes(alert)[0]

    assert set_verdict(alert.id, content_hash, "fp", user_id) is True
    assert _stored(alert) == {content_hash: "fp"}
    stored = get_db().execute(select(DetectionPointVerdict)).scalar_one()
    assert stored.signature_uuid == SIG_A and stored.user_id == user_id

    # writing what is already stored changes nothing and records nothing
    assert set_verdict(alert.id, content_hash, "fp", user_id) is False

    assert set_verdict(alert.id, content_hash, "tp", user_id) is True
    assert clear_verdict(alert.id, content_hash, user_id) is True
    assert clear_verdict(alert.id, content_hash, user_id) is False
    assert _stored(alert) == {}

    assert _history(alert) == [
        (content_hash, None, "fp"),
        (content_hash, "fp", "tp"),
        (content_hash, "tp", None),
    ]


def test_the_effective_verdict_follows_the_override(user_id):
    alert = insert_alert_with_detections(MULTI, disposition="DELIVERY")
    content_hash = _hashes(alert)[0]
    set_verdict(alert.id, content_hash, "fp", user_id)

    row = next(r for r in list_alert_detection_points(alert.id) if r["content_hash"] == content_hash)
    assert (row["verdict"], row["verdict_source"], row["override"]) == ("fp", SOURCE_EXPLICIT, "fp")
    assert row["override_user"] == "unittest"
    assert row["override_set_at"] is not None


@pytest.mark.parametrize("disposition", ["FALSE_POSITIVE", "OPEN", "IGNORE", "REVIEWED"])
def test_only_a_tp_alert_takes_verdicts(user_id, disposition):
    alert = insert_alert_with_detections(MULTI, disposition=disposition)
    content_hash = _hashes(alert)[0]

    with pytest.raises(VerdictNotAllowed):
        set_verdict(alert.id, content_hash, "fp", user_id)
    with pytest.raises(VerdictNotAllowed):
        confirm_alert(alert.id, user_id)
    assert _stored(alert) == {} and _history(alert) == []


def test_a_disposition_only_ace_sets_is_not_for_analysts(user_id, monkeypatch):
    # SIMULATED is the real case (phase 4); any analyst_selectable: false disposition behaves alike
    monkeypatch.setattr(get_config().dispositions["DELIVERY"], "analyst_selectable", False)
    alert = insert_alert_with_detections(MULTI, disposition="DELIVERY")
    content_hash = _hashes(alert)[0]

    with pytest.raises(VerdictNotAllowed):
        set_verdict(alert.id, content_hash, "fp", user_id)

    # ACE itself (the test run review) may
    assert set_verdict(alert.id, content_hash, "fp", user_id, analyst=False) is True


def test_a_row_from_before_detection_identity_is_refused(user_id):
    alert = insert_alert_with_detections(MULTI, disposition="DELIVERY")
    content_hash = _hashes(alert)[0]
    get_db().execute(update(DetectionPoint).where(DetectionPoint.content_hash == content_hash)
                     .values(node_kind=None))
    get_db().commit()

    with pytest.raises(VerdictNotAllowed):
        set_verdict(alert.id, content_hash, "fp", user_id)


def test_unknown_detection(user_id):
    alert = insert_alert_with_detections(MULTI, disposition="DELIVERY")
    with pytest.raises(DetectionNotFound):
        set_verdict(alert.id, "0" * 64, "fp", user_id)
    with pytest.raises(ValueError):
        set_verdict(alert.id, _hashes(alert)[0], "maybe", user_id)


def test_a_failed_write_leaves_nothing_behind(user_id, monkeypatch):
    alert = insert_alert_with_detections(MULTI, disposition="DELIVERY")
    content_hash = _hashes(alert)[0]

    def _broken_history(**kwargs):
        raise RuntimeError("history write failed")

    monkeypatch.setattr(store, "DetectionPointVerdictHistory", _broken_history)
    with pytest.raises(RuntimeError):
        set_verdict(alert.id, content_hash, "fp", user_id)

    get_db().rollback()
    assert _stored(alert) == {}


def test_confirm_upgrades_every_unconfirmed_detection(user_id):
    alert = insert_alert_with_detections(MULTI, disposition="DELIVERY")
    hashes = _hashes(alert)
    assert len(hashes) == 3
    assert {r["verdict_source"] for r in list_alert_detection_points(alert.id)} == {SOURCE_INHERITED_MULTI}

    # one detection was marked as noise: confirm leaves it alone
    set_verdict(alert.id, hashes[0], "fp", user_id)
    assert confirm_alert(alert.id, user_id) == 2
    assert confirm_alert(alert.id, user_id) == 0

    rows = {r["content_hash"]: r for r in list_alert_detection_points(alert.id)}
    assert rows[hashes[0]]["verdict"] == "fp"
    assert {(rows[h]["verdict"], rows[h]["verdict_source"]) for h in hashes[1:]} == {("tp", SOURCE_EXPLICIT)}
    assert [entry[1:] for entry in _history(alert)] == [(None, "fp"), (None, "tp"), (None, "tp")]


def test_confirm_on_a_single_signature_alert_confirms_nothing(user_id):
    alert = insert_alert_with_detections(MULTI[:2], disposition="DELIVERY")
    assert confirm_alert(alert.id, user_id) == 0
    assert _history(alert) == []


def test_verdicts_and_history_go_with_the_alert(user_id):
    alert = insert_alert_with_detections(MULTI, disposition="DELIVERY")
    set_verdict(alert.id, _hashes(alert)[0], "fp", user_id)

    alert_id = alert.id
    get_db().execute(Alert.__table__.delete().where(Alert.id == alert_id))
    get_db().commit()
    for model in (DetectionPointVerdict, DetectionPointVerdictHistory):
        assert get_db().execute(select(model).where(model.alert_id == alert_id)).first() is None
