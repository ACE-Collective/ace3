"""The effective verdict rule (saq.detection_verdicts.effective), in Python and in SQL."""

from datetime import datetime

import pytest
from sqlalchemy import update

from saq.configuration.config import get_config
from saq.database.model import Alert, DetectionPointVerdict, SVSAttribution, User
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.detection_verdicts.constants import SOURCE_EXPLICIT, SOURCE_INHERITED_MULTI, SOURCE_INHERITED_SINGLE
from saq.detection_verdicts.effective import compute_effective, disposition_class_lists
from saq.detection_verdicts.query import list_alert_detection_points
from saq.disposition import get_disposition_class
from tests.saq.helpers import insert_alert_with_detections
from tests.saq.svs.conftest import attribute_to_run

SIG_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
SIG_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


@pytest.mark.unit
@pytest.mark.parametrize("disposition_class, override, multi, unreviewed, expected", [
    # unclassified: no verdict, overrides included
    (None, None, False, False, (None, None)),
    (None, "fp", True, False, (None, None)),
    # a test run that is not reviewed: no verdict
    ("tp", "fp", True, True, (None, None)),
    ("fp", None, False, True, (None, None)),
    # FP alert: every detection FP, overrides masked, never "unconfirmed"
    ("fp", None, False, False, ("fp", SOURCE_INHERITED_SINGLE)),
    ("fp", None, True, False, ("fp", SOURCE_INHERITED_SINGLE)),
    ("fp", "tp", True, False, ("fp", SOURCE_INHERITED_SINGLE)),
    # TP alert: an override wins
    ("tp", "fp", True, False, ("fp", SOURCE_EXPLICIT)),
    ("tp", "tp", True, False, ("tp", SOURCE_EXPLICIT)),
    ("tp", "fp", False, False, ("fp", SOURCE_EXPLICIT)),
    # TP alert, inherited: by the number of signatures
    ("tp", None, False, False, ("tp", SOURCE_INHERITED_SINGLE)),
    ("tp", None, True, False, ("tp", SOURCE_INHERITED_MULTI)),
])
def test_compute_effective(disposition_class, override, multi, unreviewed, expected):
    assert compute_effective(disposition_class, override, multi, unreviewed) == expected


@pytest.mark.unit
def test_disposition_class_lists_follow_the_configuration(monkeypatch):
    tp, fp = disposition_class_lists()
    assert "FALSE_POSITIVE" in fp and "DELIVERY" in tp
    assert "OPEN" not in tp + fp

    monkeypatch.setitem(get_config().disposition_classification, "REVIEWED", "fp")
    assert "REVIEWED" in disposition_class_lists()[1]


def _unittest_user_id() -> int:
    return get_db().query(User.id).filter(User.username == "unittest").scalar()


def _override(alert_id: int, content_hash: str, verdict: str):
    get_db().add(DetectionPointVerdict(
        alert_id=alert_id, content_hash=content_hash, signature_uuid="x", verdict=verdict,
        user_id=_unittest_user_id()))
    get_db().commit()


SINGLE = [{"description": "d1", "signature_uuid": SIG_A, "fqdn": "one.example.com"},
          {"description": "d1", "signature_uuid": SIG_A, "fqdn": "two.example.com"}]
MULTI = [{"description": "d1", "signature_uuid": SIG_A, "fqdn": "one.example.com"},
         {"description": "d2", "signature_uuid": SIG_B}]


@pytest.mark.integration
@pytest.mark.parametrize("disposition", ["OPEN", "IGNORE", "FALSE_POSITIVE", "DELIVERY", "GRAYWARE", "NOT_CONFIGURED"])
@pytest.mark.parametrize("detections", [SINGLE, MULTI], ids=["single", "multi"])
@pytest.mark.parametrize("with_override", [False, True], ids=["inherited", "override"])
@pytest.mark.parametrize("run_state", [None, "ended", "reviewed"], ids=["no-run", "unreviewed-run", "reviewed-run"])
def test_sql_agrees_with_python(disposition, detections, with_override, run_state):
    alert = insert_alert_with_detections(detections, disposition=disposition)
    if run_state is not None:
        attribute_to_run(alert.uuid, run_state)
    rows = list_alert_detection_points(alert.id)
    assert len(rows) == 2
    if with_override:
        _override(alert.id, rows[0]["content_hash"], "fp")
        rows = list_alert_detection_points(alert.id)

    multi = len({row["signature_uuid"] for row in rows}) > 1
    for row in rows:
        expected = compute_effective(get_disposition_class(disposition), row["override"], multi,
                                     unreviewed_run=run_state == "ended")
        assert (row["verdict"], row["verdict_source"]) == expected, row


@pytest.mark.integration
def test_a_removed_attribution_gives_the_verdicts_back():
    alert = insert_alert_with_detections(SINGLE, disposition="DELIVERY")
    run = attribute_to_run(alert.uuid, "ended")
    assert {row["verdict"] for row in list_alert_detection_points(alert.id)} == {None}

    with private_transaction() as session:
        session.execute(update(SVSAttribution).where(SVSAttribution.run_id == run.id).values(
            removed_at=datetime.now(), removed_by="alice"))
    get_db().expire_all()
    assert {row["verdict"] for row in list_alert_detection_points(alert.id)} == {"tp"}


@pytest.mark.integration
def test_a_classification_change_relabels_at_read_time(monkeypatch):
    alert = insert_alert_with_detections(SINGLE, disposition="REVIEWED")
    assert {row["verdict"] for row in list_alert_detection_points(alert.id)} == {None}

    monkeypatch.setitem(get_config().disposition_classification, "REVIEWED", "fp")
    assert {row["verdict"] for row in list_alert_detection_points(alert.id)} == {"fp"}


@pytest.mark.integration
def test_override_survives_an_fp_round_trip():
    # TP -> FP masks the override without deleting it; back to TP restores it (DP-3)
    alert = insert_alert_with_detections(MULTI, disposition="DELIVERY")
    content_hash = list_alert_detection_points(alert.id)[0]["content_hash"]
    _override(alert.id, content_hash, "fp")

    def _first():
        get_db().expire_all()
        return list_alert_detection_points(alert.id)[0]

    for disposition, expected in [("FALSE_POSITIVE", ("fp", SOURCE_INHERITED_SINGLE)),
                                  ("DELIVERY", ("fp", SOURCE_EXPLICIT))]:
        get_db().execute(update(Alert).where(Alert.id == alert.id).values(disposition=disposition))
        get_db().commit()
        row = _first()
        assert (row["verdict"], row["verdict_source"]) == expected
        assert row["override"] == "fp"
