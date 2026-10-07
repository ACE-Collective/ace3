"""The label of a sample (saq.svs.labels), in Python and in SQL."""

import itertools
import uuid

import pytest
from sqlalchemy import delete, select, true

from saq.database.model import Alert, User
from saq.database.pool import get_db
from saq.detection_verdicts.constants import SOURCE_EXPLICIT, SOURCE_INHERITED_MULTI, SOURCE_INHERITED_SINGLE
from saq.detection_verdicts.query import list_alert_detection_points
from saq.detection_verdicts.store import set_verdict
from saq.svs import labels
from saq.svs.labels import STRENGTHS, Votes, aggregate_label
from saq.svs.samples import get_sample, samples_subquery
from tests.saq.svs.conftest import OTHER_RULE_UUID, RULE_UUID, graded_alert, insert_capture, set_disposition


@pytest.mark.unit
@pytest.mark.parametrize("votes, expected", [
    (Votes(), (None, None)),
    (Votes(tp_inherited_multi=3), ("tp", SOURCE_INHERITED_MULTI)),
    (Votes(fp_inherited_single=1), ("fp", SOURCE_INHERITED_SINGLE)),
    (Votes(tp_inherited_single=1, fp_inherited_single=1), ("conflicted", SOURCE_INHERITED_SINGLE)),
    # a stronger vote decides, whatever the number of weaker ones
    (Votes(fp_explicit=1, tp_inherited_single=5, tp_inherited_multi=5), ("fp", SOURCE_EXPLICIT)),
    (Votes(fp_inherited_single=1, tp_inherited_multi=9), ("fp", SOURCE_INHERITED_SINGLE)),
    # disagreement below the deciding strength does not matter
    (Votes(tp_explicit=1, tp_inherited_multi=1, fp_inherited_multi=1), ("tp", SOURCE_EXPLICIT)),
    (Votes(tp_explicit=2, fp_explicit=1), ("conflicted", SOURCE_EXPLICIT)),
])
def test_aggregate_label(votes, expected):
    assert aggregate_label(votes) == expected


@pytest.mark.unit
@pytest.mark.parametrize("counts", list(itertools.product([0, 1], repeat=6)))
def test_the_strongest_strength_decides(counts):
    votes = Votes(**dict(zip([name for name, _, _ in labels.VOTE_COLUMNS], counts)))
    label, source = aggregate_label(votes)
    for strength in STRENGTHS:
        tp, fp = votes.count("tp", strength), votes.count("fp", strength)
        if tp or fp:
            assert source == strength
            assert label == ("conflicted" if tp and fp else "tp" if tp else "fp")
            return
    assert (label, source) == (None, None)


def _user_id() -> int:
    return get_db().query(User.id).filter(User.username == "unittest").scalar()


def _sample(observable, rule_uuid: str = RULE_UUID) -> dict:
    get_db().expire_all()
    return get_sample(observable.value.lower(), rule_uuid)


def _assert_sql_agrees(sample: dict):
    """The SQL label is what aggregate_label() makes of the SQL votes."""
    assert (sample["label"], sample["label_source"]) == aggregate_label(Votes(**sample["votes"]))


def _hash_of(alert, observable, rule_uuid: str = RULE_UUID) -> str:
    (row,) = [row for row in list_alert_detection_points(alert.id)
              if row["signature_uuid"] == rule_uuid and row["node_value_sha256"] == observable.value.lower()]
    return row["content_hash"]


@pytest.mark.integration
def test_an_fp_alert_labels_its_samples_fp():
    _, files = graded_alert("FALSE_POSITIVE", {"a.bin": [RULE_UUID, OTHER_RULE_UUID]})
    sample = _sample(files["a.bin"])
    assert (sample["label"], sample["label_source"]) == ("fp", SOURCE_INHERITED_SINGLE)
    assert sample["votes"]["fp_inherited_single"] == 1
    _assert_sql_agrees(sample)


@pytest.mark.integration
def test_a_tp_alert_with_one_signature_labels_inherited_single():
    _, files = graded_alert("DELIVERY", {"a.bin": [RULE_UUID]})
    sample = _sample(files["a.bin"])
    assert (sample["label"], sample["label_source"]) == ("tp", SOURCE_INHERITED_SINGLE)
    _assert_sql_agrees(sample)


@pytest.mark.integration
def test_a_tp_alert_with_several_signatures_labels_inherited_multi():
    _, files = graded_alert("DELIVERY", {"a.bin": [RULE_UUID, OTHER_RULE_UUID]})
    for rule_uuid in (RULE_UUID, OTHER_RULE_UUID):
        sample = _sample(files["a.bin"], rule_uuid)
        assert (sample["label"], sample["label_source"]) == ("tp", SOURCE_INHERITED_MULTI)
        _assert_sql_agrees(sample)


@pytest.mark.integration
def test_an_explicit_override_decides():
    alert, files = graded_alert("DELIVERY", {"a.bin": [RULE_UUID, OTHER_RULE_UUID]})
    set_verdict(alert.id, _hash_of(alert, files["a.bin"]), "fp", _user_id())

    sample = _sample(files["a.bin"])
    assert (sample["label"], sample["label_source"]) == ("fp", SOURCE_EXPLICIT)
    _assert_sql_agrees(sample)
    # the other rule's sample is untouched
    assert _sample(files["a.bin"], OTHER_RULE_UUID)["label_source"] == SOURCE_INHERITED_MULTI


@pytest.mark.integration
def test_disagreeing_votes_of_one_strength_conflict():
    content = f"conflicted {uuid.uuid4()}".encode()
    first, first_files = graded_alert("DELIVERY", {"a.bin": [RULE_UUID]}, contents={"a.bin": content})
    graded_alert("FALSE_POSITIVE", {"b.bin": [RULE_UUID]}, contents={"b.bin": content})

    sample = _sample(first_files["a.bin"])
    assert sample["capture_count"] == 2
    assert (sample["label"], sample["label_source"]) == ("conflicted", SOURCE_INHERITED_SINGLE)
    _assert_sql_agrees(sample)

    # an explicit vote outweighs both
    set_verdict(first.id, _hash_of(first, first_files["a.bin"]), "tp", _user_id())
    sample = _sample(first_files["a.bin"])
    assert (sample["label"], sample["label_source"]) == ("tp", SOURCE_EXPLICIT)
    _assert_sql_agrees(sample)


@pytest.mark.integration
def test_an_fp_alert_outweighs_an_unconfirmed_tp():
    content = f"precedence {uuid.uuid4()}".encode()
    _, files = graded_alert("DELIVERY", {"a.bin": [RULE_UUID, OTHER_RULE_UUID]}, contents={"a.bin": content})
    graded_alert("FALSE_POSITIVE", {"b.bin": [RULE_UUID]}, contents={"b.bin": content})

    sample = _sample(files["a.bin"])
    assert sample["votes"]["tp_inherited_multi"] == 1 and sample["votes"]["fp_inherited_single"] == 1
    assert (sample["label"], sample["label_source"]) == ("fp", SOURCE_INHERITED_SINGLE)


@pytest.mark.integration
@pytest.mark.parametrize("disposition", ["OPEN", "REVIEWED", "IGNORE"])
def test_an_unclassified_alert_casts_no_vote(disposition):
    _, files = graded_alert(disposition, {"a.bin": [RULE_UUID]})
    sample = _sample(files["a.bin"])
    assert sample["capture_count"] == 1
    assert (sample["label"], sample["label_source"]) == (None, None)
    assert set(sample["votes"].values()) == {0}


@pytest.mark.integration
def test_a_deleted_alert_casts_no_vote():
    alert, files = graded_alert("FALSE_POSITIVE", {"a.bin": [RULE_UUID]})
    get_db().execute(delete(Alert).where(Alert.id == alert.id))
    get_db().commit()

    sample = _sample(files["a.bin"])
    assert sample["capture_count"] == 1
    assert sample["label"] is None


@pytest.mark.integration
def test_the_same_bytes_under_two_names_are_two_votes():
    content = f"twice {uuid.uuid4()}".encode()
    _, files = graded_alert("FALSE_POSITIVE", {"a.bin": [RULE_UUID], "b.bin": [RULE_UUID]},
                            contents={"a.bin": content, "b.bin": content})
    sample = _sample(files["a.bin"])
    assert sample["capture_count"] == 1
    assert sample["votes"]["fp_inherited_single"] == 2


@pytest.mark.integration
def test_a_detection_of_another_rule_or_file_does_not_vote():
    alert, files = graded_alert("FALSE_POSITIVE", {"a.bin": [RULE_UUID], "b.bin": [OTHER_RULE_UUID]})
    # a capture of b.bin's bytes for a rule that never matched it
    insert_capture(alert.uuid, files["b.bin"].value.lower(), RULE_UUID)

    sample = _sample(files["b.bin"])
    assert sample["label"] is None
    assert _sample(files["a.bin"])["votes"]["fp_inherited_single"] == 1


@pytest.mark.integration
def test_an_unreviewed_test_run_casts_no_vote(monkeypatch):
    _, files = graded_alert("DELIVERY", {"a.bin": [RULE_UUID]})
    monkeypatch.setattr("saq.detection_verdicts.effective.unreviewed_run_condition", lambda alert: true())
    assert _sample(files["a.bin"])["label"] is None


@pytest.mark.integration
def test_a_disposition_change_relabels_at_read_time():
    alert, files = graded_alert("FALSE_POSITIVE", {"a.bin": [RULE_UUID]})
    assert _sample(files["a.bin"])["label"] == "fp"
    set_disposition(alert.uuid, "DELIVERY")
    assert _sample(files["a.bin"])["label"] == "tp"


@pytest.mark.integration
def test_sql_agrees_with_python_over_the_whole_corpus():
    content = f"corpus {uuid.uuid4()}".encode()
    first, files = graded_alert("DELIVERY", {"a.bin": [RULE_UUID, OTHER_RULE_UUID], "c.bin": [RULE_UUID]},
                                contents={"a.bin": content})
    graded_alert("FALSE_POSITIVE", {"b.bin": [RULE_UUID]}, contents={"b.bin": content})
    graded_alert("REVIEWED", {"d.bin": [OTHER_RULE_UUID]})
    set_verdict(first.id, _hash_of(first, files["a.bin"], OTHER_RULE_UUID), "fp", _user_id())

    samples = samples_subquery()
    rows = [dict(row) for row in get_db().execute(select(samples)).mappings()]
    assert len(rows) == 4
    for row in rows:
        votes = Votes(**{name: int(row[name]) for name, _, _ in labels.VOTE_COLUMNS})
        assert (row["label"], row["label_source"]) == aggregate_label(votes), row
