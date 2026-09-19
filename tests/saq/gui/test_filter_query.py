"""The alert-management filter query builder, run outside Flask.

The search API and the GUI run the same filter lists, so the query builder has to work with
no current_user and no request context -- that is most of what this file asserts.
"""

import hashlib
from datetime import datetime

import pytest
import pytz

from saq.database.model import Alert, Observable, ObservableMapping, Tag, TagMapping
from saq.database.pool import get_db
from saq.gui.filter_query import (
    ANY_OBSERVABLE_TYPE,
    build_alert_query,
    count_alerts,
    create_filter,
    filter_alert_uuids,
)
from tests.saq.helpers import insert_alert

pytestmark = pytest.mark.integration

SIGNATURE_UUID = "6f3a1b2c-1111-2222-3333-444455556666"


def _attach(alert: Alert, observable_type: str, value: str, sha256: bytes | None = None) -> None:
    """Maps an observable to an alert, reusing the catalog row if it already exists.

    `observables` is an append-only catalog with a unique key on (type, sha256): the same
    observable on two alerts is one row and two observable_mapping rows.
    """
    db = get_db()
    digest = sha256 or hashlib.sha256(value.encode()).digest()
    observable = db.query(Observable).filter(
        Observable.type == observable_type, Observable.sha256 == digest).one_or_none()
    if observable is None:
        observable = Observable(type=observable_type, value=value.encode(), sha256=digest)
        db.add(observable)
        db.flush()

    db.add(ObservableMapping(observable_id=observable.id, alert_id=alert.id))
    db.commit()


def _tag(alert: Alert, name: str) -> None:
    db = get_db()
    tag = db.query(Tag).filter(Tag.name == name).one_or_none()
    if tag is None:
        tag = Tag(name=name)
        db.add(tag)
        db.flush()
    db.add(TagMapping(tag_id=tag.id, alert_id=alert.id))
    db.commit()


def _uuids(filters):
    query = build_alert_query(filters, entity=Alert, tz=pytz.utc, locations=None)
    return {row[0] for row in query.with_entities(Alert.uuid).distinct()}


@pytest.fixture
def corpus():
    db = get_db()
    signed = insert_alert()
    tagged = insert_alert()
    plain = insert_alert()
    db.execute(Alert.__table__.update().where(Alert.id == signed.id).values(insert_date=datetime(2026, 1, 1), queue="external"))
    db.execute(Alert.__table__.update().where(Alert.id == tagged.id).values(insert_date=datetime(2026, 2, 1)))
    db.commit()

    _attach(signed, "signature_id", SIGNATURE_UUID)
    _attach(signed, "ipv4", "10.20.30.40")
    _attach(tagged, "ipv4", "203.0.113.7")
    _tag(tagged, "credential-harvest")
    return signed, tagged, plain


class TestObservableFilter:
    def test_finds_alerts_carrying_a_signature_uuid_observable(self, corpus):
        """The use case this whole filter path exists to serve."""
        signed, _, _ = corpus
        assert _uuids([{"name": "Observable", "inverted": False,
                        "values": [["signature_id", SIGNATURE_UUID]]}]) == {signed.uuid}

    def test_type_and_value_must_both_match(self, corpus):
        assert _uuids([{"name": "Observable", "inverted": False,
                        "values": [["ipv4", SIGNATURE_UUID]]}]) == set()

    def test_value_is_normalized_the_way_the_engine_normalizes_it(self, corpus):
        """Matching on (type, sha256) after resolve_observable_identity(), not on the raw
        value BLOB: an email address is stored lowercased, so both spellings have to find it."""
        signed, _, _ = corpus
        _attach(signed, "email_address", "bob@example.com")
        for spelling in ("bob@example.com", "Bob@Example.com"):
            assert _uuids([{"name": "Observable", "inverted": False,
                            "values": [["email_address", spelling]]}]) == {signed.uuid}

    def test_any_type_matches_on_value_alone(self, corpus):
        signed, _, _ = corpus
        assert _uuids([{"name": "Observable", "inverted": False,
                        "values": [[ANY_OBSERVABLE_TYPE, SIGNATURE_UUID]]}]) == {signed.uuid}

    def test_values_within_one_entry_are_ored(self, corpus):
        signed, tagged, _ = corpus
        assert _uuids([{"name": "Observable", "inverted": False,
                        "values": [["ipv4", "10.20.30.40"], ["ipv4", "203.0.113.7"]]}]) == {signed.uuid, tagged.uuid}

    def test_separate_entries_are_anded(self, corpus):
        signed, _, _ = corpus
        both = [
            {"name": "Observable", "inverted": False, "values": [["signature_id", SIGNATURE_UUID]]},
            {"name": "Observable", "inverted": False, "values": [["ipv4", "10.20.30.40"]]},
        ]
        assert _uuids(both) == {signed.uuid}

        neither = both + [{"name": "Observable", "inverted": False, "values": [["ipv4", "203.0.113.7"]]}]
        assert _uuids(neither) == set()

    def test_inverted_keeps_alerts_with_no_observables_at_all(self, corpus):
        """The EXISTS form matters: a plain NOT over the outer join drops alerts that have no
        observable rows, which is the opposite of what "not this observable" means."""
        _, tagged, plain = corpus
        found = _uuids([{"name": "Observable", "inverted": True,
                         "values": [["signature_id", SIGNATURE_UUID]]}])
        assert {tagged.uuid, plain.uuid}.issubset(found)

    def test_an_impossible_value_matches_nothing_rather_than_raising(self, corpus):
        """A saved filter or a pasted link can carry anything; a 500 would lock the analyst
        out of a page they cannot leave without clearing cookies."""
        assert _uuids([{"name": "Observable", "inverted": False,
                        "values": [["ipv4", "not-an-ip"]]}]) == set()


class TestOtherFilters:
    def test_tag(self, corpus):
        _, tagged, _ = corpus
        assert _uuids([{"name": "Tag", "inverted": False, "values": ["credential-harvest"]}]) == {tagged.uuid}

    def test_inverted_tag_keeps_untagged_alerts(self, corpus):
        _, tagged, plain = corpus
        found = _uuids([{"name": "Tag", "inverted": True, "values": ["credential-harvest"]}])
        assert plain.uuid in found and tagged.uuid not in found

    def test_queue(self, corpus):
        signed, _, _ = corpus
        assert _uuids([{"name": "Queue", "inverted": False, "values": ["external"]}]) == {signed.uuid}

    def test_date_range_resolves_in_the_timezone_it_is_given(self, corpus):
        """No current_user here: the caller supplies the timezone."""
        signed, tagged, _ = corpus
        window = [{"name": "Alert Date", "inverted": False,
                   "values": ["01-15-2026 00:00 - 02-15-2026 00:00"]}]
        assert tagged.uuid in _uuids(window) and signed.uuid not in _uuids(window)

    def test_create_filter_needs_no_request_context(self):
        assert create_filter("Alert Date", False, tz=pytz.utc) is not None
        assert create_filter("Observable", True) is not None


class TestHelpers:
    def test_count_alerts_counts_alerts_not_joined_rows(self, corpus):
        """The Observable join fans out; counting rows would double-count the alert carrying
        two observables."""
        signed, _, _ = corpus
        filters = [{"name": "Observable", "inverted": False,
                    "values": [["signature_id", SIGNATURE_UUID], ["ipv4", "10.20.30.40"]]}]
        assert count_alerts(filters, entity=Alert, tz=pytz.utc, locations=None) == 1
        assert _uuids(filters) == {signed.uuid}

    def test_filter_alert_uuids_preserves_order_and_drops_the_rest(self, corpus):
        signed, tagged, plain = corpus
        given = [plain.uuid, signed.uuid, tagged.uuid]
        kept = filter_alert_uuids(
            [{"name": "Observable", "inverted": True, "values": [["ipv4", "10.20.30.40"]]}],
            given, entity=Alert, tz=pytz.utc, locations=None)
        assert kept == [plain.uuid, tagged.uuid]

    def test_filter_alert_uuids_with_nothing_given(self):
        assert filter_alert_uuids([], [], entity=Alert, tz=pytz.utc, locations=None) == []
