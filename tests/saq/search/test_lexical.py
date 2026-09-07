import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from saq.database.model import Alert, Observable, ObservableMapping, Tag, TagMapping
from saq.database.pool import get_db
from saq.search.lexical import lexical_search, parse_query
from saq.search.types import KIND_OBSERVABLE, KIND_TAG, KIND_UUID, SearchFilters
from tests.saq.helpers import insert_alert

pytestmark = pytest.mark.integration

SHA256_HEX = "ab" * 32


def _observable(otype: str, value: str, sha256: bytes | None = None) -> Observable:
    return Observable(type=otype, value=value.encode(), sha256=sha256 or hashlib.sha256(value.encode()).digest())


def _attach(alert: Alert, observable: Observable) -> None:
    db = get_db()
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


@pytest.fixture
def corpus():
    db = get_db()
    older = insert_alert()
    newer = insert_alert()
    other = insert_alert()
    db.execute(Alert.__table__.update().where(Alert.id == older.id).values(insert_date=datetime(2026, 1, 1), alert_type="phish", disposition="DELIVERY"))
    db.execute(Alert.__table__.update().where(Alert.id == newer.id).values(insert_date=datetime(2026, 2, 1), alert_type="phish", disposition="OPEN"))
    db.execute(Alert.__table__.update().where(Alert.id == other.id).values(insert_date=datetime(2026, 3, 1), alert_type="hunt"))
    db.commit()

    shared_ip = _observable("ipv4", "10.20.30.40")
    _attach(older, shared_ip)
    db.add(ObservableMapping(observable_id=shared_ip.id, alert_id=newer.id))
    db.commit()
    _attach(older, _observable("email_address", "Bob@Example.com"))
    _attach(newer, _observable("file", SHA256_HEX, sha256=bytes.fromhex(SHA256_HEX)))
    _attach(other, _observable("ipv4", "203.0.113.7"))
    _tag(other, "credential-harvest")
    return older, newer, other


class TestParseQuery:
    def test_extracts_identifiers_and_tokens(self):
        candidates = parse_query("look for Bob@Example.com and 10.20.30.40 tagged credential-harvest")
        assert "Bob@Example.com" in candidates.values and "bob@example.com" in candidates.values
        assert "10.20.30.40" in candidates.values
        assert "credential-harvest" in candidates.values
        assert "to" not in parse_query("go to 10.20.30.40").values  # too short

    def test_hashes_and_uuids(self):
        candidates = parse_query(f"{SHA256_HEX} 2f1e4d3c-1111-2222-3333-444455556666 2f1e4d3c-11")
        assert candidates.hashes == (SHA256_HEX,)
        assert candidates.uuids == ("2f1e4d3c-1111-2222-3333-444455556666",)
        assert candidates.uuid_prefixes == ("2f1e4d3c-11",)

    def test_blank(self):
        assert parse_query("   ").is_empty()


class TestLexicalSearch:
    def test_exact_observable_value_newest_first(self, corpus):
        older, newer, _ = corpus
        results = lexical_search(parse_query("10.20.30.40"), SearchFilters(), limit=10)
        assert [u for u, _ in results] == [newer.uuid, older.uuid]
        hits = dict(results)[newer.uuid]
        assert hits[0].kind == KIND_OBSERVABLE and hits[0].text == "10.20.30.40" and hits[0].title == "ipv4"

    def test_value_match_is_byte_exact_but_casefolded_variant_is_tried(self, corpus):
        older, _, _ = corpus
        # stored as Bob@Example.com; the raw token matches, the lowercased one does not (and that is fine)
        assert [u for u, _ in lexical_search(parse_query("Bob@Example.com"), SearchFilters(), limit=10)] == [older.uuid]
        assert lexical_search(parse_query("bob@example.com"), SearchFilters(), limit=10) == []

    def test_file_hash_matches_sha256_column(self, corpus):
        _, newer, _ = corpus
        results = lexical_search(parse_query(SHA256_HEX.upper()), SearchFilters(), limit=10)
        assert [u for u, _ in results] == [newer.uuid]

    def test_tag(self, corpus):
        _, _, other = corpus
        results = lexical_search(parse_query("Credential-Harvest"), SearchFilters(), limit=10)
        assert [u for u, _ in results] == [other.uuid]
        assert dict(results)[other.uuid][0].kind == KIND_TAG

    def test_uuid_and_prefix(self, corpus):
        older, _, _ = corpus
        assert [u for u, _ in lexical_search(parse_query(older.uuid), SearchFilters(), limit=10)] == [older.uuid]
        results = lexical_search(parse_query(older.uuid[:13]), SearchFilters(), limit=10)
        assert older.uuid in [u for u, _ in results]
        assert dict(results)[older.uuid][0].kind == KIND_UUID

    def test_filters_apply(self, corpus):
        older, newer, _ = corpus
        candidates = parse_query("10.20.30.40")
        assert [u for u, _ in lexical_search(candidates, SearchFilters(dispositions=("OPEN",)), limit=10)] == [newer.uuid]
        assert [u for u, _ in lexical_search(candidates, SearchFilters(dispositions=("OPEN",), dispositions_inverted=True), limit=10)] == [older.uuid]
        window = ((datetime(2026, 1, 15, tzinfo=timezone.utc), datetime(2026, 2, 15, tzinfo=timezone.utc)),)
        assert [u for u, _ in lexical_search(candidates, SearchFilters(insert_date_ranges=window), limit=10)] == [newer.uuid]
        assert [u for u, _ in lexical_search(candidates, SearchFilters(alert_types=("hunt",)), limit=10)] == []
        assert [u for u, _ in lexical_search(candidates, SearchFilters(locations=("nowhere",)), limit=10)] == []
        assert [u for u, _ in lexical_search(candidates, SearchFilters(exclude_alert_uuids=(newer.uuid,)), limit=10)] == [older.uuid]

    def test_limit(self, corpus):
        assert len(lexical_search(parse_query("10.20.30.40"), SearchFilters(), limit=1)) == 1

    def test_no_candidates(self):
        assert lexical_search(parse_query(""), SearchFilters(), limit=10) == []
