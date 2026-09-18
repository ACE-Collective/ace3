import hashlib
from datetime import datetime, timezone

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


def _search(query: str, filters: SearchFilters = SearchFilters(), limit: int = 10):
    return lexical_search(parse_query(query), filters, limit=limit)


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
    # stored the way the engine stores it: EmailAddressObservable lowercases its value, so
    # that is what the observables row and its sha256 hold
    _attach(older, _observable("email_address", "bob@example.com"))
    _attach(newer, _observable("file", SHA256_HEX, sha256=bytes.fromhex(SHA256_HEX)))
    _attach(other, _observable("ipv4", "203.0.113.7"))
    _tag(other, "credential-harvest")
    return older, newer, other


class TestOnlyFieldTermsReachTheLane:
    """Free text never produces an exact lookup, even when a word is also a tag or an indicator."""

    def test_a_word_that_is_also_a_tag_matches_nothing(self, corpus):
        assert _search("credential-harvest phishing campaign") == []

    def test_a_bare_indicator_matches_nothing(self, corpus):
        assert _search("10.20.30.40") == []
        assert _search(SHA256_HEX) == []

    def test_the_whole_phrase_is_not_a_candidate(self, corpus):
        assert _search("look for credential-harvest") == []

    def test_nothing_to_look_up(self):
        assert _search("") == []
        assert parse_query("docusign invoice").is_empty()


class TestLexicalSearch:
    def test_exact_observable_value_newest_first(self, corpus):
        older, newer, _ = corpus
        results = _search("ipv4:10.20.30.40")
        assert [u for u, _ in results] == [newer.uuid, older.uuid]
        hits = dict(results)[newer.uuid]
        assert hits[0].kind == KIND_OBSERVABLE and hits[0].text == "10.20.30.40" and hits[0].title == "ipv4"

    def test_explicit_observable_form(self, corpus):
        older, newer, _ = corpus
        assert [u for u, _ in _search("observable:ipv4:10.20.30.40")] == [newer.uuid, older.uuid]

    def test_the_type_has_to_match(self, corpus):
        """A value alone is not an identity: (type, sha256) is."""
        assert _search("fqdn:10.20.30.40") == []

    def test_value_is_normalized_by_the_observable_class(self, corpus):
        """Matching on (type, sha256) after resolve_observable_identity() means the query is
        normalized exactly as the engine normalized the observable."""
        older, _, _ = corpus
        assert [u for u, _ in _search("email_address:Bob@Example.com")] == [older.uuid]
        assert [u for u, _ in _search("email_address:bob@example.com")] == [older.uuid]

    def test_file_observable_matches_its_content_hash(self, corpus):
        _, newer, _ = corpus
        assert [u for u, _ in _search(f"file:{SHA256_HEX.upper()}")] == [newer.uuid]

    def test_tag(self, corpus):
        _, _, other = corpus
        results = _search("tag:Credential-Harvest")
        assert [u for u, _ in results] == [other.uuid]
        assert dict(results)[other.uuid][0].kind == KIND_TAG

    def test_uuid_and_prefix(self, corpus):
        older, _, _ = corpus
        assert [u for u, _ in _search(f"uuid:{older.uuid}")] == [older.uuid]
        results = _search(f"uuid:{older.uuid[:13]}")
        assert older.uuid in [u for u, _ in results]
        assert dict(results)[older.uuid][0].kind == KIND_UUID

    def test_several_terms_are_ored_into_one_result_set(self, corpus):
        older, newer, other = corpus
        found = {u for u, _ in _search("ipv4:10.20.30.40 tag:credential-harvest")}
        assert found == {older.uuid, newer.uuid, other.uuid}

    def test_comma_separated_values(self, corpus):
        older, newer, other = corpus
        found = {u for u, _ in _search("ipv4:10.20.30.40,203.0.113.7")}
        assert found == {older.uuid, newer.uuid, other.uuid}

    def test_filters_apply(self, corpus):
        older, newer, _ = corpus
        candidates = parse_query("ipv4:10.20.30.40")
        assert [u for u, _ in lexical_search(candidates, SearchFilters(dispositions=("OPEN",)), limit=10)] == [newer.uuid]
        assert [u for u, _ in lexical_search(candidates, SearchFilters(dispositions=("OPEN",), dispositions_inverted=True), limit=10)] == [older.uuid]
        window = ((datetime(2026, 1, 15, tzinfo=timezone.utc), datetime(2026, 2, 15, tzinfo=timezone.utc)),)
        assert [u for u, _ in lexical_search(candidates, SearchFilters(insert_date_ranges=window), limit=10)] == [newer.uuid]
        assert [u for u, _ in lexical_search(candidates, SearchFilters(alert_types=("hunt",)), limit=10)] == []
        assert [u for u, _ in lexical_search(candidates, SearchFilters(locations=("nowhere",)), limit=10)] == []
        assert [u for u, _ in lexical_search(candidates, SearchFilters(exclude_alert_uuids=(newer.uuid,)), limit=10)] == [older.uuid]

    def test_limit(self, corpus):
        assert len(_search("ipv4:10.20.30.40", limit=1)) == 1
