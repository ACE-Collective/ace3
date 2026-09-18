"""The filter-only listing path: filters, no query, no ranking.

`POST /api/v2/search/alerts {"filters": {"observables": [...]}}` lands here. It answers "every
alert carrying this observable", which is a listing rather than a search -- so `total` is a real
SQL count, the page is a LIMIT/OFFSET rather than a slice of a capped fused list, and no result
carries a tier.
"""

import hashlib
from datetime import datetime

import pytest

from saq.database.model import Alert, Observable, ObservableMapping
from saq.database.pool import get_db
from saq.search.query import filter_listing, search_alerts
from saq.search.types import SearchFilters, SearchRequest
from tests.saq.helpers import insert_alert

pytestmark = pytest.mark.integration

SIGNATURE_UUID = "6f3a1b2c-1111-2222-3333-444455556666"
OTHER_SIGNATURE_UUID = "1a2b3c4d-9999-8888-7777-666655554444"


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


def _signature_filters(signature_uuid=SIGNATURE_UUID, **kwargs) -> SearchFilters:
    return SearchFilters(
        filter_list=({"name": "Observable", "inverted": False,
                      "values": [["signature_id", signature_uuid]]},),
        **kwargs)


@pytest.fixture
def corpus():
    """Three alerts carrying the signature, newest last, plus one that does not."""
    db = get_db()
    alerts = [insert_alert() for _ in range(3)]
    for index, alert in enumerate(alerts):
        db.execute(Alert.__table__.update().where(Alert.id == alert.id).values(
            insert_date=datetime(2026, 1, index + 1), queue="external" if index == 0 else "default"))
    db.commit()

    for alert in alerts:
        _attach(alert, "signature_id", SIGNATURE_UUID)

    unrelated = insert_alert()
    _attach(unrelated, "signature_id", OTHER_SIGNATURE_UUID)
    return alerts, unrelated


class TestFilterListing:
    def test_newest_first(self, corpus):
        alerts, unrelated = corpus
        response = filter_listing(_signature_filters(), limit=10, offset=0)
        assert response.alert_uuids == [alerts[2].uuid, alerts[1].uuid, alerts[0].uuid]
        assert unrelated.uuid not in response.alert_uuids

    def test_no_tier_and_no_hits(self, corpus):
        response = filter_listing(_signature_filters(), limit=10, offset=0)
        assert all(result.tier is None and result.hits == [] for result in response.results)
        assert response.lanes_used == frozenset()

    def test_total_is_the_full_count_not_the_page(self, corpus):
        response = filter_listing(_signature_filters(), limit=1, offset=0)
        assert response.total == 3 and len(response.results) == 1
        assert response.has_more()

    def test_pagination(self, corpus):
        alerts, _ = corpus
        page2 = filter_listing(_signature_filters(), limit=2, offset=2)
        assert page2.alert_uuids == [alerts[0].uuid]
        assert page2.results[0].rank == 3

    def test_scalar_filters_narrow_it_too(self, corpus):
        alerts, _ = corpus
        response = filter_listing(_signature_filters(queues=("external",)), limit=10, offset=0)
        assert response.alert_uuids == [alerts[0].uuid]

    def test_node_scoping(self, corpus):
        assert filter_listing(_signature_filters(locations=("nowhere",)), limit=10, offset=0).total == 0

    def test_post_filter_applies(self, corpus):
        alerts, _ = corpus
        response = filter_listing(
            _signature_filters(), limit=10, offset=0,
            post_filter=lambda uuids: [u for u in uuids if u != alerts[2].uuid])
        assert response.alert_uuids == [alerts[1].uuid, alerts[0].uuid]

    def test_no_match(self, corpus):
        response = filter_listing(
            SearchFilters(filter_list=({"name": "Observable", "inverted": False,
                                        "values": [["signature_id", "00000000-0000-0000-0000-000000000000"]]},)),
            limit=10, offset=0)
        assert response.total == 0 and response.results == []


class TestSearchAlertsRoutesToTheListing:
    def test_filters_with_no_query(self, corpus):
        alerts, _ = corpus
        response = search_alerts(SearchRequest(query="", filters=_signature_filters(), limit=10))
        assert response.alert_uuids == [alerts[2].uuid, alerts[1].uuid, alerts[0].uuid]
        assert all(result.tier is None for result in response.results)

    def test_a_typed_filter_term_with_no_free_text(self, corpus):
        """`-signature_id:<uuid>` is a filter, not a lookup, so this lists as well."""
        alerts, unrelated = corpus
        response = search_alerts(SearchRequest(query=f"-signature_id:{SIGNATURE_UUID}", limit=50))
        assert unrelated.uuid in response.alert_uuids
        assert not {alert.uuid for alert in alerts} & set(response.alert_uuids)

    def test_an_exact_term_is_a_search_not_a_listing(self, corpus):
        """The same observable written as a positive term goes through the lexical lane, which
        does report evidence."""
        alerts, _ = corpus
        response = search_alerts(SearchRequest(query=f"signature_id:{SIGNATURE_UUID}", limit=10))
        assert set(response.alert_uuids) == {alert.uuid for alert in alerts}
        assert all(result.tier == "exact" for result in response.results)
