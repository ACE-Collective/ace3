from datetime import datetime, timezone
from unittest.mock import Mock

import pytest
from qdrant_client import models

from saq.configuration.config import get_config
from saq.search import index, query
from saq.search.query import SemanticLane
from saq.search.syntax import parse_search_query
from saq.search.types import (
    LANE_LEXICAL,
    LANE_SEMANTIC,
    TIER_EXACT,
    TIER_GOOD,
    TIER_STRONG,
    TIER_WEAK,
    AlertSearchResult,
    SearchFilters,
    SearchHit,
    SearchRequest,
    SearchResponse,
)

pytestmark = pytest.mark.unit

# a query that exercises both lanes: one exact field term plus free text for the semantic lanes
EXACT_AND_TEXT = "ipv4:1.2.3.4 docusign"


def _hit(lane, text="t", score=0.5):
    return SearchHit(lane=lane, kind="alert", key=f"k:{text}", title=None, text=text, score=score)


class TestPayloadFilter:
    def test_empty(self):
        assert query.build_payload_filter(SearchFilters()) is None

    def test_keyword_fields(self):
        f = query.build_payload_filter(SearchFilters(alert_types=("phish",), dispositions=("OPEN", "DELIVERY"), queues=("q",), tags=("bad",)))
        by_key = {c.key: c for c in f.must}
        assert by_key[index.FIELD_ALERT_TYPE].match.any == ["phish"]
        assert by_key[index.FIELD_DISPOSITION].match.any == ["OPEN", "DELIVERY"]
        assert by_key[index.FIELD_QUEUE].match.any == ["q"]
        assert by_key[index.FIELD_TAGS].match.any == ["bad"]
        assert f.must_not is None

    def test_inverted_goes_to_must_not(self):
        f = query.build_payload_filter(SearchFilters(dispositions=("IGNORE",), dispositions_inverted=True))
        assert f.must is None
        assert f.must_not[0].key == index.FIELD_DISPOSITION

    def test_date_ranges_are_ored(self):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = datetime(2026, 1, 2, tzinfo=timezone.utc)
        f = query.build_payload_filter(SearchFilters(insert_date_ranges=((start, end), (start, end))))
        nested = f.must[0]
        assert isinstance(nested, models.Filter)
        assert len(nested.should) == 2
        assert nested.should[0].range.gte == start and nested.should[0].range.lte == end

    def test_locations_and_exclusions(self):
        f = query.build_payload_filter(SearchFilters(locations=("n1",), exclude_alert_uuids=("a",)), exclude_alert_uuids=["b"])
        assert f.must[0].key == index.FIELD_LOCATION
        assert f.must_not[0].match.any == ["a", "b"]


class TestFuse:
    def test_weighted_rrf(self):
        fused = query.fuse({LANE_LEXICAL: ["a", "b"], LANE_SEMANTIC: ["b", "c"]}, {LANE_LEXICAL: 2.0, LANE_SEMANTIC: 1.0}, k=60)
        assert [u for u, _ in fused] == ["b", "a", "c"]
        assert dict(fused)["b"] == pytest.approx(2 / 62 + 1 / 61)

    def test_exact_first_keeps_lexical_order_then_fused(self):
        fused = [("b", 0.9), ("a", 0.8), ("d", 0.5), ("c", 0.4)]
        assert query.exact_first(fused, ["a", "b"]) == [("a", 0.8), ("b", 0.9), ("d", 0.5), ("c", 0.4)]
        assert query.exact_first(fused, []) == fused

    def test_consensus_beats_single_lane_at_equal_weight(self):
        fused = query.fuse({"x": ["a", "b"], "y": ["b", "a"]}, {"x": 1.0, "y": 1.0}, k=60)
        assert fused[0][1] == pytest.approx(fused[1][1])


class TestTiers:
    def _result(self, lanes, dense=None, sparse=None):
        return AlertSearchResult(alert_uuid="a", rank=1, fused_score=1.0, tier="", lanes=frozenset(lanes), dense_score=dense, sparse_score=sparse)

    def test_tiers_come_from_evidence_not_position(self, monkeypatch):
        monkeypatch.setattr(get_config().search, "score_threshold", 0.3)
        monkeypatch.setattr(get_config().search, "strong_threshold", 0.55)
        assert query.assign_tier(self._result({LANE_LEXICAL}, dense=0.1)) == TIER_EXACT
        assert query.assign_tier(self._result({LANE_SEMANTIC}, dense=0.6)) == TIER_STRONG
        assert query.assign_tier(self._result({LANE_SEMANTIC}, dense=0.35, sparse=1.2)) == TIER_STRONG
        assert query.assign_tier(self._result({LANE_SEMANTIC}, dense=0.35)) == TIER_GOOD
        assert query.assign_tier(self._result({LANE_SEMANTIC}, sparse=0.7)) == TIER_WEAK
        # a lone result is not "strong" just because it is alone
        assert query.assign_tier(self._result({LANE_SEMANTIC}, dense=0.31)) == TIER_GOOD


class TestSearchAlerts:
    @pytest.fixture
    def lanes(self, monkeypatch):
        dense = [("b", [_hit(LANE_SEMANTIC, "sem b", 0.7)]), ("c", [_hit(LANE_SEMANTIC, "sem c", 0.6)]), ("d", [_hit(LANE_SEMANTIC, "sem d", 0.5)])]
        semantic = SemanticLane(dense=dense, sparse=[("b", [_hit(LANE_SEMANTIC, "sem b", 0.9)])], dense_scores={"b": 0.7, "c": 0.6, "d": 0.5}, sparse_scores={"b": 0.9})
        lexical = [("a", [_hit(LANE_LEXICAL, "ipv4 1.2.3.4", 1.0)]), ("b", [_hit(LANE_LEXICAL, "tag foo", 1.0)])]
        monkeypatch.setattr(query, "semantic_search", lambda *args, **kwargs: semantic)
        monkeypatch.setattr(query, "lexical_search", lambda *args, **kwargs: lexical)

    def test_ranking_happens_before_pagination(self, lanes):
        page1 = query.search_alerts(SearchRequest(query=EXACT_AND_TEXT, limit=2, offset=0))
        page2 = query.search_alerts(SearchRequest(query=EXACT_AND_TEXT, limit=2, offset=2))
        assert page1.total == page2.total == 4
        assert page1.alert_uuids == ["a", "b"]
        assert page2.alert_uuids == ["c", "d"]
        assert page1.results[0].tier == TIER_EXACT
        assert page1.results[0].rank == 1 and page2.results[0].rank == 3
        assert page1.has_more() and not page2.has_more()

    def test_hits_merge_exact_first(self, lanes):
        response = query.search_alerts(SearchRequest(query=EXACT_AND_TEXT, limit=10))
        b = next(r for r in response.results if r.alert_uuid == "b")
        # the exact hit first, then the ONE semantic chunk (reached by both qdrant lanes) at its best score
        assert [h.lane for h in b.hits] == [LANE_LEXICAL, LANE_SEMANTIC]
        assert b.hits[1].score == 0.9
        assert b.lanes == {LANE_LEXICAL, LANE_SEMANTIC}
        assert b.dense_score == 0.7 and b.sparse_score == 0.9
        c = next(r for r in response.results if r.alert_uuid == "c")
        assert c.tier == TIER_STRONG and c.dense_score == 0.6

    def test_post_filter_drives_total(self, lanes):
        response = query.search_alerts(SearchRequest(query=EXACT_AND_TEXT, limit=10), post_filter=lambda uuids: [u for u in uuids if u != "a"])
        assert response.total == 3
        assert response.alert_uuids == ["b", "c", "d"]
        assert "post_filter" in response.timings_ms

    def test_lane_selection(self, lanes):
        response = query.search_alerts(SearchRequest(query=EXACT_AND_TEXT, lanes=frozenset({LANE_LEXICAL})))
        assert response.lanes_used == {LANE_LEXICAL}
        assert response.alert_uuids == ["a", "b"]

    def test_include_hits_false(self, lanes):
        response = query.search_alerts(SearchRequest(query=EXACT_AND_TEXT, include_hits=False))
        assert all(r.hits == [] for r in response.results)

    def test_blank_query(self, lanes):
        assert query.search_alerts(SearchRequest(query="   ")).total == 0

    def test_prose_never_reaches_the_exact_lane(self, lanes, monkeypatch):
        """Free text does not run an exact lookup. `lexical_search` is stubbed to return
        matches, so if the lane ran at all they would show up."""
        called = []
        monkeypatch.setattr(query, "lexical_search", lambda *a, **k: called.append(1) or [])
        response = query.search_alerts(SearchRequest(query="docusign phish invoice"))
        assert called == []
        assert all(r.tier != TIER_EXACT for r in response.results)

    def test_semantic_lane_is_skipped_without_free_text(self, lanes, monkeypatch):
        """encode_query("") is a real vector with a nearest neighbour, so `tag:phish` alone
        must not run the semantic lanes at all."""
        called = []
        monkeypatch.setattr(query, "semantic_search", lambda *a, **k: called.append(1) or SemanticLane())
        response = query.search_alerts(SearchRequest(query="tag:phish"))
        assert called == []
        assert response.lanes_used == {LANE_LEXICAL}

    def test_query_errors_are_reported_and_nothing_is_searched(self, lanes):
        response = query.search_alerts(SearchRequest(query="alert_date:-7dd"))
        assert response.total == 0 and response.results == []
        assert response.errors and "time window" in response.errors[0]

    def test_lane_failure_is_contained(self, monkeypatch):
        monkeypatch.setattr(query, "lexical_search", lambda *a, **k: [("a", [_hit(LANE_LEXICAL)])])

        def boom(*args, **kwargs):
            raise RuntimeError("qdrant down")

        monkeypatch.setattr(query, "semantic_search", boom)
        response = query.search_alerts(SearchRequest(query=EXACT_AND_TEXT))
        assert response.alert_uuids == ["a"]

    def test_max_results_cap(self, monkeypatch):
        monkeypatch.setattr(get_config().search, "max_results", 2)
        monkeypatch.setattr(query, "semantic_search", lambda *a, **k: SemanticLane(dense=[(str(i), []) for i in range(5)]))
        monkeypatch.setattr(query, "lexical_search", lambda *a, **k: [])
        assert query.search_alerts(SearchRequest(query="some free text")).total == 2


class TestFilterListing:
    """A request with filters and no query is a listing: newest first, no ranking, no tier."""

    @pytest.fixture
    def listing(self, monkeypatch):
        captured = {}

        def fake_listing(filters, *, limit, offset, post_filter=None, timings=None):
            captured["filters"] = filters
            captured["limit"] = limit
            captured["offset"] = offset
            return SearchResponse(query="", total=3, offset=offset, limit=limit,
                                  results=[AlertSearchResult(alert_uuid="a", rank=1, fused_score=0.0, tier=None)])

        monkeypatch.setattr(query, "filter_listing", fake_listing)
        return captured

    def test_no_query_with_filters_lists(self, listing):
        filters = SearchFilters(filter_list=({"name": "Observable", "inverted": False, "values": [["signature_id", "abc"]]},))
        response = query.search_alerts(SearchRequest(query="", filters=filters, limit=25, offset=50))
        assert response.total == 3 and response.results[0].tier is None
        assert listing["limit"] == 25 and listing["offset"] == 50
        assert listing["filters"].filter_list == filters.filter_list

    def test_no_query_no_filters_is_still_empty(self, listing):
        assert query.search_alerts(SearchRequest(query="")).total == 0
        assert "filters" not in listing

    def test_a_typed_filter_term_alone_also_lists(self, listing):
        query.search_alerts(SearchRequest(query="queue:default"))
        assert listing["filters"].queues == ("default",)

    def test_a_typed_sql_only_term_alone_also_lists(self, listing):
        query.search_alerts(SearchRequest(query="owner:jdoe"))
        assert listing["filters"].filter_list == ({"name": "Owner", "inverted": False, "values": ["jdoe"]},)


class TestMergeParsedFilters:
    def _merge(self, text, filters=None):
        return query.merge_parsed_filters(filters or SearchFilters(), parse_search_query(text))

    def test_a_payload_expressible_term_becomes_a_pre_filter(self):
        """Not just an optimization: the semantic lane retrieves semantic_limit alerts, so a
        post-filtered `queue:default` would return a fraction of what it should."""
        merged = self._merge("queue:default disposition:DELIVERY,IGNORE alert_type:phish")
        assert merged.queues == ("default",) and merged.queues_inverted is False
        assert merged.dispositions == ("DELIVERY", "IGNORE")
        assert merged.alert_types == ("phish",)
        assert merged.filter_list == ()

    def test_inversion_is_carried_onto_the_pre_filter(self):
        merged = self._merge("-queue:default -tag:whitelisted")
        assert merged.queues == ("default",) and merged.queues_inverted is True
        assert merged.tags == ("whitelisted",) and merged.tags_inverted is True

    def test_a_relative_date_becomes_a_range(self):
        merged = self._merge("alert_date:-7d")
        assert len(merged.insert_date_ranges) == 1
        start, end = merged.insert_date_ranges[0]
        assert start < end

    def test_a_term_with_no_payload_field_goes_to_the_filter_list(self):
        merged = self._merge("owner:jdoe -ipv4:1.2.3.4 tag:phish*")
        assert {entry["name"] for entry in merged.filter_list} == {"Owner", "Observable", "Tag"}

    def test_a_field_the_caller_already_set_is_anded_in_sql_instead(self):
        """SearchFilters holds one value set per field; two different ones cannot both be
        pre-filters, and silently picking one would widen the search."""
        merged = self._merge("queue:external", SearchFilters(queues=("default",)))
        assert merged.queues == ("default",)
        assert merged.filter_list == ({"name": "Queue", "inverted": False, "values": ["external"]},)

    def test_existing_filter_list_entries_are_kept(self):
        filters = SearchFilters(filter_list=({"name": "Owner", "inverted": False, "values": ["me"]},))
        merged = self._merge("description:invoice", filters)
        assert [entry["name"] for entry in merged.filter_list] == ["Owner", "Description"]

    def test_nothing_parsed_leaves_the_filters_alone(self):
        filters = SearchFilters(queues=("default",))
        assert query.merge_parsed_filters(filters, parse_search_query("free text")) is filters


class TestQdrantCalls:
    def test_semantic_search_runs_floored_dense_and_sparse_grouped_queries(self, mock_qdrant, mock_model, monkeypatch):
        monkeypatch.setattr(get_config().search, "score_threshold", 0.3)
        group = Mock(id="alert-1", hits=[Mock(score=0.9, payload={index.FIELD_KIND: "alert", index.FIELD_KEY: "header", index.FIELD_CHUNK: 0, index.FIELD_TEXT: "hello", index.FIELD_TITLE: "t"})])
        mock_qdrant.query_points_groups.return_value = Mock(groups=[group])

        lane = query.semantic_search("hello world", SearchFilters(alert_types=("phish",)), limit=10, group_size=3, model=mock_model)

        assert lane.dense == [("alert-1", [SearchHit(lane=LANE_SEMANTIC, kind="alert", key="alert:header:0", title="t", text="hello", score=0.9)])]
        assert lane.dense_scores == {"alert-1": 0.9} and lane.sparse_scores == {"alert-1": 0.9}
        calls = mock_qdrant.query_points_groups.call_args_list
        assert [c.kwargs["using"] for c in calls] == [index.DENSE, index.SPARSE]
        dense, sparse = calls[0].kwargs, calls[1].kwargs
        assert dense["score_threshold"] == 0.3 and sparse["score_threshold"] is None
        assert isinstance(sparse["query"], models.SparseVector)
        for kwargs in (dense, sparse):
            assert kwargs["group_by"] == index.FIELD_ROOT_UUID
            assert kwargs["limit"] == 10 and kwargs["group_size"] == 3
            assert kwargs["query_filter"] is not None

    def test_sparse_query_is_skipped_when_only_stopwords(self, mock_qdrant, mock_model):
        mock_qdrant.query_points_groups.return_value = Mock(groups=[])
        query.semantic_search("the and of", SearchFilters(), limit=5, group_size=1, model=mock_model)
        assert [c.kwargs["using"] for c in mock_qdrant.query_points_groups.call_args_list] == [index.DENSE]

    def test_semantic_search_without_collection(self, mock_qdrant, mock_model):
        mock_qdrant.collection_exists.return_value = False
        lane = query.semantic_search("x", SearchFilters(), limit=5, group_size=1, model=mock_model)
        assert lane.dense == [] and lane.sparse == []
        mock_qdrant.query_points_groups.assert_not_called()

    def test_similar_search_recommends_from_own_points(self, mock_qdrant, monkeypatch):
        monkeypatch.setattr(get_config().search, "score_threshold", 0.3)
        mock_qdrant.scroll.return_value = ([Mock(id="p1"), Mock(id="p2")], None)
        mock_qdrant.query_points_groups.return_value = Mock(groups=[])
        query.similar_search("alert-1", SearchFilters(), limit=5, group_size=2)

        kwargs = mock_qdrant.query_points_groups.call_args.kwargs
        assert isinstance(kwargs["query"], models.RecommendQuery)
        assert kwargs["query"].recommend.positive == ["p1", "p2"]
        assert kwargs["using"] == index.DENSE
        assert kwargs["score_threshold"] == 0.3
        assert kwargs["query_filter"].must_not[0].match.any == ["alert-1"]

    def test_similar_search_unindexed_alert(self, mock_qdrant):
        assert query.similar_search("alert-1", SearchFilters(), limit=5, group_size=2).dense == []
        response = query.similar_alerts("alert-1")
        assert response.total == 0 and response.query == "similar:alert-1"


class TestTestAlerts:
    """Test-run alerts (svs.queue) are left out of a search that says nothing about queues, and
    counted (docs/SVS_RUNS.md, RPT-7)."""

    @pytest.fixture
    def calls(self, monkeypatch):
        """Records the filters each lane run sees; the test-queue run finds one alert."""
        seen = []

        def semantic(text, filters, **kwargs):
            seen.append(filters)
            if filters.queues == ("svs",) and not filters.queues_inverted:
                return SemanticLane(dense=[("t", [])], dense_scores={"t": 0.5})
            return SemanticLane(dense=[("a", []), ("b", [])], dense_scores={"a": 0.6, "b": 0.5})

        monkeypatch.setattr(query, "semantic_search", semantic)
        monkeypatch.setattr(query, "lexical_search", lambda *a, **k: [])
        monkeypatch.setattr(query, "_any_test_alerts", lambda: True)
        return seen

    def test_leave_out_test_alerts(self):
        filters, test_filters = query.leave_out_test_alerts(SearchFilters(dispositions=("OPEN",)), include=False)
        assert (filters.queues, filters.queues_inverted) == (("svs",), True)
        assert (test_filters.queues, test_filters.queues_inverted) == (("svs",), False)
        # everything else is the request's own
        assert filters.dispositions == test_filters.dispositions == ("OPEN",)

    @pytest.mark.parametrize("filters", [
        SearchFilters(queues=("default",)),
        SearchFilters(queues=("default",), queues_inverted=True),
        SearchFilters(filter_list=({"name": "Queue", "inverted": True, "values": ["external"]},)),
    ])
    def test_a_request_that_names_a_queue_gets_what_it_asked_for(self, filters):
        assert query.leave_out_test_alerts(filters, include=False) == (filters, None)

    def test_asking_for_test_alerts(self):
        filters = SearchFilters()
        assert query.leave_out_test_alerts(filters, include=True) == (filters, None)

    def test_the_configured_queue(self, monkeypatch):
        monkeypatch.setattr(get_config().svs, "queue", "atomic")
        filters, _ = query.leave_out_test_alerts(SearchFilters(), include=False)
        assert filters.queues == ("atomic",)

    def test_search_leaves_them_out_and_counts_them(self, calls):
        response = query.search_alerts(SearchRequest(query="mimikatz"))
        assert response.alert_uuids == ["a", "b"]
        assert response.excluded_test_alerts == 1
        assert [(f.queues, f.queues_inverted) for f in calls] == [(("svs",), True), (("svs",), False)]
        assert "excluded_test_alerts" in response.timings_ms

    def test_no_counting_pass_while_no_test_alert_exists(self, calls, monkeypatch):
        monkeypatch.setattr(query, "_any_test_alerts", lambda: False)
        response = query.search_alerts(SearchRequest(query="mimikatz"))
        assert response.excluded_test_alerts == 0
        assert len(calls) == 1

    def test_a_typed_queue_term_brings_them_back(self, calls):
        response = query.search_alerts(SearchRequest(query="mimikatz queue:svs"))
        assert response.alert_uuids == ["t"]
        assert response.excluded_test_alerts is None
        assert len(calls) == 1

    def test_include_test_alerts(self, calls):
        response = query.search_alerts(SearchRequest(query="mimikatz", include_test_alerts=True))
        assert response.excluded_test_alerts is None
        assert calls[0].queues == ()

    def test_the_count_respects_the_post_filter(self, calls):
        """Node scoping applies to the count too: an alert this node can't show isn't counted."""
        response = query.search_alerts(SearchRequest(query="mimikatz"), post_filter=lambda uuids: [u for u in uuids if u != "t"])
        assert response.excluded_test_alerts == 0

    def test_a_listing_counts_them_too(self, monkeypatch):
        seen = []

        def fake_listing(filters, *, limit, offset, post_filter=None, timings=None):
            seen.append((filters.queues, filters.queues_inverted, limit))
            total = 4 if not filters.queues_inverted else 9
            return SearchResponse(query="", total=total, offset=offset, limit=limit)

        monkeypatch.setattr(query, "filter_listing", fake_listing)
        monkeypatch.setattr(query, "_any_test_alerts", lambda: True)
        response = query.search_alerts(SearchRequest(query="disposition:OPEN", limit=20))
        assert response.total == 9 and response.excluded_test_alerts == 4
        assert seen == [(("svs",), True, 20), (("svs",), False, 0)]

    def test_similar_alerts(self, monkeypatch):
        seen = []

        def similar(alert_uuid, filters, **kwargs):
            seen.append(filters)
            if not filters.queues_inverted:
                return SemanticLane(dense=[("t1", []), ("t2", [])])
            return SemanticLane(dense=[("a", [])])

        monkeypatch.setattr(query, "similar_search", similar)
        monkeypatch.setattr(query, "_any_test_alerts", lambda: True)
        response = query.similar_alerts("x")
        assert response.alert_uuids == ["a"] and response.excluded_test_alerts == 2

        seen.clear()
        response = query.similar_alerts("x", include_test_alerts=True)
        assert response.excluded_test_alerts is None and seen[0].queues == ()
