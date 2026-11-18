"""Tests for the aceapi_v2 observable-detection service."""

import hashlib
from datetime import datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from saq.constants import MAX_DETECTION_VALUE_LENGTH
from saq.database.model import Observable, ObservableComment, ObservableDetection, User
from saq.database.util.observable_detection import InvalidDetectionValue
from aceapi_v2.detection import service
from aceapi_v2.detection.schemas import DetectionStatus

pytestmark = pytest.mark.integration


def _sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf8", errors="ignore")).digest()


async def _make_detection(session: AsyncSession, otype: str, value: str, **kwargs) -> ObservableDetection:
    detection = ObservableDetection(
        type=otype, value=value, value_sha256=_sha256(value), **kwargs)
    session.add(detection)
    await session.flush()
    return detection


async def _make_observable(session: AsyncSession, otype: str, value: str, **kwargs) -> Observable:
    obs = Observable(type=otype, sha256=_sha256(value), value=value.encode("utf8"), **kwargs)
    session.add(obs)
    await session.flush()
    return obs


class TestListDetections:
    @pytest.mark.asyncio
    async def test_search_substring(self, session: AsyncSession):
        await _make_detection(session, "fqdn", "evil.example.com")
        await _make_detection(session, "fqdn", "good.example.org")

        results = await service.list_detections(session, search="example.com")
        values = [r.value for r in results]
        assert "evil.example.com" in values
        assert "good.example.org" not in values

    @pytest.mark.asyncio
    async def test_like_wildcards_in_search_are_literal(self, session: AsyncSession):
        await _make_detection(session, "pcttype", "pct100%.example.com")
        await _make_detection(session, "pcttype", "pct100percent.example.com")

        # unescaped, "100%." is a LIKE pattern and would match both; escaped it is the literal
        # five characters, which only the first value contains
        results = await service.list_detections(session, observable_type="pcttype", search="100%.")
        assert [r.value for r in results] == ["pct100%.example.com"]

    @pytest.mark.asyncio
    async def test_underscore_in_search_is_literal(self, session: AsyncSession):
        await _make_detection(session, "usctype", "a_b.example.com")
        await _make_detection(session, "usctype", "axb.example.com")

        results = await service.list_detections(session, observable_type="usctype", search="a_b")
        assert [r.value for r in results] == ["a_b.example.com"]

    @pytest.mark.asyncio
    async def test_asterisk_anchors_the_search(self, session: AsyncSession):
        """A term containing '*' is an explicit pattern, so an analyst can anchor a search."""
        await _make_detection(session, "fqdn", "bad.example.ru")
        await _make_detection(session, "fqdn", "ru.example.com")

        results = await service.list_detections(session, search="*.ru")
        assert [r.value for r in results] == ["bad.example.ru"]

    @pytest.mark.asyncio
    async def test_search_matches_long_values_in_full(self, session: AsyncSession):
        """The whole value is searchable -- there is no truncated sort-prefix column to miss."""
        value = "https://example.com/" + ("a" * (MAX_DETECTION_VALUE_LENGTH - 40)) + "/needle"
        await _make_detection(session, "url", value)

        results = await service.list_detections(session, search="needle")
        assert [r.value for r in results] == [value]

    @pytest.mark.asyncio
    async def test_created_and_modified_display_names(self, session: AsyncSession):
        creator = User(username="det_creator", email="c@e.com", display_name="Det Creator", password="pw")
        modifier = User(username="det_modifier", email="m@e.com", display_name="Det Modifier", password="pw")
        session.add_all([creator, modifier])
        await session.flush()
        await _make_detection(session, "ipv4", "10.9.9.9",
                              created_by=creator.id, modified_by=modifier.id)

        results = await service.list_detections(session, search="10.9.9.9")
        assert results[0].created_by == "Det Creator"
        assert results[0].modified_by == "Det Modifier"


class TestStatusFilter:
    """Expired detections are hidden by default, matching what the engine treats as active."""

    async def _make_set(self, session: AsyncSession) -> None:
        await _make_detection(session, "statustype", "never.example.com")
        await _make_detection(session, "statustype", "future.example.com", expires_on=datetime(2999, 1, 1))
        await _make_detection(session, "statustype", "past.example.com", expires_on=datetime(2000, 1, 1))

    @pytest.mark.asyncio
    async def test_default_excludes_expired(self, session: AsyncSession):
        await self._make_set(session)

        results = await service.list_detections(session, observable_type="statustype")
        assert [r.value for r in results] == ["future.example.com", "never.example.com"]
        assert not any(r.expired for r in results)
        assert await service.count_detections(session, observable_type="statustype") == 2

    @pytest.mark.asyncio
    async def test_expired_only(self, session: AsyncSession):
        await self._make_set(session)

        results = await service.list_detections(
            session, observable_type="statustype", status=DetectionStatus.EXPIRED)
        assert [r.value for r in results] == ["past.example.com"]
        assert results[0].expired
        assert await service.count_detections(
            session, observable_type="statustype", status=DetectionStatus.EXPIRED) == 1

    @pytest.mark.asyncio
    async def test_all(self, session: AsyncSession):
        await self._make_set(session)

        results = await service.list_detections(
            session, observable_type="statustype", status=DetectionStatus.ALL)
        assert {r.value: r.expired for r in results} == {
            "future.example.com": False,
            "never.example.com": False,
            "past.example.com": True,
        }

    @pytest.mark.asyncio
    async def test_page_total_follows_status(self, session: AsyncSession):
        await self._make_set(session)

        assert (await service.get_detection_page(session, observable_type="statustype")).total == 2
        page = await service.get_detection_page(
            session, observable_type="statustype", status=DetectionStatus.ALL)
        assert page.total == 3


class TestObservableContext:
    """The LEFT JOIN back to the observables index."""

    @pytest.mark.asyncio
    async def test_comments_and_fa_hits_for_a_seen_observable(self, session: AsyncSession):
        value = "commented.example.com"
        obs = await _make_observable(session, "fqdn", value, fa_hits=42)
        await _make_detection(session, "fqdn", value)

        user = User(username="det_commenter", email="dc@e.com", display_name="Det Commenter", password="pw")
        session.add(user)
        await session.flush()
        # added newest first, so the order is the dates' and not the rows'
        session.add_all([
            ObservableComment(observable_id=obs.id, user_id=user.id, comment="second",
                              insert_date=datetime(2024, 6, 1, 0, 0, 0),
                              edited_at=datetime(2024, 7, 1, 0, 0, 0)),
            ObservableComment(observable_id=obs.id, user_id=user.id, comment="first",
                              insert_date=datetime(2024, 1, 1, 0, 0, 0)),
        ])
        await session.flush()

        results = await service.list_detections(session, search=value)
        assert results[0].observable_id == obs.id
        assert results[0].fa_hits == 42
        # oldest-first
        assert [c.comment for c in results[0].comments] == ["first", "second"]
        assert results[0].comments[0].user_display_name == "Det Commenter"
        assert [c.edited_at for c in results[0].comments] == [None, datetime(2024, 7, 1, 0, 0, 0)]

    @pytest.mark.asyncio
    async def test_never_seen_observable_has_no_context(self, session: AsyncSession):
        """A detection added ahead of the first sighting renders without erroring."""
        await _make_detection(session, "fqdn", "never-seen.example.com")

        results = await service.list_detections(session, search="never-seen.example.com")
        assert results[0].observable_id is None
        assert results[0].fa_hits is None
        assert results[0].comments == []

    @pytest.mark.asyncio
    async def test_matching_hash_under_another_type_is_not_joined(self, session: AsyncSession):
        """The join is on (type, hash), so a shared value under a different type does not leak in."""
        value = "shared.example.com"
        await _make_observable(session, "url_domain", value, fa_hits=7)
        await _make_detection(session, "fqdn", value)

        results = await service.list_detections(session, search=value)
        assert results[0].observable_id is None
        assert results[0].fa_hits is None


class TestTypeFilterAndCount:
    @pytest.mark.asyncio
    async def test_filter_by_type(self, session: AsyncSession):
        await _make_detection(session, "ipv4", "20.0.0.1")
        await _make_detection(session, "fqdn", "typed.example.com")

        results = await service.list_detections(session, observable_type="fqdn")
        assert [r.type for r in results] == ["fqdn"]

    @pytest.mark.asyncio
    async def test_count_honours_filters(self, session: AsyncSession):
        await _make_detection(session, "ipv4", "21.0.0.1")
        await _make_detection(session, "ipv4", "21.0.0.2")

        assert await service.count_detections(session, search="21.0.0.") == 2
        assert await service.count_detections(session, search="21.0.0.1") == 1

    @pytest.mark.asyncio
    async def test_all_types_comes_from_the_registry(self):
        """The create form must offer types that have never been seen or detected on."""
        all_types = service.list_all_observable_types()
        assert "ipv4" in all_types
        assert all_types == sorted(all_types)


class TestPagination:
    @pytest.mark.asyncio
    async def test_pages_partition_the_result(self, session: AsyncSession):
        values = [f"page{i:02}.example.com" for i in range(26)]
        for value in values:
            await _make_detection(session, "pagetype", value)

        first = await service.get_detection_page(session, observable_type="pagetype", page=1, page_size=25)
        second = await service.get_detection_page(session, observable_type="pagetype", page=2, page_size=25)
        assert (first.total, first.total_pages) == (26, 2)
        assert (first.first_index, first.last_index, second.first_index, second.last_index) == (1, 25, 26, 26)
        assert [r.value for r in first.items + second.items] == values

    @pytest.mark.asyncio
    async def test_ordered_by_type_then_value_then_id(self, session: AsyncSession):
        # the type comes first: ord_b's value sorts before both of ord_a's
        await _make_detection(session, "ord_b", "aaa.example.com")
        await _make_detection(session, "ord_a", "ccc.example.com")
        await _make_detection(session, "ord_a", "bbb.example.com")

        rows = [r for r in await service.list_detections(session) if r.type.startswith("ord_")]
        assert [(r.type, r.value) for r in rows] == [
            ("ord_a", "bbb.example.com"),
            ("ord_a", "ccc.example.com"),
            ("ord_b", "aaa.example.com"),
        ]

    @pytest.mark.asyncio
    async def test_values_sharing_a_long_prefix_paginate_deterministically(self, session: AsyncSession):
        prefix = "https://collide.example.com/" + ("x" * 900)
        a = await _make_detection(session, "tie", prefix + "/aaa")
        b = await _make_detection(session, "tie", prefix + "/bbb")

        p1 = await service.get_detection_page(session, observable_type="tie", page=1, page_size=25)
        assert [i.id for i in p1.items] == [a.id, b.id]

    @pytest.mark.asyncio
    async def test_page_is_clamped_to_valid_range(self, session: AsyncSession):
        await _make_detection(session, "clamped", "c.example.com")

        assert (await service.get_detection_page(session, observable_type="clamped", page=999)).page == 1
        assert (await service.get_detection_page(session, observable_type="clamped", page=-5)).page == 1

    @pytest.mark.asyncio
    async def test_empty_result_has_one_page(self, session: AsyncSession):
        page = await service.get_detection_page(session, observable_type="does-not-exist")
        assert page.total == 0
        assert page.total_pages == 1
        assert page.first_index == 0
        assert page.has_next is False

    @pytest.mark.asyncio
    async def test_page_size_is_clamped_to_the_offered_choices(self):
        assert service.clamp_page_size(100000) == service.DEFAULT_PAGE_SIZE
        assert service.clamp_page_size(None) == service.DEFAULT_PAGE_SIZE
        assert service.clamp_page_size(200) == 200


class TestCreateDetection:
    @pytest.mark.asyncio
    async def test_create_normalizes_through_the_observable_class(self, session: AsyncSession):
        result = await service.create_detection(
            session, observable_type="ipv4_conversation", value=" 1.2.3.4_5.6.7.8 ",
            created_by_user_id=None)
        assert result.value == "1.2.3.4_5.6.7.8"

    @pytest.mark.asyncio
    async def test_create_rejects_an_overlong_value(self, session: AsyncSession):
        with pytest.raises(InvalidDetectionValue):
            await service.create_detection(
                session, observable_type="url",
                value="https://e.com/" + ("x" * MAX_DETECTION_VALUE_LENGTH),
                created_by_user_id=None)

    @pytest.mark.asyncio
    async def test_case_variants_are_distinct_detections_but_one_search_finds_both(self, session: AsyncSession):
        """Uniqueness is on the binary hash; search uses the case-insensitive collation."""
        await service.create_detection(
            session, observable_type="fqdn", value="Case.example.net", created_by_user_id=None)
        await service.create_detection(
            session, observable_type="fqdn", value="case.example.net", created_by_user_id=None)

        results = await service.list_detections(session, search="case.example.net")
        assert len(results) == 2


class TestSetExpiration:
    @pytest.mark.asyncio
    async def test_records_who_changed_it(self, session: AsyncSession):
        user = User(username="det_expirer", email="e@e.com", display_name="Det Expirer", password="pw")
        session.add(user)
        await session.flush()
        detection = await _make_detection(session, "ipv4", "4.4.4.5")

        result = await service.set_detection_expiration(
            session, detection.id, datetime(2030, 1, 1), user.id)
        assert result.modified_by == "Det Expirer"
