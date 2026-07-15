"""Tests for the aceapi_v2 observable-detection settings service."""

import hashlib

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from saq.database.model import Observable, ObservableComment, User
from aceapi_v2.detection import service

pytestmark = pytest.mark.integration


def _sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf8", errors="ignore")).digest()


async def _make_observable(session: AsyncSession, otype: str, value: str, **kwargs) -> Observable:
    obs = Observable(type=otype, sha256=_sha256(value), value=value.encode("utf8"), **kwargs)
    session.add(obs)
    await session.flush()
    return obs


class TestListDetectionObservables:
    @pytest.mark.asyncio
    async def test_filter_for_detection(self, session: AsyncSession):
        await _make_observable(session, "ipv4", "10.0.0.1", for_detection=True)
        await _make_observable(session, "ipv4", "10.0.0.2", for_detection=False)
        await session.flush()

        enabled = await service.list_detection_observables(session, for_detection=True)
        values = {o.value for o in enabled}
        assert "10.0.0.1" in values
        assert "10.0.0.2" not in values

    @pytest.mark.asyncio
    async def test_search(self, session: AsyncSession):
        await _make_observable(session, "fqdn", "evil.example.com", for_detection=True)
        await _make_observable(session, "fqdn", "good.example.org", for_detection=True)
        await session.flush()

        results = await service.list_detection_observables(session, search="evil")
        values = {o.value for o in results}
        assert "evil.example.com" in values
        assert "good.example.org" not in values

    @pytest.mark.asyncio
    @pytest.mark.parametrize("term", ["mixedcase", "MIXEDCASE", "MixedCase", "mIxEdCaSe"])
    async def test_search_is_case_insensitive(self, session: AsyncSession, term):
        """`value` is a BLOB, so an un-cast LIKE would compare bytes and miss on case."""
        await _make_observable(session, "fqdn", "MixedCase.example.com", for_detection=True)
        await session.flush()

        results = await service.list_detection_observables(session, search=term)
        assert "MixedCase.example.com" in {o.value for o in results}

    @pytest.mark.asyncio
    async def test_search_treats_like_wildcards_literally(self, session: AsyncSession):
        await _make_observable(session, "fqdn", "pct100percent.example.com", for_detection=True)
        await _make_observable(session, "fqdn", "pct100.example.com", for_detection=True)
        await session.flush()

        # '%' must not act as a SQL wildcard: "100%p" is a literal substring, matching neither row
        assert await service.count_detection_observables(session, search="100%p") == 0
        # and '_' must not match any single character
        assert await service.count_detection_observables(session, search="pct1_0") == 0
        # the literal text still matches
        assert await service.count_detection_observables(session, search="pct100p") == 1

    @pytest.mark.asyncio
    async def test_search_matches_beyond_the_value_sort_prefix(self, session: AsyncSession):
        """value_sort is only a prefix; search must still find substrings past its length."""
        prefix_len = Observable.__table__.c.value_sort.type.length
        value = "https://long.example.com/" + "x" * (prefix_len + 50) + "/needle_at_the_end"
        await _make_observable(session, "url", value, for_detection=True)
        await session.flush()

        results = await service.list_detection_observables(session, search="needle_at_the_end")
        assert value in {o.value for o in results}

    @pytest.mark.asyncio
    async def test_detection_modified_by_display_name(self, session: AsyncSession):
        user = User(username="det_enabler", email="det_enabler@e.com", display_name="Det Enabler", password="pw")
        session.add(user)
        await session.flush()
        await _make_observable(session, "ipv4", "10.9.9.9", for_detection=True, detection_modified_by=user.id)
        await session.flush()

        results = await service.list_detection_observables(session, search="10.9.9.9")
        assert results[0].detection_modified_by == "Det Enabler"


class TestComments:
    @pytest.mark.asyncio
    async def test_comments_returned_oldest_first_with_author(self, session: AsyncSession):
        """The detection row surfaces each observable's comments, oldest-first, with author name."""
        from datetime import datetime

        user = User(username="det_commenter", email="det_commenter@e.com", display_name="Commenter", password="pw")
        session.add(user)
        obs = await _make_observable(session, "fqdn", "commented.example.com", for_detection=True)
        await session.flush()

        # inserted newest-first so ordering can't accidentally pass on insertion order
        session.add(ObservableComment(
            user_id=user.id, observable_id=obs.id, comment="second",
            insert_date=datetime(2026, 1, 2, 10, 0, 0)))
        session.add(ObservableComment(
            user_id=user.id, observable_id=obs.id, comment="first",
            insert_date=datetime(2026, 1, 1, 10, 0, 0)))
        await session.flush()

        results = await service.list_detection_observables(session, search="commented.example.com")
        assert len(results) == 1
        comments = results[0].comments
        assert [c.comment for c in comments] == ["first", "second"]
        assert all(c.user_display_name == "Commenter" for c in comments)

    @pytest.mark.asyncio
    async def test_no_comments_is_empty_list(self, session: AsyncSession):
        await _make_observable(session, "fqdn", "uncommented.example.com", for_detection=True)
        await session.flush()

        results = await service.list_detection_observables(session, search="uncommented.example.com")
        assert len(results) == 1
        assert results[0].comments == []


class TestTypeFilterAndCount:
    @pytest.mark.asyncio
    async def test_filter_by_type(self, session: AsyncSession):
        await _make_observable(session, "ipv4", "20.0.0.1", for_detection=True)
        await _make_observable(session, "fqdn", "typed.example.com", for_detection=True)
        await session.flush()

        only_fqdn = await service.list_detection_observables(session, observable_type="fqdn")
        assert all(o.type == "fqdn" for o in only_fqdn)
        assert "typed.example.com" in {o.value for o in only_fqdn}

    @pytest.mark.asyncio
    async def test_count_matches_filters(self, session: AsyncSession):
        await _make_observable(session, "ipv4", "21.0.0.1", for_detection=True)
        await _make_observable(session, "ipv4", "21.0.0.2", for_detection=False)
        await session.flush()

        enabled = await service.count_detection_observables(session, for_detection=True, search="21.0.0.")
        assert enabled == 1
        both = await service.count_detection_observables(session, search="21.0.0.")
        assert both == 2

    @pytest.mark.asyncio
    async def test_list_observable_types_distinct_sorted(self, session: AsyncSession):
        await _make_observable(session, "zzz_type", "z.example.com")
        await _make_observable(session, "zzz_type", "z2.example.com")
        await session.flush()
        types = await service.list_observable_types(session)
        assert types == sorted(types)
        assert types.count("zzz_type") == 1


class TestPagination:
    @pytest.mark.asyncio
    async def test_pages_partition_the_result_set(self, session: AsyncSession):
        for i in range(5):
            await _make_observable(session, "pagetype", f"page{i}.example.com", for_detection=True)
        await session.flush()

        p1 = await service.get_detection_page(session, observable_type="pagetype", page=1, page_size=25)
        assert p1.total == 5 and p1.total_pages == 1
        assert p1.first_index == 1 and p1.last_index == 5
        assert not p1.has_prev and not p1.has_next

    @pytest.mark.asyncio
    async def test_multi_page_no_overlap_and_ordered_by_value(self, session: AsyncSession):
        # inserted out of alphabetical order so id order != value order
        for name in ("mp3", "mp1", "mp4", "mp0", "mp2"):
            await _make_observable(session, "multipage", f"{name}.example.com", for_detection=True)
        await session.flush()

        first = await service.list_detection_observables(session, observable_type="multipage", limit=2, offset=0)
        second = await service.list_detection_observables(session, observable_type="multipage", limit=2, offset=2)
        assert len(first) == 2 and len(second) == 2
        assert {o.id for o in first}.isdisjoint({o.id for o in second})

        # sorted alphabetically by value across page boundaries, NOT by insertion order
        assert [o.value for o in first] == ["mp0.example.com", "mp1.example.com"]
        assert [o.value for o in second] == ["mp2.example.com", "mp3.example.com"]

    @pytest.mark.asyncio
    async def test_ordering_groups_by_type_then_value(self, session: AsyncSession):
        await _make_observable(session, "ord_b", "zzz.example.com", for_detection=True)
        await _make_observable(session, "ord_a", "bbb.example.com", for_detection=True)
        await _make_observable(session, "ord_a", "aaa.example.com", for_detection=True)
        await session.flush()

        rows = [o for o in await service.list_detection_observables(session, for_detection=True)
                if o.type in ("ord_a", "ord_b")]
        assert [(o.type, o.value) for o in rows] == [
            ("ord_a", "aaa.example.com"),
            ("ord_a", "bbb.example.com"),
            ("ord_b", "zzz.example.com"),
        ]

    @pytest.mark.asyncio
    async def test_long_values_sharing_a_prefix_paginate_deterministically(self, session: AsyncSession):
        # Build values that collide in value_sort no matter what length the column is: both share a
        # prefix longer than value_sort, so the generated column ties and `id` must break it.
        value_sort_length = Observable.__table__.c.value_sort.type.length
        prefix = "https://collide.example.com/" + "x" * (value_sort_length + 10)
        a = await _make_observable(session, "tie", prefix + "/aaa", for_detection=True)
        b = await _make_observable(session, "tie", prefix + "/bbb", for_detection=True)
        await session.flush()

        # sanity: the two rows really do share a value_sort (otherwise the test proves nothing).
        # value_sort is computed by the database, so it must be read back explicitly.
        await session.refresh(a, ["value_sort"])
        await session.refresh(b, ["value_sort"])
        assert a.value_sort == b.value_sort

        page1 = await service.list_detection_observables(session, observable_type="tie", limit=1, offset=0)
        page2 = await service.list_detection_observables(session, observable_type="tie", limit=1, offset=1)
        assert [o.id for o in page1] == [min(a.id, b.id)]
        assert [o.id for o in page2] == [max(a.id, b.id)]
        # no row appears on both pages and none is skipped
        assert {page1[0].id, page2[0].id} == {a.id, b.id}

    @pytest.mark.asyncio
    async def test_page_is_clamped_to_valid_range(self, session: AsyncSession):
        await _make_observable(session, "clamped", "c.example.com", for_detection=True)
        await session.flush()
        # page 0 and page 999 both clamp into range
        low = await service.get_detection_page(session, observable_type="clamped", page=0)
        high = await service.get_detection_page(session, observable_type="clamped", page=999)
        assert low.page == 1
        assert high.page == high.total_pages

    @pytest.mark.asyncio
    async def test_empty_result_has_one_page(self, session: AsyncSession):
        page = await service.get_detection_page(session, observable_type="does_not_exist")
        assert page.total == 0 and page.total_pages == 1 and page.items == []
        assert page.first_index == 0 and page.last_index == 0

    @pytest.mark.parametrize("requested,expected", [
        (25, 25), (50, 50), (100, 100), (200, 200),
        (None, service.DEFAULT_PAGE_SIZE), (7, service.DEFAULT_PAGE_SIZE),
        (10_000, service.DEFAULT_PAGE_SIZE),  # cannot be used to request the whole table
    ])
    def test_page_size_is_clamped_to_choices(self, requested, expected):
        assert service.clamp_page_size(requested) == expected


class TestSetForDetection:
    @pytest.mark.asyncio
    async def test_enable(self, session: AsyncSession):
        user = User(username="det_u1", email="det_u1@e.com", display_name="U1", password="pw")
        session.add(user)
        obs = await _make_observable(session, "ipv4", "1.1.1.1", for_detection=False)
        await session.flush()

        result = await service.set_observable_for_detection(session, obs.id, True, user.id, "because reasons")
        assert result.for_detection is True
        assert result.detection_context == "because reasons"
        assert result.detection_modified_by == "U1"

    @pytest.mark.asyncio
    async def test_disable_records_who_disabled_and_clears_expiration(self, session: AsyncSession):
        """Disabling must not leave the enable's user/context/expiration behind."""
        from datetime import datetime

        enabler = User(username="det_en", email="det_en@e.com", display_name="Enabler", password="pw")
        disabler = User(username="det_dis", email="det_dis@e.com", display_name="Disabler", password="pw")
        session.add_all([enabler, disabler])
        obs = await _make_observable(session, "ipv4", "2.2.2.2", for_detection=False)
        await session.flush()

        await service.set_observable_for_detection(session, obs.id, True, enabler.id, "enabled by Enabler")
        await service.set_observable_expiration(session, obs.id, datetime(2030, 1, 1))

        result = await service.set_observable_for_detection(session, obs.id, False, disabler.id, "disabled by Disabler")
        assert result.for_detection is False
        # the columns now describe the disable, not the stale enable
        assert result.detection_modified_by == "Disabler"
        assert result.detection_context == "disabled by Disabler"
        # a stale expiration would be silently inherited on re-enable, excluding the observable
        # from the detection cache while the UI claimed it was enabled
        assert result.expires_on is None

    @pytest.mark.asyncio
    async def test_unknown_id(self, session: AsyncSession):
        assert await service.set_observable_for_detection(session, 999999, True, 1, None) is None


class TestSetExpiration:
    @pytest.mark.asyncio
    async def test_set_and_clear(self, session: AsyncSession):
        from datetime import datetime
        obs = await _make_observable(session, "ipv4", "3.3.3.3", for_detection=True)
        await session.flush()

        when = datetime(2030, 1, 1, 12, 0, 0)
        result = await service.set_observable_expiration(session, obs.id, when)
        assert result.expires_on == when

        cleared = await service.set_observable_expiration(session, obs.id, None)
        assert cleared.expires_on is None

    @pytest.mark.asyncio
    async def test_unknown_id(self, session: AsyncSession):
        assert await service.set_observable_expiration(session, 999999, None) is None
