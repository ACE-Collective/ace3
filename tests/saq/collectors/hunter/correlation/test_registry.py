import pytest

from saq.collectors.hunter.correlation.registry import (
    QuerySource,
    clear_query_sources,
    get_query_source,
    get_registered_sources,
    register_query_source,
)


class MockQuerySource(QuerySource):
    default_time_field = "_time"
    default_time_format = "iso8601"

    def execute_query(self, query, start_time, end_time, timeout, source_options=None):
        return [{"result": "test"}]


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_query_sources()
    yield
    clear_query_sources()


@pytest.mark.unit
class TestQuerySourceRegistry:

    def test_register_and_get(self):
        source = MockQuerySource()
        register_query_source("test", source)
        assert get_query_source("test") is source

    def test_get_unregistered_raises(self):
        with pytest.raises(ValueError, match="not registered"):
            get_query_source("nonexistent")

    def test_overwrite_registration(self):
        source1 = MockQuerySource()
        source2 = MockQuerySource()
        register_query_source("test", source1)
        register_query_source("test", source2)
        assert get_query_source("test") is source2

    def test_clear_sources(self):
        register_query_source("test", MockQuerySource())
        clear_query_sources()
        assert len(get_registered_sources()) == 0

    def test_get_registered_sources(self):
        source = MockQuerySource()
        register_query_source("src1", source)
        register_query_source("src2", source)
        sources = get_registered_sources()
        assert "src1" in sources
        assert "src2" in sources
