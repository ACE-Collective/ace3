import pytest

from saq.constants import TIMESPEC_TOKEN
from saq.observables.mapping import ObservableMapping
from saq.query.config import (
    BaseQueryConfig,
    SummaryDetailConfig,
    load_query_from_file,
    resolve_query,
)


@pytest.mark.unit
def test_base_query_config_defaults():
    """Test BaseQueryConfig with only defaults."""
    config = BaseQueryConfig()
    assert config.query is None
    assert config.query_path is None
    assert config.observable_mapping == []
    assert config.max_result_count is None
    assert config.ignored_values == []
    assert config.summary_details == []


@pytest.mark.unit
def test_base_query_config_with_ignored_values():
    """Test BaseQueryConfig compiles ignored_values patterns."""
    config = BaseQueryConfig(ignored_values=[r"N/A", r"\d+\.\d+\.\d+\.\d+"])
    assert config.is_ignored_value("N/A") is True
    assert config.is_ignored_value("192.168.1.1") is True
    assert config.is_ignored_value("some-value") is False


@pytest.mark.unit
def test_base_query_config_with_observable_mapping():
    """Test BaseQueryConfig with observable mappings."""
    config = BaseQueryConfig(
        observable_mapping=[
            ObservableMapping(field="src_ip", type="ipv4"),
            ObservableMapping(field="user", type="user"),
        ]
    )
    assert len(config.observable_mapping) == 2
    assert config.observable_mapping[0].type == "ipv4"
    assert config.observable_mapping[1].type == "user"


@pytest.mark.unit
def test_summary_detail_config_defaults():
    """Test SummaryDetailConfig default values."""
    config = SummaryDetailConfig(content="${field}")
    assert config.content == "${field}"
    assert config.header is None
    assert config.format == "md"
    assert config.limit == 100
    assert config.grouped is False


@pytest.mark.unit
def test_summary_detail_config_invalid_format():
    """Test SummaryDetailConfig with invalid format falls back to md."""
    config = SummaryDetailConfig(content="test", format="invalid")
    assert config.format == "md"


@pytest.mark.unit
def test_load_query_from_file(tmp_path):
    """Test loading a query from file."""
    query_file = tmp_path / "test_query.txt"
    query_file.write_text("SELECT * FROM events WHERE ip = '1.2.3.4'")

    result = load_query_from_file(str(query_file))
    assert result == "SELECT * FROM events WHERE ip = '1.2.3.4'"


@pytest.mark.unit
def test_resolve_query_inline():
    """Test resolve_query with inline query."""
    result = resolve_query("SELECT 1", None, "test")
    assert result == "SELECT 1"


@pytest.mark.unit
def test_resolve_query_from_file(tmp_path):
    """Test resolve_query with file path."""
    query_file = tmp_path / "test_query.txt"
    query_file.write_text("SELECT * FROM events")

    result = resolve_query(None, str(query_file), "test")
    assert result == "SELECT * FROM events"


@pytest.mark.unit
def test_resolve_query_neither_raises():
    """Test resolve_query raises ValueError when neither query nor path provided."""
    with pytest.raises(ValueError, match="no query specified"):
        resolve_query(None, None, "test_module")


@pytest.mark.unit
def test_resolve_query_inline_takes_precedence(tmp_path):
    """Test resolve_query prefers inline query over file."""
    query_file = tmp_path / "test_query.txt"
    query_file.write_text("FROM FILE")

    result = resolve_query("INLINE QUERY", str(query_file), "test")
    assert result == "INLINE QUERY"


@pytest.mark.unit
def test_base_query_config_time_ranges_none():
    """Test BaseQueryConfig with no time_ranges."""
    config = BaseQueryConfig()
    assert config.time_ranges is None


@pytest.mark.unit
def test_base_query_config_time_ranges_string_shorthand():
    """Test time_ranges with plain string values (lookback-only shorthand)."""
    config = BaseQueryConfig(time_ranges={"TIMESPEC2": "00:30:00"})
    assert config.time_ranges is not None
    assert "TIMESPEC2" in config.time_ranges
    assert config.time_ranges["TIMESPEC2"].duration_before == "00:30:00"
    assert config.time_ranges["TIMESPEC2"].duration_after is None


@pytest.mark.unit
def test_base_query_config_time_ranges_dict_form():
    """Test time_ranges with full dict form (before and after)."""
    config = BaseQueryConfig(time_ranges={
        "TIMESPEC2": {"duration_before": "01:00:00", "duration_after": "24:00:00"}
    })
    assert config.time_ranges["TIMESPEC2"].duration_before == "01:00:00"
    assert config.time_ranges["TIMESPEC2"].duration_after == "24:00:00"


@pytest.mark.unit
def test_base_query_config_time_ranges_mixed():
    """Test time_ranges with mixed string and dict forms."""
    config = BaseQueryConfig(time_ranges={
        TIMESPEC_TOKEN: "00:10:00",
        "TIMESPEC2": {"duration_before": "01:00:00", "duration_after": "00:30:00"},
    })
    assert config.time_ranges[TIMESPEC_TOKEN].duration_before == "00:10:00"
    assert config.time_ranges[TIMESPEC_TOKEN].duration_after is None
    assert config.time_ranges["TIMESPEC2"].duration_before == "01:00:00"
    assert config.time_ranges["TIMESPEC2"].duration_after == "00:30:00"
