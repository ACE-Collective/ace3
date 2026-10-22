import datetime
from unittest.mock import MagicMock, patch

import pytest

from saq.collectors.hunter.correlation.registry import clear_query_sources
from saq.collectors.hunter.correlation.sources.splunk import SplunkQuerySource
from saq.configuration.config import get_splunk_config


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_query_sources()
    yield
    clear_query_sources()


@pytest.mark.unit
class TestSplunkQuerySource:

    def test_execute_query_calls_splunk_client_with_config_name(self):
        mock_client = MagicMock()
        mock_client.query.return_value = []
        with patch(
            "saq.splunk.SplunkClient",
            return_value=mock_client,
        ) as mock_factory:
            source = SplunkQuerySource("my_config")
            source.execute_query(
                "search index=main",
                datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
                datetime.datetime(2024, 1, 2, tzinfo=datetime.timezone.utc),
                datetime.timedelta(minutes=30),
            )
            mock_factory.assert_called_once_with("my_config")

    def test_execute_query_passes_correct_params(self):
        mock_client = MagicMock()
        mock_client.query.return_value = []
        start = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
        end = datetime.datetime(2024, 1, 2, tzinfo=datetime.timezone.utc)
        timeout = datetime.timedelta(minutes=15)
        with patch(
            "saq.splunk.SplunkClient",
            return_value=mock_client,
        ):
            source = SplunkQuerySource()
            source.execute_query("search index=main", start, end, timeout)
            mock_client.query.assert_called_once_with(
                query="search index=main",
                start=start,
                end=end,
                timeout=timeout,
            )

    def test_execute_query_returns_results(self):
        mock_client = MagicMock()
        expected = [{"host": "web1"}, {"host": "web2"}]
        mock_client.query.return_value = expected
        with patch(
            "saq.splunk.SplunkClient",
            return_value=mock_client,
        ):
            source = SplunkQuerySource()
            results = source.execute_query(
                "search index=main",
                datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
                datetime.datetime(2024, 1, 2, tzinfo=datetime.timezone.utc),
                datetime.timedelta(minutes=5),
            )
            assert results == expected

    def test_execute_query_returns_empty_list(self):
        mock_client = MagicMock()
        mock_client.query.return_value = []
        with patch(
            "saq.splunk.SplunkClient",
            return_value=mock_client,
        ):
            source = SplunkQuerySource()
            results = source.execute_query(
                "search index=main",
                datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
                datetime.datetime(2024, 1, 2, tzinfo=datetime.timezone.utc),
                datetime.timedelta(minutes=5),
            )
            assert results == []

    def test_default_config_name(self):
        mock_client = MagicMock()
        mock_client.query.return_value = []
        with patch(
            "saq.splunk.SplunkClient",
            return_value=mock_client,
        ) as mock_factory:
            source = SplunkQuerySource()
            source.execute_query(
                "search index=main",
                datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
                datetime.datetime(2024, 1, 2, tzinfo=datetime.timezone.utc),
                datetime.timedelta(minutes=5),
            )
            mock_factory.assert_called_once_with("default")


@pytest.mark.unit
class TestSplunkSourceMetadata:

    def test_default_time_field_and_format(self):
        # the splunk source declares the conventional defaults so hunts can omit
        # relative_time_field / relative_time_format on splunk-anchored time_ranges
        assert SplunkQuerySource.default_time_field == "_time"
        assert SplunkQuerySource.default_time_format == "iso8601"

    def test_execute_query_accepts_and_ignores_source_options(self):
        """Splunk source has no per-call options today; it must accept and
        ignore source_options to satisfy the QuerySource ABC contract."""
        mock_client = MagicMock()
        mock_client.query.return_value = []
        with patch(
            "saq.splunk.SplunkClient",
            return_value=mock_client,
        ):
            source = SplunkQuerySource()
            results = source.execute_query(
                "search index=main",
                datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
                datetime.datetime(2024, 1, 2, tzinfo=datetime.timezone.utc),
                datetime.timedelta(minutes=5),
                source_options={"some_key": "some_value"},
            )
            assert results == []


@pytest.mark.unit
class TestSplunkSourceTimespecFormatting:
    """Correlation Trace UI displays the time bounds in source-native syntax so
    analysts can paste them back into the data source. For Splunk that means
    `earliest=MM/DD/YYYY:HH:MM:SS latest=…` rendered in the configured TZ."""

    def test_format_timespec_uses_configured_timezone(self, monkeypatch):
        # UTC 12:26-12:31 → EDT (UTC-4) 08:26-08:31 on 2026-05-18
        start = datetime.datetime(2026, 5, 18, 12, 26, 32, tzinfo=datetime.timezone.utc)
        end = datetime.datetime(2026, 5, 18, 12, 31, 32, tzinfo=datetime.timezone.utc)
        monkeypatch.setattr(get_splunk_config("default"), "timezone", "America/New_York")
        source = SplunkQuerySource("default")
        assert source.format_timespec_for_display(start, end) == (
            "earliest=05/18/2026:08:26:32 latest=05/18/2026:08:31:32"
        )

    def test_format_timespec_in_utc_config(self, monkeypatch):
        start = datetime.datetime(2026, 5, 18, 12, 26, 32, tzinfo=datetime.timezone.utc)
        end = datetime.datetime(2026, 5, 18, 12, 31, 32, tzinfo=datetime.timezone.utc)
        monkeypatch.setattr(get_splunk_config("test_api"), "timezone", "UTC")
        source = SplunkQuerySource("test_api")
        assert source.format_timespec_for_display(start, end) == (
            "earliest=05/18/2026:12:26:32 latest=05/18/2026:12:31:32"
        )

    def test_format_timespec_unknown_config_raises(self):
        start = datetime.datetime(2026, 5, 18, 12, 26, 32, tzinfo=datetime.timezone.utc)
        with pytest.raises(ValueError, match="splunk config for no_such_splunk not found"):
            SplunkQuerySource("no_such_splunk").format_timespec_for_display(start, start)
