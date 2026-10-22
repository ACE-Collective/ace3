import logging
import time
from datetime import timedelta
from unittest.mock import patch

import pytest
from ace_api import sha256_str

from saq.collectors.collector_configuration import CollectorServiceConfiguration
from saq.collectors.duplicate_filter import DuplicateSubmissionFilter
from saq.database import get_db
from saq.database.model import Persistence
from saq.persistence import Persistable


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def persistence_manager():
    obj = Persistable()
    obj.register_persistence_source("test_duplicate_filter")
    return obj


@pytest.fixture
def service_config():
    return CollectorServiceConfiguration(
        name="test_dup_filter",
        python_module="tests.saq.collectors.test_duplicate_filter",
        python_class="DummyService",
        description="Test duplicate filter",
        enabled=True,
        workload_type="test_dup",
        delete_files=False,
        collection_frequency=1,
        persistence_clear_seconds=60,
        persistence_expiration_seconds=86400,
        persistence_unmodified_expiration_seconds=14400,
    )


@pytest.fixture
def integration_filter(persistence_manager, service_config):
    return DuplicateSubmissionFilter(persistence_manager, service_config)


@pytest.mark.integration
class TestDuplicateSubmissionFilterKeys:

    def test_init_keeps_manager_and_config(self, integration_filter, persistence_manager, service_config):
        assert integration_filter.persistence_manager is persistence_manager
        assert integration_filter.service_config is service_config
        assert isinstance(integration_filter.persistent_clear_time, float)

    def test_key_is_stored_as_its_sha256(self, integration_filter, persistence_manager):
        integration_filter.mark_as_processed("test_key")
        get_db().close()
        assert persistence_manager.persistent_data_exists(sha256_str("test_key")) is True
        assert persistence_manager.persistent_data_exists("test_key") is False

    @pytest.mark.parametrize("key", [None, ""])
    def test_empty_key_is_never_stored_or_duplicate(self, integration_filter, persistence_manager, key):
        integration_filter.mark_as_processed(key)
        get_db().close()
        assert integration_filter.is_duplicate(key) is False
        assert get_db().query(Persistence).filter(
            Persistence.source_id == persistence_manager.persistence_source.id).count() == 0


@pytest.mark.integration
class TestDuplicateSubmissionFilterClearInterval:

    @pytest.fixture
    def expire_everything(self, service_config):
        service_config.persistence_expiration_seconds = 0
        service_config.persistence_unmodified_expiration_seconds = 0

    @patch("saq.collectors.duplicate_filter.time")
    def test_clear_expired_data_runs_after_interval_elapsed(self, mock_time, persistence_manager, service_config, expire_everything):
        mock_time.time.return_value = 1000.0
        df = DuplicateSubmissionFilter(persistence_manager, service_config)
        df.mark_as_processed("old_key")
        get_db().close()

        # not yet: the 60-second interval has not elapsed
        mock_time.time.return_value = 1059.0
        df.clear_expired_data()
        get_db().close()
        assert df.is_duplicate("old_key") is True

        mock_time.time.return_value = 1061.0
        df.clear_expired_data()
        get_db().close()
        assert df.is_duplicate("old_key") is False

    @patch("saq.collectors.duplicate_filter.time")
    def test_clear_expired_data_passes_configured_timedeltas(self, mock_time, persistence_manager, service_config):
        mock_time.time.return_value = 1000.0
        df = DuplicateSubmissionFilter(persistence_manager, service_config)
        df.mark_as_processed("fresh_key")
        get_db().close()

        mock_time.time.return_value = 1061.0
        with patch.object(persistence_manager, "delete_expired_persistent_keys",
                          wraps=persistence_manager.delete_expired_persistent_keys) as delete_expired:
            df.clear_expired_data()
        get_db().close()

        delete_expired.assert_called_once_with(timedelta(seconds=86400), timedelta(seconds=14400))
        # a key saved just now is inside both windows
        assert df.is_duplicate("fresh_key") is True

    @patch("saq.collectors.duplicate_filter.time")
    def test_clear_expired_data_resets_timer_on_success(self, mock_time, persistence_manager, service_config, expire_everything):
        mock_time.time.return_value = 1000.0
        df = DuplicateSubmissionFilter(persistence_manager, service_config)

        mock_time.time.return_value = 1061.0
        df.clear_expired_data()
        assert df.persistent_clear_time == 1061.0

        # a key saved after the clear survives a call made before the next interval
        df.mark_as_processed("new_key")
        get_db().close()
        mock_time.time.return_value = 1062.0
        df.clear_expired_data()
        get_db().close()
        assert df.is_duplicate("new_key") is True

    @patch("saq.collectors.duplicate_filter.time")
    def test_clear_expired_data_resets_timer_even_on_exception(self, mock_time, persistence_manager, service_config):
        mock_time.time.return_value = 1000.0
        df = DuplicateSubmissionFilter(persistence_manager, service_config)

        with patch.object(persistence_manager, "delete_expired_persistent_keys",
                          side_effect=Exception("db error")) as delete_expired:
            # first call - interval elapsed, exception occurs
            mock_time.time.return_value = 1061.0
            df.clear_expired_data()

            # second call immediately after - timer was reset so should NOT run again
            mock_time.time.return_value = 1062.0
            df.clear_expired_data()

        assert delete_expired.call_count == 1

    @patch("saq.collectors.duplicate_filter.time")
    def test_clear_expired_data_logs_warning_on_exception(self, mock_time, persistence_manager, service_config, caplog):
        mock_time.time.return_value = 1000.0
        df = DuplicateSubmissionFilter(persistence_manager, service_config)

        mock_time.time.return_value = 1061.0
        with patch.object(persistence_manager, "delete_expired_persistent_keys", side_effect=Exception("db error")), \
             caplog.at_level(logging.WARNING):
            df.clear_expired_data()

        assert any("unable to delete expired persistent keys" in r.message for r in caplog.records)

    @patch("saq.collectors.duplicate_filter.time")
    def test_clear_expired_data_with_zero_interval(self, mock_time, persistence_manager, service_config, expire_everything):
        service_config.persistence_clear_seconds = 0
        mock_time.time.return_value = 1000.0
        df = DuplicateSubmissionFilter(persistence_manager, service_config)
        df.mark_as_processed("old_key")
        get_db().close()

        # time.time() - persistent_clear_time == 0 is NOT > 0, so advance by the smallest amount
        mock_time.time.return_value = 1000.001
        df.clear_expired_data()
        get_db().close()
        assert df.is_duplicate("old_key") is False


# ===========================================================================
# Integration tests
# ===========================================================================


@pytest.mark.integration
class TestDuplicateSubmissionFilterIntegration:

    def test_integration_init_with_registered_persistence_source(self, integration_filter):
        assert integration_filter.persistence_manager.persistence_source is not None
        assert integration_filter.persistence_manager.persistence_source.name == "test_duplicate_filter"

    def test_integration_init_fails_without_registered_source(self, service_config):
        obj = Persistable()
        # persistence_source is None by default
        with pytest.raises(RuntimeError):
            DuplicateSubmissionFilter(obj, service_config)

    def test_integration_new_key_is_not_duplicate(self, integration_filter):
        assert integration_filter.is_duplicate("brand_new_key") is False

    def test_integration_mark_then_detect_duplicate(self, integration_filter):
        key = "integration_test_key"
        assert integration_filter.is_duplicate(key) is False
        integration_filter.mark_as_processed(key)
        get_db().close()
        assert integration_filter.is_duplicate(key) is True

    def test_integration_different_keys_are_independent(self, integration_filter):
        integration_filter.mark_as_processed("key_a")
        get_db().close()
        assert integration_filter.is_duplicate("key_a") is True
        assert integration_filter.is_duplicate("key_b") is False

    def test_integration_mark_same_key_twice_does_not_error(self, integration_filter):
        integration_filter.mark_as_processed("idempotent_key")
        get_db().close()
        # second call should not raise thanks to ON DUPLICATE KEY UPDATE
        integration_filter.mark_as_processed("idempotent_key")
        get_db().close()
        assert integration_filter.is_duplicate("idempotent_key") is True

    def test_integration_clear_expired_data_removes_old_keys(self, integration_filter):
        integration_filter.mark_as_processed("old_key")
        get_db().close()
        assert integration_filter.is_duplicate("old_key") is True

        # force the clear interval to pass
        integration_filter.persistent_clear_time = 0

        # use a zero-second expiration to expire everything immediately
        integration_filter.service_config.persistence_expiration_seconds = 0
        integration_filter.service_config.persistence_unmodified_expiration_seconds = 0

        integration_filter.clear_expired_data()
        get_db().close()
        assert integration_filter.is_duplicate("old_key") is False

    def test_integration_clear_expired_data_respects_interval(self, integration_filter):
        integration_filter.mark_as_processed("interval_key")
        get_db().close()

        # clear time was just set so interval hasn't elapsed
        integration_filter.clear_expired_data()
        get_db().close()

        # key should still exist because clear didn't actually run
        assert integration_filter.is_duplicate("interval_key") is True

    def test_integration_empty_string_key_not_stored(self, integration_filter):
        integration_filter.mark_as_processed("")
        get_db().close()
        assert integration_filter.is_duplicate("") is False

    def test_integration_multiple_keys_tracked_independently(self, integration_filter):
        keys = ["key_1", "key_2", "key_3"]
        for key in keys:
            integration_filter.mark_as_processed(key)
        get_db().close()

        for key in keys:
            assert integration_filter.is_duplicate(key) is True

        assert integration_filter.is_duplicate("key_4") is False

    def test_integration_different_persistence_sources_are_isolated(self, service_config):
        manager_a = Persistable()
        manager_a.register_persistence_source("source_a")
        filter_a = DuplicateSubmissionFilter(manager_a, service_config)

        manager_b = Persistable()
        manager_b.register_persistence_source("source_b")
        filter_b = DuplicateSubmissionFilter(manager_b, service_config)

        filter_a.mark_as_processed("shared_key")
        get_db().close()

        assert filter_a.is_duplicate("shared_key") is True
        assert filter_b.is_duplicate("shared_key") is False
