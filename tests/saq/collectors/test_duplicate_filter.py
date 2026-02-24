import logging
import time
from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
from ace_api import sha256_str

from saq.collectors.collector_configuration import CollectorServiceConfiguration
from saq.collectors.duplicate_filter import DuplicateSubmissionFilter
from saq.database import get_db
from saq.persistence import Persistable


# ---------------------------------------------------------------------------
# Unit test fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_persistence_manager():
    manager = MagicMock(spec=Persistable)
    manager.persistence_source = MagicMock()
    return manager


@pytest.fixture
def mock_service_config():
    config = MagicMock(spec=CollectorServiceConfiguration)
    config.persistence_clear_seconds = 60
    config.persistence_expiration_seconds = 86400
    config.persistence_unmodified_expiration_seconds = 14400
    return config


@pytest.fixture
def duplicate_filter(mock_persistence_manager, mock_service_config):
    return DuplicateSubmissionFilter(mock_persistence_manager, mock_service_config)


# ---------------------------------------------------------------------------
# Integration test fixtures
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


# ===========================================================================
# Unit tests
# ===========================================================================


@pytest.mark.unit
class TestDuplicateSubmissionFilterUnit:

    def test_init_with_valid_persistence_source(self, duplicate_filter, mock_persistence_manager, mock_service_config):
        assert duplicate_filter.persistence_manager is mock_persistence_manager
        assert duplicate_filter.service_config is mock_service_config
        assert isinstance(duplicate_filter.persistent_clear_time, float)

    def test_init_raises_runtime_error_when_persistence_source_not_set(self, mock_service_config):
        manager = MagicMock(spec=Persistable)
        manager.persistence_source = None
        with pytest.raises(RuntimeError):
            DuplicateSubmissionFilter(manager, mock_service_config)

    @pytest.mark.parametrize("falsy_value", [0, "", False])
    def test_init_raises_runtime_error_when_persistence_source_is_falsy(self, falsy_value, mock_service_config):
        manager = MagicMock(spec=Persistable)
        manager.persistence_source = falsy_value
        with pytest.raises(RuntimeError):
            DuplicateSubmissionFilter(manager, mock_service_config)

    def test_is_duplicate_returns_false_for_new_key(self, duplicate_filter):
        duplicate_filter.persistence_manager.persistent_data_exists.return_value = False
        assert duplicate_filter.is_duplicate("new_key") is False

    def test_is_duplicate_returns_true_for_existing_key(self, duplicate_filter):
        duplicate_filter.persistence_manager.persistent_data_exists.return_value = True
        assert duplicate_filter.is_duplicate("existing_key") is True

    def test_is_duplicate_returns_false_for_none_key(self, duplicate_filter):
        assert duplicate_filter.is_duplicate(None) is False
        duplicate_filter.persistence_manager.persistent_data_exists.assert_not_called()

    def test_is_duplicate_returns_false_for_empty_string(self, duplicate_filter):
        assert duplicate_filter.is_duplicate("") is False
        duplicate_filter.persistence_manager.persistent_data_exists.assert_not_called()

    def test_is_duplicate_hashes_key_with_sha256(self, duplicate_filter):
        duplicate_filter.persistence_manager.persistent_data_exists.return_value = False
        duplicate_filter.is_duplicate("test_key")
        expected_hash = sha256_str("test_key")
        duplicate_filter.persistence_manager.persistent_data_exists.assert_called_once_with(expected_hash)

    def test_mark_as_processed_saves_hashed_key(self, duplicate_filter):
        duplicate_filter.mark_as_processed("test_key")
        expected_hash = sha256_str("test_key")
        duplicate_filter.persistence_manager.save_persistent_key.assert_called_once_with(expected_hash)

    def test_mark_as_processed_does_nothing_for_none_key(self, duplicate_filter):
        duplicate_filter.mark_as_processed(None)
        duplicate_filter.persistence_manager.save_persistent_key.assert_not_called()

    def test_mark_as_processed_does_nothing_for_empty_string(self, duplicate_filter):
        duplicate_filter.mark_as_processed("")
        duplicate_filter.persistence_manager.save_persistent_key.assert_not_called()

    def test_clear_expired_data_does_not_run_before_interval(self, duplicate_filter):
        # just created, so interval has not elapsed
        duplicate_filter.clear_expired_data()
        duplicate_filter.persistence_manager.delete_expired_persistent_keys.assert_not_called()

    @patch("saq.collectors.duplicate_filter.time")
    def test_clear_expired_data_runs_after_interval_elapsed(self, mock_time, mock_persistence_manager, mock_service_config):
        mock_time.time.return_value = 1000.0
        df = DuplicateSubmissionFilter(mock_persistence_manager, mock_service_config)

        # advance time past the 60-second interval
        mock_time.time.return_value = 1061.0
        df.clear_expired_data()
        mock_persistence_manager.delete_expired_persistent_keys.assert_called_once()

    @patch("saq.collectors.duplicate_filter.time")
    def test_clear_expired_data_passes_correct_timedelta_arguments(self, mock_time, mock_persistence_manager, mock_service_config):
        mock_time.time.return_value = 1000.0
        df = DuplicateSubmissionFilter(mock_persistence_manager, mock_service_config)

        mock_time.time.return_value = 1061.0
        df.clear_expired_data()

        expected_expiration = timedelta(seconds=86400)
        expected_unmodified = timedelta(seconds=14400)
        mock_persistence_manager.delete_expired_persistent_keys.assert_called_once_with(
            expected_expiration, expected_unmodified
        )

    @patch("saq.collectors.duplicate_filter.time")
    def test_clear_expired_data_resets_timer_on_success(self, mock_time, mock_persistence_manager, mock_service_config):
        mock_time.time.return_value = 1000.0
        df = DuplicateSubmissionFilter(mock_persistence_manager, mock_service_config)

        # first call - interval elapsed
        mock_time.time.return_value = 1061.0
        df.clear_expired_data()
        assert mock_persistence_manager.delete_expired_persistent_keys.call_count == 1

        # second call immediately after - should NOT run again
        mock_time.time.return_value = 1062.0
        df.clear_expired_data()
        assert mock_persistence_manager.delete_expired_persistent_keys.call_count == 1

    @patch("saq.collectors.duplicate_filter.time")
    def test_clear_expired_data_resets_timer_even_on_exception(self, mock_time, mock_persistence_manager, mock_service_config):
        mock_time.time.return_value = 1000.0
        df = DuplicateSubmissionFilter(mock_persistence_manager, mock_service_config)

        mock_persistence_manager.delete_expired_persistent_keys.side_effect = Exception("db error")

        # first call - interval elapsed, exception occurs
        mock_time.time.return_value = 1061.0
        df.clear_expired_data()

        # second call immediately after - timer was reset so should NOT run again
        mock_time.time.return_value = 1062.0
        df.clear_expired_data()
        assert mock_persistence_manager.delete_expired_persistent_keys.call_count == 1

    @patch("saq.collectors.duplicate_filter.time")
    def test_clear_expired_data_logs_warning_on_exception(self, mock_time, mock_persistence_manager, mock_service_config, caplog):
        mock_time.time.return_value = 1000.0
        df = DuplicateSubmissionFilter(mock_persistence_manager, mock_service_config)

        mock_persistence_manager.delete_expired_persistent_keys.side_effect = Exception("db error")

        mock_time.time.return_value = 1061.0
        with caplog.at_level(logging.WARNING):
            df.clear_expired_data()

        assert any("unable to delete expired persistent keys" in r.message for r in caplog.records)

    @patch("saq.collectors.duplicate_filter.time")
    def test_clear_expired_data_with_zero_interval(self, mock_time, mock_persistence_manager, mock_service_config):
        mock_service_config.persistence_clear_seconds = 0
        mock_time.time.return_value = 1000.0
        df = DuplicateSubmissionFilter(mock_persistence_manager, mock_service_config)

        # even at the same time, 0 interval means any elapsed time > 0 should trigger
        # but time.time() - persistent_clear_time == 0, which is NOT > 0
        # so we advance by the smallest amount
        mock_time.time.return_value = 1000.001
        df.clear_expired_data()
        mock_persistence_manager.delete_expired_persistent_keys.assert_called_once()

    def test_is_duplicate_and_mark_as_processed_use_same_hash(self, duplicate_filter):
        key = "consistent_hash_key"
        duplicate_filter.persistence_manager.persistent_data_exists.return_value = False

        duplicate_filter.is_duplicate(key)
        duplicate_filter.mark_as_processed(key)

        exists_hash = duplicate_filter.persistence_manager.persistent_data_exists.call_args[0][0]
        save_hash = duplicate_filter.persistence_manager.save_persistent_key.call_args[0][0]
        assert exists_hash == save_hash
        assert exists_hash == sha256_str(key)


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
