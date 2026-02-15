from datetime import datetime
from unittest.mock import Mock, patch

import pytest

from saq.collectors.email.journal import JournalEmailCollector
from saq.configuration import get_config
from saq.configuration.config import get_service_config
from saq.constants import ANALYSIS_MODE_EMAIL, ANALYSIS_TYPE_MAILBOX, DIRECTIVE_ARCHIVE, DIRECTIVE_NO_SCAN, DIRECTIVE_ORIGINAL_EMAIL, SERVICE_JOURNAL_EMAIL_COLLECTOR


pytestmark = pytest.mark.unit


class TestJournalEmailCollector:
    """Test suite for JournalEmailCollector class."""

    @pytest.fixture
    def mock_config(self, monkeypatch):
        """Mock configuration values."""
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "blacklist_yara_rule_path", "/tmp/blacklist.yara")
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "blacklist_yara_rule_check_frequency", 60)
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "delete_s3_objects", False)
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "bucket_name", "journal-emails")

    @pytest.fixture
    def mock_s3_client(self):
        """Mock S3 client."""
        with patch("saq.collectors.email.journal.get_s3_client") as mock_get_s3_client:
            mock_client = Mock()
            mock_get_s3_client.return_value = mock_client
            yield mock_client

    @pytest.fixture
    def collector(self, mock_config, mock_s3_client):
        """Create a JournalEmailCollector instance with mocked dependencies."""
        with patch("saq.collectors.email.journal.local_time") as mock_local_time:
            mock_local_time.return_value = datetime(2023, 1, 1, 12, 0, 0)
            collector = JournalEmailCollector()
            collector.fqdn = "test.example.com"
            return collector

    def test_init(self, collector, mock_s3_client):
        """Test collector initialization."""
        assert collector.client == mock_s3_client
        assert collector.blacklist_yara_rule_path == "/tmp/blacklist.yara"
        assert collector.blacklist_yara_rule_check_frequency == 60
        assert collector.yara_context is None
        assert collector.bucket_name == "journal-emails"

    def test_should_load_blacklist_yara_rule_no_path(self, collector):
        """Test should_load_blacklist_yara_rule when no path is configured."""
        collector.blacklist_yara_rule_path = ""

        result = collector.should_load_blacklist_yara_rule()

        assert result is False

    def test_should_load_blacklist_yara_rule_file_not_exists(self, collector):
        """Test should_load_blacklist_yara_rule when file doesn't exist."""
        collector.blacklist_yara_rule_path = "/nonexistent/path.yara"

        with patch("saq.collectors.email.journal.os.path.exists") as mock_exists:
            mock_exists.return_value = False

            result = collector.should_load_blacklist_yara_rule()

            assert result is False

    def test_should_load_blacklist_yara_rule_within_check_frequency(self, collector):
        """Test should_load_blacklist_yara_rule within check frequency."""
        collector.yara_context = Mock()
        collector.blacklist_yara_rule_check_frequency = 60

        with patch("saq.collectors.email.journal.os.path.exists") as mock_exists, \
             patch("saq.collectors.email.journal.local_time") as mock_local_time:

            mock_exists.return_value = True
            mock_local_time.return_value = collector.blacklist_yara_rule_last_check

            result = collector.should_load_blacklist_yara_rule()

            assert result is False

    def test_should_load_blacklist_yara_rule_file_changed(self, collector):
        """Test should_load_blacklist_yara_rule when file has changed."""
        collector.blacklist_yara_rule_last_mtime = 1000

        with patch("saq.collectors.email.journal.os.path.exists") as mock_exists, \
             patch("saq.collectors.email.journal.os.path.getmtime") as mock_getmtime:

            mock_exists.return_value = True
            mock_getmtime.return_value = 2000  # File has newer mtime

            result = collector.should_load_blacklist_yara_rule()

            assert result is True

    def test_load_blacklist_yara_rule(self, collector):
        """Test loading blacklist yara rule."""
        with patch("saq.collectors.email.journal.yara.compile") as mock_yara_compile:
            mock_rules = Mock()
            mock_yara_compile.return_value = mock_rules

            collector.load_blacklist_yara_rule()

            mock_yara_compile.assert_called_once_with(filepath=collector.blacklist_yara_rule_path)
            assert collector.yara_context == mock_rules

    def test_is_blacklisted_no_yara_context(self, collector):
        """Test is_blacklisted when no yara context is available."""
        collector.yara_context = None

        with patch.object(collector, "should_load_blacklist_yara_rule") as mock_should_load:
            mock_should_load.return_value = False

            result = collector.is_blacklisted("/tmp/test_email.eml")

            assert result is False

    def test_is_blacklisted_loads_rules_when_needed(self, collector):
        """Test is_blacklisted loads rules when needed."""
        with patch.object(collector, "should_load_blacklist_yara_rule") as mock_should_load, \
             patch.object(collector, "load_blacklist_yara_rule") as mock_load:

            mock_should_load.return_value = True
            collector.yara_context = Mock()
            collector.yara_context.match.return_value = []

            result = collector.is_blacklisted("/tmp/test_email.eml")

            mock_load.assert_called_once()
            assert result is False

    def test_is_blacklisted_returns_true_for_blacklisted_email(self, collector):
        """Test is_blacklisted returns True for blacklisted email."""
        mock_match = Mock()
        mock_match.rule = "test_rule"
        mock_match.tags = ["blacklist"]

        collector.yara_context = Mock()
        collector.yara_context.match.return_value = [mock_match]

        with patch.object(collector, "should_load_blacklist_yara_rule") as mock_should_load:
            mock_should_load.return_value = False

            result = collector.is_blacklisted("/tmp/test_email.eml")

            assert result is True

    def test_is_blacklisted_returns_false_for_non_blacklisted_email(self, collector):
        """Test is_blacklisted returns False for non-blacklisted email."""
        mock_match = Mock()
        mock_match.rule = "test_rule"
        mock_match.tags = ["other_tag"]

        collector.yara_context = Mock()
        collector.yara_context.match.return_value = [mock_match]

        with patch.object(collector, "should_load_blacklist_yara_rule") as mock_should_load:
            mock_should_load.return_value = False

            result = collector.is_blacklisted("/tmp/test_email.eml")

            assert result is False

    def test_collect_empty_bucket(self, collector, mock_s3_client):
        """Test collect method with empty bucket."""
        mock_s3_client.list_objects_v2.return_value = {}

        submissions = list(collector.collect())

        assert len(submissions) == 0
        mock_s3_client.list_objects_v2.assert_called_once_with(Bucket="journal-emails")

    def test_collect_single_object(self, collector, mock_s3_client, tmpdir):
        """Test collect method with single object in bucket."""
        # setup a mock object in the bucket
        mock_s3_client.list_objects_v2.return_value = {"Contents": [{"Key": "test-email.eml"}]}

        email_content = b"From: test@example.com\nSubject: Test\n\nTest email"
        email_path = str(tmpdir.join("test_email.eml"))

        with open(email_path, "wb") as f:
            f.write(email_content)

        with patch("saq.collectors.email.journal.get_temp_dir") as mock_get_temp_dir, \
             patch("saq.collectors.email.journal.uuid4") as mock_uuid4, \
             patch("saq.collectors.email.journal.local_time") as mock_local_time, \
             patch.object(collector, "is_blacklisted") as mock_is_blacklisted:

            mock_get_temp_dir.return_value = str(tmpdir)
            mock_uuid4.side_effect = ["email-uuid", "root-uuid"]
            mock_local_time.return_value = datetime(2023, 1, 1, 12, 0, 0)
            mock_is_blacklisted.return_value = False

            def mock_download_file(bucket, key, local_path):
                with open(email_path, "rb") as src, open(local_path, "wb") as dst:
                    dst.write(src.read())

            mock_s3_client.download_file.side_effect = mock_download_file

            submissions = list(collector.collect())

            assert len(submissions) == 1
            submission = submissions[0]

            assert submission.key == "test-email.eml"
            assert submission.root.description == "ACE Mailbox Scanner Detection"
            assert submission.root.analysis_mode == ANALYSIS_MODE_EMAIL
            assert submission.root.tool == "ACE - Mailbox Scanner"
            assert submission.root.tool_instance == collector.fqdn
            assert submission.root.alert_type == ANALYSIS_TYPE_MAILBOX

            assert len(submission.root.observables) == 1
            file_observable = submission.root.observables[0]
            assert DIRECTIVE_NO_SCAN in file_observable.directives
            assert DIRECTIVE_ORIGINAL_EMAIL in file_observable.directives
            assert DIRECTIVE_ARCHIVE in file_observable.directives

    def test_collect_blacklisted_email(self, collector, mock_s3_client, tmpdir):
        """Test collect method with blacklisted email."""
        mock_s3_client.list_objects_v2.return_value = {"Contents": [{"Key": "blacklisted-email.eml"}]}

        with patch("saq.collectors.email.journal.get_temp_dir") as mock_get_temp_dir, \
             patch("saq.collectors.email.journal.uuid4") as mock_uuid4, \
             patch("saq.collectors.email.journal.delete_file") as mock_delete_file, \
             patch.object(collector, "is_blacklisted") as mock_is_blacklisted:

            mock_get_temp_dir.return_value = str(tmpdir)
            mock_uuid4.return_value = "email-uuid"
            mock_is_blacklisted.return_value = True

            mock_s3_client.download_file.return_value = None

            submissions = list(collector.collect())

            assert len(submissions) == 0
            mock_delete_file.assert_called_once()

    def test_collect_with_s3_deletion_enabled(self, collector, mock_s3_client, tmpdir, mock_config, monkeypatch):
        """Test collect method with S3 object deletion enabled."""
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "delete_s3_objects", True)

        mock_s3_client.list_objects_v2.return_value = {"Contents": [{"Key": "test-email.eml"}]}

        email_content = b"From: test@example.com\nSubject: Test\n\nTest email"
        email_path = str(tmpdir.join("test_email.eml"))

        with open(email_path, "wb") as f:
            f.write(email_content)

        with patch("saq.collectors.email.journal.get_temp_dir") as mock_get_temp_dir, \
             patch("saq.collectors.email.journal.uuid4") as mock_uuid4, \
             patch("saq.collectors.email.journal.local_time") as mock_local_time, \
             patch.object(collector, "is_blacklisted") as mock_is_blacklisted:

            mock_get_temp_dir.return_value = str(tmpdir)
            mock_uuid4.side_effect = ["email-uuid", "root-uuid"]
            mock_local_time.return_value = datetime(2023, 1, 1, 12, 0, 0)
            mock_is_blacklisted.return_value = False

            def mock_download_file(bucket, key, local_path):
                with open(email_path, "rb") as src, open(local_path, "wb") as dst:
                    dst.write(src.read())

            mock_s3_client.download_file.side_effect = mock_download_file

            submissions = list(collector.collect())

            assert len(submissions) == 1

            mock_s3_client.delete_object.assert_called_once_with(
                Bucket="journal-emails", Key="test-email.eml"
            )

    def test_collect_s3_deletion_failure(self, collector, mock_s3_client, tmpdir, mock_config, monkeypatch):
        """Test collect method handles S3 deletion failures gracefully."""
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "delete_s3_objects", True)

        mock_s3_client.list_objects_v2.return_value = {"Contents": [{"Key": "test-email.eml"}]}

        email_content = b"From: test@example.com\nSubject: Test\n\nTest email"
        email_path = str(tmpdir.join("test_email.eml"))

        with open(email_path, "wb") as f:
            f.write(email_content)

        with patch("saq.collectors.email.journal.get_temp_dir") as mock_get_temp_dir, \
             patch("saq.collectors.email.journal.uuid4") as mock_uuid4, \
             patch("saq.collectors.email.journal.local_time") as mock_local_time, \
             patch.object(collector, "is_blacklisted") as mock_is_blacklisted:

            mock_get_temp_dir.return_value = str(tmpdir)
            mock_uuid4.side_effect = ["email-uuid", "root-uuid"]
            mock_local_time.return_value = datetime(2023, 1, 1, 12, 0, 0)
            mock_is_blacklisted.return_value = False

            def mock_download_file(bucket, key, local_path):
                with open(email_path, "rb") as src, open(local_path, "wb") as dst:
                    dst.write(src.read())

            mock_s3_client.download_file.side_effect = mock_download_file
            mock_s3_client.delete_object.side_effect = Exception("Deletion failed")

            submissions = list(collector.collect())

            # should still return submission despite deletion failure
            assert len(submissions) == 1

    def test_collect_list_objects_failure(self, collector, mock_s3_client):
        """Test collect method handles list_objects failure gracefully."""
        mock_s3_client.list_objects_v2.side_effect = Exception("Connection failed")

        submissions = list(collector.collect())

        assert len(submissions) == 0

    def test_collect_download_failure(self, collector, mock_s3_client, tmpdir):
        """Test collect method handles download failure gracefully and continues to next object."""
        mock_s3_client.list_objects_v2.return_value = {"Contents": [{"Key": "fail-email.eml"}, {"Key": "success-email.eml"}]}

        email_content = b"From: test@example.com\nSubject: Test\n\nTest email"
        email_path = str(tmpdir.join("test_email.eml"))

        with open(email_path, "wb") as f:
            f.write(email_content)

        with patch("saq.collectors.email.journal.get_temp_dir") as mock_get_temp_dir, \
             patch("saq.collectors.email.journal.uuid4") as mock_uuid4, \
             patch("saq.collectors.email.journal.local_time") as mock_local_time, \
             patch.object(collector, "is_blacklisted") as mock_is_blacklisted:

            mock_get_temp_dir.return_value = str(tmpdir)
            mock_uuid4.side_effect = ["email-uuid-1", "email-uuid-2", "root-uuid"]
            mock_local_time.return_value = datetime(2023, 1, 1, 12, 0, 0)
            mock_is_blacklisted.return_value = False

            call_count = 0
            def mock_download_file(bucket, key, local_path):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    raise Exception("Download failed")
                with open(email_path, "rb") as src, open(local_path, "wb") as dst:
                    dst.write(src.read())

            mock_s3_client.download_file.side_effect = mock_download_file

            submissions = list(collector.collect())

            # only the second object should produce a submission
            assert len(submissions) == 1
            assert submissions[0].key == "success-email.eml"

    def test_collect_blacklisted_email_deleted_from_s3(self, collector, mock_s3_client, tmpdir, mock_config, monkeypatch):
        """Test that blacklisted emails are also deleted from S3 when deletion is enabled."""
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "delete_s3_objects", True)

        mock_s3_client.list_objects_v2.return_value = {"Contents": [{"Key": "blacklisted-email.eml"}]}

        with patch("saq.collectors.email.journal.get_temp_dir") as mock_get_temp_dir, \
             patch("saq.collectors.email.journal.uuid4") as mock_uuid4, \
             patch("saq.collectors.email.journal.delete_file") as mock_delete_file, \
             patch.object(collector, "is_blacklisted") as mock_is_blacklisted:

            mock_get_temp_dir.return_value = str(tmpdir)
            mock_uuid4.return_value = "email-uuid"
            mock_is_blacklisted.return_value = True
            mock_s3_client.download_file.return_value = None

            submissions = list(collector.collect())

            assert len(submissions) == 0
            mock_delete_file.assert_called_once()
            mock_s3_client.delete_object.assert_called_once_with(Bucket="journal-emails", Key="blacklisted-email.eml")
