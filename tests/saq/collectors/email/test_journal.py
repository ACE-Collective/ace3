from datetime import datetime
from unittest.mock import Mock, patch

import pytest

from saq.collectors.email.journal import JournalEmailCollector
from saq.configuration import get_config
from saq.configuration.config import get_service_config
from saq.constants import ANALYSIS_MODE_EMAIL, ANALYSIS_TYPE_MAILBOX, DIRECTIVE_ARCHIVE, DIRECTIVE_NO_SCAN, DIRECTIVE_ORIGINAL_EMAIL, SERVICE_JOURNAL_EMAIL_COLLECTOR


pytestmark = pytest.mark.unit


class TestJournalEmailCollectorS3:
    """Test suite for JournalEmailCollector with S3 source."""

    @pytest.fixture
    def mock_config(self, monkeypatch):
        """Mock configuration values for S3 source."""
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "blacklist_yara_rule_path", "/tmp/blacklist.yara")
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "blacklist_yara_rule_check_frequency", 60)
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "delete_s3_objects", False)
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "bucket_name", "journal-emails")
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "source", "s3")

    @pytest.fixture
    def mock_s3_client(self):
        """Mock S3 client."""
        with patch("saq.collectors.email.journal.get_s3_client", create=True) as mock_get_s3_client:
            mock_client = Mock()
            mock_get_s3_client.return_value = mock_client
            yield mock_client

    @pytest.fixture
    def collector(self, mock_config, mock_s3_client):
        """Create a JournalEmailCollector instance with mocked S3 dependencies."""
        with patch("saq.collectors.email.journal.local_time") as mock_local_time:
            mock_local_time.return_value = datetime(2023, 1, 1, 12, 0, 0)
            # patch the s3 import inside the collector __init__
            with patch("saq.storage.s3.get_s3_client", return_value=mock_s3_client):
                collector = JournalEmailCollector()
                collector.fqdn = "test.example.com"
                return collector

    def test_init(self, collector, mock_s3_client):
        """Test collector initialization with S3 source."""
        assert collector.client == mock_s3_client
        assert collector.blacklist_yara_rule_path == "/tmp/blacklist.yara"
        assert collector.blacklist_yara_rule_check_frequency == 60
        assert collector.yara_context is None
        assert collector.bucket_name == "journal-emails"
        assert collector.source == "s3"

    def test_collect_empty_bucket(self, collector, mock_s3_client):
        """Test collect method with empty bucket."""
        mock_s3_client.list_objects_v2.return_value = {}

        submissions = list(collector.collect())

        assert len(submissions) == 0
        mock_s3_client.list_objects_v2.assert_called_once_with(Bucket="journal-emails")

    def test_collect_single_object(self, collector, mock_s3_client, tmpdir):
        """Test collect method with single object in bucket."""
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

    def test_collect_list_objects_failure(self, collector, mock_s3_client):
        """Test collect method handles list_objects failure gracefully."""
        mock_s3_client.list_objects_v2.side_effect = Exception("Connection failed")

        submissions = list(collector.collect())

        assert len(submissions) == 0


class TestJournalEmailCollectorLocal:
    """Test suite for JournalEmailCollector with local source."""

    @pytest.fixture
    def mock_config(self, monkeypatch, tmpdir):
        """Mock configuration values for local source."""
        source_dir = str(tmpdir.join("journal-emails"))
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "blacklist_yara_rule_path", "/tmp/blacklist.yara")
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "blacklist_yara_rule_check_frequency", 60)
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "source", "local")
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "source_directory", source_dir)
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "delete_files", True)
        return source_dir

    @pytest.fixture
    def collector(self, mock_config):
        """Create a JournalEmailCollector instance for local source."""
        with patch("saq.collectors.email.journal.local_time") as mock_local_time:
            mock_local_time.return_value = datetime(2023, 1, 1, 12, 0, 0)
            collector = JournalEmailCollector()
            collector.fqdn = "test.example.com"
            return collector

    def test_init_local(self, collector, mock_config):
        """Test collector initialization with local source."""
        assert collector.source == "local"
        assert collector.source_directory == mock_config
        assert not hasattr(collector, "client")

    def test_collect_empty_directory(self, collector, mock_config):
        """Test collect with empty source directory."""
        import os
        os.makedirs(mock_config, exist_ok=True)

        submissions = list(collector.collect())
        assert len(submissions) == 0

    def test_collect_nonexistent_directory(self, collector):
        """Test collect with nonexistent source directory."""
        submissions = list(collector.collect())
        assert len(submissions) == 0

    def test_collect_single_file(self, collector, mock_config, tmpdir):
        """Test collect method with a single file in the directory."""
        import os
        os.makedirs(mock_config, exist_ok=True)

        # create a test email file
        email_content = b"From: test@example.com\nSubject: Test\n\nTest email"
        email_file = os.path.join(mock_config, "test-email.eml")
        with open(email_file, "wb") as f:
            f.write(email_content)

        with patch("saq.collectors.email.journal.get_temp_dir") as mock_get_temp_dir, \
             patch("saq.collectors.email.journal.uuid4") as mock_uuid4, \
             patch("saq.collectors.email.journal.local_time") as mock_local_time, \
             patch.object(collector, "is_blacklisted") as mock_is_blacklisted:

            mock_get_temp_dir.return_value = str(tmpdir)
            mock_uuid4.side_effect = ["email-uuid", "root-uuid"]
            mock_local_time.return_value = datetime(2023, 1, 1, 12, 0, 0)
            mock_is_blacklisted.return_value = False

            submissions = list(collector.collect())

            assert len(submissions) == 1
            submission = submissions[0]

            assert submission.key == "test-email.eml"
            assert submission.root.description == "ACE Mailbox Scanner Detection"
            assert submission.root.analysis_mode == ANALYSIS_MODE_EMAIL

            # source file should be deleted since delete_files is True
            assert not os.path.exists(email_file)

    def test_collect_no_delete(self, collector, mock_config, tmpdir, monkeypatch):
        """Test collect method with delete_files disabled."""
        import os
        os.makedirs(mock_config, exist_ok=True)
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "delete_files", False)

        email_content = b"From: test@example.com\nSubject: Test\n\nTest email"
        email_file = os.path.join(mock_config, "test-email.eml")
        with open(email_file, "wb") as f:
            f.write(email_content)

        with patch("saq.collectors.email.journal.get_temp_dir") as mock_get_temp_dir, \
             patch("saq.collectors.email.journal.uuid4") as mock_uuid4, \
             patch("saq.collectors.email.journal.local_time") as mock_local_time, \
             patch.object(collector, "is_blacklisted") as mock_is_blacklisted:

            mock_get_temp_dir.return_value = str(tmpdir)
            mock_uuid4.side_effect = ["email-uuid", "root-uuid"]
            mock_local_time.return_value = datetime(2023, 1, 1, 12, 0, 0)
            mock_is_blacklisted.return_value = False

            submissions = list(collector.collect())

            assert len(submissions) == 1
            # source file should still exist
            assert os.path.exists(email_file)

    def test_collect_blacklisted_email(self, collector, mock_config, tmpdir):
        """Test collect method with blacklisted email in local directory."""
        import os
        os.makedirs(mock_config, exist_ok=True)

        email_content = b"From: test@example.com\nSubject: Test\n\nTest email"
        email_file = os.path.join(mock_config, "blacklisted.eml")
        with open(email_file, "wb") as f:
            f.write(email_content)

        with patch("saq.collectors.email.journal.get_temp_dir") as mock_get_temp_dir, \
             patch("saq.collectors.email.journal.uuid4") as mock_uuid4, \
             patch("saq.collectors.email.journal.delete_file") as mock_delete_file, \
             patch.object(collector, "is_blacklisted") as mock_is_blacklisted:

            mock_get_temp_dir.return_value = str(tmpdir)
            mock_uuid4.return_value = "email-uuid"
            mock_is_blacklisted.return_value = True

            submissions = list(collector.collect())

            assert len(submissions) == 0
            mock_delete_file.assert_called_once()
            # source file should also be deleted
            assert not os.path.exists(email_file)

    def test_collect_multiple_files(self, collector, mock_config, tmpdir):
        """Test collect method with multiple files in directory."""
        import os
        os.makedirs(mock_config, exist_ok=True)

        for i in range(3):
            email_file = os.path.join(mock_config, f"email-{i}.eml")
            with open(email_file, "wb") as f:
                f.write(f"From: test{i}@example.com\nSubject: Test {i}\n\nTest email {i}".encode())

        with patch("saq.collectors.email.journal.get_temp_dir") as mock_get_temp_dir, \
             patch("saq.collectors.email.journal.uuid4") as mock_uuid4, \
             patch("saq.collectors.email.journal.local_time") as mock_local_time, \
             patch.object(collector, "is_blacklisted") as mock_is_blacklisted:

            mock_get_temp_dir.return_value = str(tmpdir)
            mock_uuid4.side_effect = [f"uuid-{i}" for i in range(6)]
            mock_local_time.return_value = datetime(2023, 1, 1, 12, 0, 0)
            mock_is_blacklisted.return_value = False

            submissions = list(collector.collect())

            assert len(submissions) == 3


class TestJournalEmailCollectorCommon:
    """Tests for shared functionality (blacklist logic) that applies to both sources."""

    @pytest.fixture
    def mock_config(self, monkeypatch, tmpdir):
        """Mock configuration values."""
        source_dir = str(tmpdir.join("journal-emails"))
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "blacklist_yara_rule_path", "/tmp/blacklist.yara")
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "blacklist_yara_rule_check_frequency", 60)
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "source", "local")
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "source_directory", source_dir)
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "delete_files", True)

    @pytest.fixture
    def collector(self, mock_config):
        """Create a JournalEmailCollector instance."""
        with patch("saq.collectors.email.journal.local_time") as mock_local_time:
            mock_local_time.return_value = datetime(2023, 1, 1, 12, 0, 0)
            collector = JournalEmailCollector()
            collector.fqdn = "test.example.com"
            return collector

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
            mock_getmtime.return_value = 2000

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
