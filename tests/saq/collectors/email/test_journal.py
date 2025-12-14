import json
from datetime import datetime
from queue import Empty, Queue
from unittest.mock import Mock, patch

import pytest

from saq.collectors.email.journal import JournalEmailCollector, JournalEmailMessageLocation
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
        monkeypatch.setattr(get_config().rabbitmq, "username", "test_user")
        monkeypatch.setattr(get_config().rabbitmq, "password", "test_password")
        monkeypatch.setattr(get_config().rabbitmq, "host", "test_host")
        monkeypatch.setattr(get_config().rabbitmq, "port", 5672)

    @pytest.fixture
    def mock_minio_client(self):
        """Mock Minio client."""
        with patch("saq.collectors.email.journal.get_minio_client") as mock_get_minio_client:
            mock_client = Mock()
            mock_get_minio_client.return_value = mock_client
            yield mock_client

    @pytest.fixture
    def mock_pika(self):
        """Mock pika connection and channel."""
        mock_connection = Mock()
        mock_channel = Mock()
        mock_queue_result = Mock()
        mock_queue_result.method.queue = "test_queue"

        mock_channel.queue_declare.return_value = mock_queue_result
        mock_connection.channel.return_value = mock_channel

        with patch("saq.collectors.email.journal.pika") as mock_pika:
            mock_pika.PlainCredentials.return_value = Mock()
            mock_pika.ConnectionParameters.return_value = Mock()
            mock_pika.BlockingConnection.return_value = mock_connection

            yield {
                "pika": mock_pika,
                "connection": mock_connection,
                "channel": mock_channel,
                "queue_result": mock_queue_result,
            }

    @pytest.fixture
    def collector(self, mock_config, mock_minio_client):
        """Create a JournalEmailCollector instance with mocked dependencies."""
        with patch("saq.collectors.email.journal.local_time") as mock_local_time:
            mock_local_time.return_value = datetime(2023, 1, 1, 12, 0, 0)
            collector = JournalEmailCollector()
            collector.fqdn = "test.example.com"
            return collector

    def test_init(self, collector, mock_minio_client):
        """Test collector initialization."""
        assert isinstance(collector.message_queue, Queue)
        assert collector.consumer_loop_shutdown is False
        assert collector.client == mock_minio_client
        assert collector.blacklist_yara_rule_path == "/tmp/blacklist.yara"
        assert collector.blacklist_yara_rule_check_frequency == 60
        assert collector.yara_context is None

    def test_connect_success(self, collector, mock_pika):
        """Test successful connection to RabbitMQ."""
        result = collector.connect()

        assert result is True
        assert collector.connection == mock_pika["connection"]
        assert collector.channel == mock_pika["channel"]
        assert collector.queue_name == "test_queue"

        # Verify proper setup calls
        mock_pika["channel"].exchange_declare.assert_called_once_with(
            exchange="minio-events",
            exchange_type="topic",
            durable=True
        )
        mock_pika["channel"].queue_declare.assert_called_once_with(queue="journal")
        mock_pika["channel"].queue_bind.assert_called_once_with(
            exchange="minio-events",
            queue="test_queue",
            routing_key="minio.object.*"
        )

    def test_handle_object_created(self, collector):
        """Test handling of object created events."""
        bucket_name = "test-bucket"
        object_key = "test-key"
        object_size = 1024
        event_time = "2023-01-01T12:00:00Z"

        collector.handle_object_created(bucket_name, object_key, object_size, event_time)

        # Verify message was added to queue
        message = collector.message_queue.get_nowait()
        assert isinstance(message, JournalEmailMessageLocation)
        assert message.bucket_name == bucket_name
        assert message.object_key == object_key
        assert message.object_size == object_size
        assert message.event_time == event_time

    def test_process_message_object_created(self, collector):
        """Test processing of S3 object created notification."""
        notification = {
            "EventName": "s3:ObjectCreated:Put",
            "Records": [{
                "s3": {
                    "bucket": {"name": "test-bucket"},
                    "object": {"key": "test-key", "size": 2048}
                },
                "eventTime": "2023-01-01T12:00:00Z"
            }]
        }

        body = json.dumps(notification).encode("utf-8")
        result = collector.process_message(body)

        assert result is True

        # Verify message was added to queue
        message = collector.message_queue.get_nowait()
        assert message.bucket_name == "test-bucket"
        assert message.object_key == "test-key"
        assert message.object_size == 2048
        assert message.event_time == "2023-01-01T12:00:00Z"

    def test_process_message_unhandled_event(self, collector):
        """Test processing of unhandled event types."""
        notification = {
            "EventName": "s3:ObjectRemoved:Delete",
            "Records": [{
                "s3": {
                    "bucket": {"name": "test-bucket"},
                    "object": {"key": "test-key", "size": 1024}
                },
                "eventTime": "2023-01-01T12:00:00Z"
            }]
        }

        body = json.dumps(notification).encode("utf-8")
        result = collector.process_message(body)

        assert result is True

        # Verify no message was added to queue
        with pytest.raises(Empty):
            collector.message_queue.get_nowait()

    def test_process_message_malformed(self, collector):
        """Test processing of malformed notification."""
        notification = {"EventName": "s3:ObjectCreated:Put"}  # Missing Records

        body = json.dumps(notification).encode("utf-8")
        result = collector.process_message(body)

        assert result is True

        # Should handle gracefully and add message with default values
        message = collector.message_queue.get_nowait()
        assert message.bucket_name == "unknown"
        assert message.object_key == "unknown"
        assert message.object_size == 0
        assert message.event_time == "unknown"

    def test_consumer_loop_connect_and_consume(self, collector, mock_pika):
        """Test consumer loop connects and starts consuming."""
        # Setup to exit after first iteration
        collector.consumer_loop_shutdown = True
        mock_pika["channel"].start_consuming.side_effect = lambda: None

        collector.consumer_loop()

        # Verify connection setup
        assert collector.connection == mock_pika["connection"]
        assert collector.channel == mock_pika["channel"]
        mock_pika["channel"].basic_consume.assert_called_once()
        mock_pika["channel"].start_consuming.assert_called_once()

    def test_consumer_loop_handles_exceptions(self, collector, mock_pika):
        """Test consumer loop handles connection exceptions."""
        # First call raises exception, second call succeeds but loop exits
        mock_pika["pika"].BlockingConnection.side_effect = [
            Exception("Connection failed"),
            mock_pika["connection"]
        ]

        # Set shutdown flag to exit after handling exception
        def set_shutdown():
            collector.consumer_loop_shutdown = True

        mock_pika["channel"].start_consuming.side_effect = set_shutdown

        with patch("saq.collectors.email.journal.time.sleep") as mock_sleep, \
             patch("saq.collectors.email.journal.report_exception") as mock_report:

            collector.consumer_loop()

            # Verify exception was reported and sleep was called
            mock_report.assert_called_once()
            mock_sleep.assert_called_once_with(1)

    def test_stop_consumer_loop(self, collector, mock_pika):
        """Test stopping the consumer loop."""
        collector.channel = mock_pika["channel"]
        collector.consumer_tag = "test_consumer_tag"

        collector.stop_consumer_loop()

        assert collector.consumer_loop_shutdown is True
        mock_pika["channel"].connection.add_callback_threadsafe.assert_called_once()

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
            # Current time is within check frequency
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

    def test_collect_empty_queue(self, collector):
        """Test collect method with empty message queue."""
        submissions = list(collector.collect())

        assert len(submissions) == 0

    def test_collect_single_message(self, collector, mock_minio_client, tmpdir):
        """Test collect method with single message."""
        # Setup message in queue
        message = JournalEmailMessageLocation(
            bucket_name="test-bucket",
            object_key="test-email.eml",
            object_size=1024,
            event_time="2023-01-01T12:00:00Z"
        )
        collector.message_queue.put(message)

        # Mock file operations
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

            # Mock minio client to copy test file to expected location
            def mock_fget_object(bucket, key, local_path):
                with open(email_path, "rb") as src, open(local_path, "wb") as dst:
                    dst.write(src.read())

            mock_minio_client.fget_object.side_effect = mock_fget_object

            submissions = list(collector.collect())

            assert len(submissions) == 1
            submission = submissions[0]

            # Verify submission properties
            assert submission.key == "test-email.eml"
            assert submission.root.description == "ACE Mailbox Scanner Detection"
            assert submission.root.analysis_mode == ANALYSIS_MODE_EMAIL
            assert submission.root.tool == "ACE - Mailbox Scanner"
            assert submission.root.tool_instance == collector.fqdn
            assert submission.root.alert_type == ANALYSIS_TYPE_MAILBOX

            # Verify file observable was added
            assert len(submission.root.observables) == 1
            file_observable = submission.root.observables[0]
            assert DIRECTIVE_NO_SCAN in file_observable.directives
            assert DIRECTIVE_ORIGINAL_EMAIL in file_observable.directives
            assert DIRECTIVE_ARCHIVE in file_observable.directives

    def test_collect_blacklisted_email(self, collector, mock_minio_client, tmpdir):
        """Test collect method with blacklisted email."""
        # Setup message in queue
        message = JournalEmailMessageLocation(
            bucket_name="test-bucket",
            object_key="blacklisted-email.eml",
            object_size=1024,
            event_time="2023-01-01T12:00:00Z"
        )
        collector.message_queue.put(message)

        with patch("saq.collectors.email.journal.get_temp_dir") as mock_get_temp_dir, \
             patch("saq.collectors.email.journal.uuid4") as mock_uuid4, \
             patch("saq.collectors.email.journal.delete_file") as mock_delete_file, \
             patch.object(collector, "is_blacklisted") as mock_is_blacklisted:

            mock_get_temp_dir.return_value = str(tmpdir)
            mock_uuid4.return_value = "email-uuid"
            mock_is_blacklisted.return_value = True

            # Mock minio client
            mock_minio_client.fget_object.return_value = None

            submissions = list(collector.collect())

            # Verify no submissions were generated
            assert len(submissions) == 0

            # Verify file was deleted
            mock_delete_file.assert_called_once()

    def test_collect_with_s3_deletion_enabled(self, collector, mock_minio_client, tmpdir, mock_config, monkeypatch):
        """Test collect method with S3 object deletion enabled."""
        # Enable S3 object deletion
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "delete_s3_objects", True)

        # Setup message in queue
        message = JournalEmailMessageLocation(
            bucket_name="test-bucket",
            object_key="test-email.eml",
            object_size=1024,
            event_time="2023-01-01T12:00:00Z"
        )
        collector.message_queue.put(message)

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

            # Mock minio client
            def mock_fget_object(bucket, key, local_path):
                with open(email_path, "rb") as src, open(local_path, "wb") as dst:
                    dst.write(src.read())

            mock_minio_client.fget_object.side_effect = mock_fget_object

            submissions = list(collector.collect())

            assert len(submissions) == 1

            # Verify S3 object was deleted
            mock_minio_client.remove_object.assert_called_once_with(
                "test-bucket", "test-email.eml"
            )

    def test_collect_s3_deletion_failure(self, collector, mock_minio_client, tmpdir, mock_config, monkeypatch):
        """Test collect method handles S3 deletion failures gracefully."""
        # Enable S3 object deletion
        monkeypatch.setattr(get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), "delete_s3_objects", True)

        # Setup message in queue
        message = JournalEmailMessageLocation(
            bucket_name="test-bucket",
            object_key="test-email.eml",
            object_size=1024,
            event_time="2023-01-01T12:00:00Z"
        )
        collector.message_queue.put(message)

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

            # Mock minio client with deletion failure
            def mock_fget_object(bucket, key, local_path):
                with open(email_path, "rb") as src, open(local_path, "wb") as dst:
                    dst.write(src.read())

            mock_minio_client.fget_object.side_effect = mock_fget_object
            mock_minio_client.remove_object.side_effect = Exception("Deletion failed")

            submissions = list(collector.collect())

            # Should still return submission despite deletion failure
            assert len(submissions) == 1


class TestJournalEmailMessageLocation:
    """Test suite for JournalEmailMessageLocation dataclass."""

    def test_creation(self):
        """Test creating JournalEmailMessageLocation."""
        location = JournalEmailMessageLocation(
            bucket_name="test-bucket",
            object_key="test-key",
            object_size=1024,
            event_time="2023-01-01T12:00:00Z"
        )

        assert location.bucket_name == "test-bucket"
        assert location.object_key == "test-key"
        assert location.object_size == 1024
        assert location.event_time == "2023-01-01T12:00:00Z"
