import pytest
from unittest.mock import Mock
from datetime import datetime

from minio import Minio
from minio.api import Object as MinioObject
from minio.api import DeleteObject
import yara

from saq.collectors.email.journal import JournalEmailCollector, JournalEmailCollectorService
from saq.analysis.root import Submission
from saq.constants import ANALYSIS_MODE_EMAIL, ANALYSIS_TYPE_MAILBOX, G_TEMP_DIR, CONFIG_JOURNAL_EMAIL_COLLECTOR


@pytest.fixture
def mock_minio_client():
    """Mock Minio client for testing."""
    mock_client = Mock(spec=Minio)
    mock_client.bucket_exists.return_value = True
    mock_client.make_bucket = Mock()
    mock_client.list_objects.return_value = []
    mock_client.fget_object = Mock()
    mock_client.remove_objects.return_value = []
    return mock_client


@pytest.fixture
def mock_s3_object():
    """Mock S3 object for testing."""
    mock_obj = Mock(spec=MinioObject)
    mock_obj.object_name = "test_email.rfc822"
    mock_obj.etag = "mock_etag"
    mock_obj.size = 1024
    mock_obj.last_modified = datetime.now()
    return mock_obj


@pytest.fixture
def sample_email_content():
    """Sample email content for testing."""
    return b"""Return-Path: <sender@example.com>
Delivered-To: recipient@example.com
Received: by mail.example.com
    for <recipient@example.com>; Wed, 1 Jan 2024 12:00:00 -0500 (EST)
Message-ID: <12345@example.com>
Date: Wed, 1 Jan 2024 12:00:00 -0500
From: sender@example.com
To: recipient@example.com
Subject: Test Email Subject

This is a test email body.
"""


@pytest.fixture
def temp_yara_rule(tmpdir):
    """Create a temporary YARA rule file for testing."""
    yara_content = """
rule test_rule : blacklist {
    strings:
        $test = "malicious"
    condition:
        $test
}

rule whitelist_rule {
    strings:
        $safe = "safe"
    condition:
        $safe
}
"""
    yara_file = tmpdir.join("test_rules.yara")
    yara_file.write(yara_content)
    return str(yara_file)


@pytest.fixture
def blacklist_yara_rule(tmpdir):
    """Create a YARA rule specifically for blacklisting."""
    yara_content = """
rule blacklist_rule : blacklist {
    strings:
        $spam = "SPAM"
        $phishing = "phishing"
    condition:
        any of them
}
"""
    yara_file = tmpdir.join("blacklist_rules.yara")
    yara_file.write(yara_content)
    return str(yara_file)


def setup_mock_config(monkeypatch, mock_minio_client, yara_rule_path="", check_frequency=300):
    """Helper to set up common mock configuration."""
    monkeypatch.setattr("saq.collectors.email.journal.get_minio_client", lambda: mock_minio_client)
    
    def mock_get_config_value(section, key, default=None):
        config_values = {
            "s3_bucket": "test-bucket",
            "s3_prefix": "emails/",
            "blacklist_yara_rule_path": yara_rule_path,
            "blacklist_yara_rule_check_frequency": str(check_frequency)
        }
        return config_values.get(key, default)
    
    monkeypatch.setattr("saq.collectors.email.journal.get_config_value", mock_get_config_value)
    monkeypatch.setattr("saq.collectors.email.journal.get_config_value_as_int", 
                      lambda section, key: check_frequency)


class TestJournalEmailCollector:

    @pytest.mark.unit
    def test_init_creates_bucket_if_not_exists(self, monkeypatch, mock_minio_client):
        """Test that collector creates S3 bucket if it doesn't exist."""
        mock_minio_client.bucket_exists.return_value = False
        setup_mock_config(monkeypatch, mock_minio_client)
        
        collector = JournalEmailCollector()
        
        mock_minio_client.bucket_exists.assert_called_once_with("test-bucket")
        mock_minio_client.make_bucket.assert_called_once_with("test-bucket")

    @pytest.mark.unit
    def test_init_does_not_create_bucket_if_exists(self, monkeypatch, mock_minio_client):
        """Test that collector doesn't create bucket if it already exists."""
        mock_minio_client.bucket_exists.return_value = True
        setup_mock_config(monkeypatch, mock_minio_client)
        
        collector = JournalEmailCollector()
        
        mock_minio_client.bucket_exists.assert_called_once_with("test-bucket")
        mock_minio_client.make_bucket.assert_not_called()

    @pytest.mark.unit
    def test_should_load_blacklist_yara_rule_no_path(self, monkeypatch, mock_minio_client):
        """Test should_load_blacklist_yara_rule returns False when no path configured."""
        setup_mock_config(monkeypatch, mock_minio_client, yara_rule_path="")
        
        collector = JournalEmailCollector()
        assert not collector.should_load_blacklist_yara_rule()

    @pytest.mark.unit
    def test_should_load_blacklist_yara_rule_file_not_exists(self, monkeypatch, mock_minio_client):
        """Test should_load_blacklist_yara_rule returns False when file doesn't exist."""
        setup_mock_config(monkeypatch, mock_minio_client, yara_rule_path="/nonexistent/path.yara")
        
        collector = JournalEmailCollector()
        assert not collector.should_load_blacklist_yara_rule()

    @pytest.mark.unit
    def test_should_load_blacklist_yara_rule_first_load(self, monkeypatch, mock_minio_client, temp_yara_rule):
        """Test should_load_blacklist_yara_rule returns True for first load."""
        setup_mock_config(monkeypatch, mock_minio_client, yara_rule_path=temp_yara_rule)
        
        collector = JournalEmailCollector()
        assert collector.should_load_blacklist_yara_rule()

    @pytest.mark.unit
    def test_should_load_blacklist_yara_rule_within_frequency(self, monkeypatch, mock_minio_client, temp_yara_rule):
        """Test should_load_blacklist_yara_rule respects check frequency."""
        setup_mock_config(monkeypatch, mock_minio_client, yara_rule_path=temp_yara_rule, check_frequency=300)
        
        collector = JournalEmailCollector()
        # Load rule first time
        collector.load_blacklist_yara_rule()
        
        # Should not reload within frequency window
        assert not collector.should_load_blacklist_yara_rule()

    @pytest.mark.unit
    def test_load_blacklist_yara_rule(self, monkeypatch, mock_minio_client, temp_yara_rule):
        """Test loading YARA rule from file."""
        setup_mock_config(monkeypatch, mock_minio_client, yara_rule_path=temp_yara_rule)
        
        collector = JournalEmailCollector()
        collector.load_blacklist_yara_rule()
        
        assert collector.yara_context is not None
        assert isinstance(collector.yara_context, yara.Rules)

    @pytest.mark.unit
    def test_is_blacklisted_no_yara_context(self, monkeypatch, mock_minio_client, tmpdir):
        """Test is_blacklisted returns False when no YARA context."""
        setup_mock_config(monkeypatch, mock_minio_client, yara_rule_path="")
        
        collector = JournalEmailCollector()
        
        test_file = tmpdir.join("test_email.txt")
        test_file.write("test content")
        
        assert not collector.is_blacklisted(str(test_file))

    @pytest.mark.unit
    def test_is_blacklisted_with_blacklist_tag(self, monkeypatch, mock_minio_client, blacklist_yara_rule, tmpdir):
        """Test is_blacklisted returns True when email matches blacklist rule."""
        setup_mock_config(monkeypatch, mock_minio_client, yara_rule_path=blacklist_yara_rule)
        
        collector = JournalEmailCollector()
        collector.load_blacklist_yara_rule()
        
        # Create test file with content that matches blacklist rule
        test_file = tmpdir.join("spam_email.txt")
        test_file.write("This is SPAM content")
        
        assert collector.is_blacklisted(str(test_file))

    @pytest.mark.unit
    def test_is_blacklisted_no_match(self, monkeypatch, mock_minio_client, blacklist_yara_rule, tmpdir):
        """Test is_blacklisted returns False when email doesn't match blacklist rule."""
        setup_mock_config(monkeypatch, mock_minio_client, yara_rule_path=blacklist_yara_rule)
        
        collector = JournalEmailCollector()
        collector.load_blacklist_yara_rule()
        
        # Create test file with content that doesn't match blacklist rule
        test_file = tmpdir.join("safe_email.txt")
        test_file.write("This is a safe email")
        
        assert not collector.is_blacklisted(str(test_file))

    @pytest.mark.unit
    def test_collect_no_emails(self, monkeypatch, mock_minio_client):
        """Test collect method when no emails are present."""
        mock_minio_client.list_objects.return_value = []
        setup_mock_config(monkeypatch, mock_minio_client)
        
        collector = JournalEmailCollector()
        submissions = list(collector.collect())
        
        assert len(submissions) == 0
        mock_minio_client.list_objects.assert_called_once_with("test-bucket", "emails/", include_user_meta=True)

    @pytest.mark.unit
    def test_collect_single_email_not_blacklisted(self, monkeypatch, mock_minio_client, mock_s3_object, tmpdir, sample_email_content):
        """Test collect method with single non-blacklisted email."""
        mock_minio_client.list_objects.return_value = [mock_s3_object]
        
        # Mock file download
        def mock_fget_object(bucket, object_name, file_path):
            with open(file_path, 'wb') as f:
                f.write(sample_email_content)

        mock_minio_client.fget_object.side_effect = mock_fget_object
        
        setup_mock_config(monkeypatch, mock_minio_client)
        
        # Mock the g function for temp directory
        monkeypatch.setattr("saq.collectors.email.journal.g", lambda key: str(tmpdir) if key == G_TEMP_DIR else None)
        
        collector = JournalEmailCollector()
        collector.fqdn = "test-collector"
        
        submissions = list(collector.collect())
        
        assert len(submissions) == 1
        submission = submissions[0]
        assert isinstance(submission, Submission)
        assert submission.key == "test_email.rfc822"
        assert submission.root.analysis_mode == ANALYSIS_MODE_EMAIL
        assert submission.root.alert_type == ANALYSIS_TYPE_MAILBOX
        assert submission.root.description == "ACE Mailbox Scanner Detection"
        assert submission.root.tool == "ACE - Mailbox Scanner"
        assert submission.root.tool_instance == "test-collector"

    @pytest.mark.unit
    def test_collect_blacklisted_email_skipped(self, monkeypatch, mock_minio_client, mock_s3_object, tmpdir, blacklist_yara_rule):
        """Test collect method skips blacklisted emails."""
        mock_minio_client.list_objects.return_value = [mock_s3_object]
        
        # Mock file download with spam content
        spam_content = b"This is SPAM content in email"
        def mock_fget_object(bucket, object_name, file_path):
            with open(file_path, 'wb') as f:
                f.write(spam_content)

        mock_minio_client.fget_object.side_effect = mock_fget_object
        
        setup_mock_config(monkeypatch, mock_minio_client, yara_rule_path=blacklist_yara_rule)
        
        # Mock the g function for temp directory
        monkeypatch.setattr("saq.collectors.email.journal.g", lambda key: str(tmpdir) if key == G_TEMP_DIR else None)
        
        collector = JournalEmailCollector()
        submissions = list(collector.collect())
        
        assert len(submissions) == 0  # Email should be blacklisted and skipped

    @pytest.mark.unit
    def test_collect_removes_processed_emails(self, monkeypatch, mock_minio_client, mock_s3_object, tmpdir, sample_email_content):
        """Test collect method removes emails from S3 after processing."""
        mock_minio_client.list_objects.return_value = [mock_s3_object]
        
        # Mock file download
        def mock_fget_object(bucket, object_name, file_path):
            with open(file_path, 'wb') as f:
                f.write(sample_email_content)

        mock_minio_client.fget_object.side_effect = mock_fget_object
        
        setup_mock_config(monkeypatch, mock_minio_client)
        
        # Mock the g function for temp directory
        monkeypatch.setattr("saq.collectors.email.journal.g", lambda key: str(tmpdir) if key == G_TEMP_DIR else None)
        
        collector = JournalEmailCollector()
        collector.fqdn = "test-collector"
        
        submissions = list(collector.collect())
        
        # Verify remove_objects was called
        mock_minio_client.remove_objects.assert_called_once()
        call_args = mock_minio_client.remove_objects.call_args
        assert call_args[0][0] == "test-bucket"  # bucket name
        delete_objects = call_args[0][1]
        assert len(delete_objects) == 1
        assert isinstance(delete_objects[0], DeleteObject)
        assert delete_objects[0].name == "test_email.rfc822"

    @pytest.mark.unit
    def test_collect_multiple_emails_mixed_blacklist(self, monkeypatch, mock_minio_client, tmpdir, blacklist_yara_rule, sample_email_content):
        """Test collect method with multiple emails, some blacklisted."""
        # Create multiple mock objects
        mock_obj1 = Mock(spec=MinioObject)
        mock_obj1.object_name = "email1.rfc822"
        mock_obj2 = Mock(spec=MinioObject) 
        mock_obj2.object_name = "spam_email.rfc822"
        mock_obj3 = Mock(spec=MinioObject)
        mock_obj3.object_name = "email3.rfc822"
        
        mock_minio_client.list_objects.return_value = [mock_obj1, mock_obj2, mock_obj3]
        
        # Mock file download - spam content for second email
        def mock_fget_object(bucket, object_name, file_path):
            if "spam" in object_name:
                content = b"This is SPAM content"
            else:
                content = sample_email_content
            with open(file_path, 'wb') as f:
                f.write(content)

        mock_minio_client.fget_object.side_effect = mock_fget_object
        
        setup_mock_config(monkeypatch, mock_minio_client, yara_rule_path=blacklist_yara_rule)
        
        # Mock the g function for temp directory
        monkeypatch.setattr("saq.collectors.email.journal.g", lambda key: str(tmpdir) if key == G_TEMP_DIR else None)
        
        collector = JournalEmailCollector()
        collector.fqdn = "test-collector"
        
        submissions = list(collector.collect())
        
        # Should have 2 submissions (spam email blacklisted)
        assert len(submissions) == 2
        submission_keys = [s.key for s in submissions]
        assert "email1.rfc822" in submission_keys
        assert "email3.rfc822" in submission_keys
        assert "spam_email.rfc822" not in submission_keys

    @pytest.mark.unit  
    def test_collect_handles_remove_objects_errors(self, monkeypatch, mock_minio_client, mock_s3_object, tmpdir, sample_email_content):
        """Test collect method handles errors when removing objects from S3."""
        mock_minio_client.list_objects.return_value = [mock_s3_object]
        
        # Mock file download
        def mock_fget_object(bucket, object_name, file_path):
            with open(file_path, 'wb') as f:
                f.write(sample_email_content)

        mock_minio_client.fget_object.side_effect = mock_fget_object
        
        # Mock remove_objects to return error
        mock_error = Mock()
        mock_error.object_name = "test_email.rfc822"
        mock_error.error = "Permission denied"
        mock_minio_client.remove_objects.return_value = [mock_error]
        
        setup_mock_config(monkeypatch, mock_minio_client)
        
        # Mock the g function for temp directory
        monkeypatch.setattr("saq.collectors.email.journal.g", lambda key: str(tmpdir) if key == G_TEMP_DIR else None)
        
        collector = JournalEmailCollector()
        collector.fqdn = "test-collector"
        
        # Should not raise exception despite delete error
        submissions = list(collector.collect())
        assert len(submissions) == 1
