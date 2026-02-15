"""Tests for the get_s3_client function."""

from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("boto3")

from saq.storage.s3 import get_s3_client


pytestmark = pytest.mark.unit


class TestGetS3ClientAWSNative:
    """Tests for the AWS-native path when no self-hosted S3 config is present."""

    @patch("saq.storage.s3.boto3")
    @patch("saq.storage.s3.get_config")
    def test_returns_boto3_client_with_region(self, mock_get_config, mock_boto3):
        """When get_config().s3 is None, creates a boto3 client with just the region."""
        mock_get_config.return_value.s3 = None
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client

        result = get_s3_client(region="us-east-2")

        mock_boto3.client.assert_called_once_with("s3", region_name="us-east-2")
        assert result is mock_client

    @patch("saq.storage.s3.boto3")
    @patch("saq.storage.s3.get_config")
    def test_returns_boto3_client_without_region(self, mock_get_config, mock_boto3):
        """When get_config().s3 is None and no region provided, creates client with region_name=None."""
        mock_get_config.return_value.s3 = None
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client

        result = get_s3_client()

        mock_boto3.client.assert_called_once_with("s3", region_name=None)
        assert result is mock_client

    @patch("saq.storage.s3.boto3")
    @patch("saq.storage.s3.get_config")
    def test_does_not_pass_endpoint_or_credentials(self, mock_get_config, mock_boto3):
        """AWS-native path should not pass endpoint_url, access key, or secret key."""
        mock_get_config.return_value.s3 = None

        get_s3_client(region="us-west-1")

        call_kwargs = mock_boto3.client.call_args
        assert "endpoint_url" not in call_kwargs.kwargs
        assert "aws_access_key_id" not in call_kwargs.kwargs
        assert "aws_secret_access_key" not in call_kwargs.kwargs


class TestGetS3ClientSelfHosted:
    """Tests for the self-hosted S3-compatible path when S3 config is present."""

    @patch("saq.storage.s3.boto3")
    @patch("saq.storage.s3.get_config")
    def test_returns_client_with_explicit_endpoint_and_credentials(self, mock_get_config, mock_boto3):
        """When get_config().s3 exists, creates a client with explicit endpoint and credentials."""
        mock_s3_config = MagicMock()
        mock_s3_config.host = "minio.local"
        mock_s3_config.port = 9000
        mock_s3_config.access_key = "test-access-key"
        mock_s3_config.secret_key = "test-secret-key"
        mock_s3_config.secure = False
        mock_s3_config.cert_check = False
        mock_s3_config.region = "us-east-1"
        mock_get_config.return_value.s3 = mock_s3_config

        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client

        result = get_s3_client()

        call_kwargs = mock_boto3.client.call_args.kwargs
        assert mock_boto3.client.call_args.args == ("s3",)
        assert call_kwargs["endpoint_url"] == "http://minio.local:9000"
        assert call_kwargs["aws_access_key_id"] == "test-access-key"
        assert call_kwargs["aws_secret_access_key"] == "test-secret-key"
        assert call_kwargs["region_name"] == "us-east-1"
        assert call_kwargs["verify"] is False
        assert result is mock_client

    @pytest.mark.parametrize("secure,expected_protocol", [
        (True, "https"),
        (False, "http"),
    ])
    @patch("saq.storage.s3.boto3")
    @patch("saq.storage.s3.get_config")
    def test_uses_correct_protocol(self, mock_get_config, mock_boto3, secure, expected_protocol):
        """Endpoint URL protocol should match the secure setting."""
        mock_s3_config = MagicMock()
        mock_s3_config.host = "s3.local"
        mock_s3_config.port = 9000
        mock_s3_config.access_key = "key"
        mock_s3_config.secret_key = "secret"
        mock_s3_config.secure = secure
        mock_s3_config.cert_check = True
        mock_s3_config.region = None
        mock_get_config.return_value.s3 = mock_s3_config

        get_s3_client()

        call_kwargs = mock_boto3.client.call_args.kwargs
        assert call_kwargs["endpoint_url"] == f"{expected_protocol}://s3.local:9000"

    @patch("saq.storage.s3.boto3")
    @patch("saq.storage.s3.get_config")
    def test_region_parameter_ignored_when_self_hosted(self, mock_get_config, mock_boto3):
        """When self-hosted config exists, the region parameter is ignored in favor of config region."""
        mock_s3_config = MagicMock()
        mock_s3_config.host = "s3.local"
        mock_s3_config.port = 9000
        mock_s3_config.access_key = "key"
        mock_s3_config.secret_key = "secret"
        mock_s3_config.secure = False
        mock_s3_config.cert_check = False
        mock_s3_config.region = "config-region"
        mock_get_config.return_value.s3 = mock_s3_config

        get_s3_client(region="ignored-region")

        call_kwargs = mock_boto3.client.call_args.kwargs
        assert call_kwargs["region_name"] == "config-region"
