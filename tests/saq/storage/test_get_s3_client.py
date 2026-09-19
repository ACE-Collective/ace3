"""Tests for the get_s3_client function."""

from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("boto3")

from saq.configuration.schema import S3Config
from saq.storage.s3 import build_boto_config, get_s3_client


pytestmark = pytest.mark.unit


def _mock_s3_config(**overrides) -> MagicMock:
    """A mocked self-hosted S3Config.

    The timeout fields must be real numbers, not MagicMocks: build_boto_config() feeds them to
    botocore, which validates them. A bare MagicMock() here raises
    "TypeError: '<' not supported between instances of 'MagicMock' and 'int'".
    """
    config = MagicMock()
    config.host = "s3.local"
    config.port = 9000
    config.access_key = "key"
    config.secret_key = "secret"
    config.secure = False
    config.cert_check = False
    config.region = None
    config.connect_timeout = 10
    config.read_timeout = 60
    config.max_attempts = 3
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def assert_bounded(boto_config, *, connect=10, read=60, attempts=3):
    """Every S3 client ACE builds must be bounded.

    botocore's own defaults are 60s connect, 60s read and *legacy* retry mode (5 attempts), which
    lets a black-holed endpoint hold a caller for ~300s per request. These assertions are the
    tripwire for anyone constructing a client without the shared config.
    """
    assert boto_config is not None, "client built with no botocore config at all"
    assert boto_config.connect_timeout == connect
    assert boto_config.read_timeout == read
    assert boto_config.retries == {"mode": "standard", "total_max_attempts": attempts}
    assert boto_config.signature_version == "s3v4"


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

        assert mock_boto3.client.call_args.args == ("s3",)
        call_kwargs = mock_boto3.client.call_args.kwargs
        assert call_kwargs["region_name"] == "us-east-2"
        # every construction path, including AWS-native, must pass the shared bounded config
        assert_bounded(call_kwargs["config"])
        assert result is mock_client

    @patch("saq.storage.s3.boto3")
    @patch("saq.storage.s3.get_config")
    def test_returns_boto3_client_without_region(self, mock_get_config, mock_boto3):
        """When get_config().s3 is None and no region provided, creates client with region_name=None."""
        mock_get_config.return_value.s3 = None
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client

        result = get_s3_client()

        assert mock_boto3.client.call_args.args == ("s3",)
        call_kwargs = mock_boto3.client.call_args.kwargs
        assert call_kwargs["region_name"] is None
        assert_bounded(call_kwargs["config"])
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
        mock_get_config.return_value.s3 = _mock_s3_config(
            host="minio.local",
            access_key="test-access-key",
            secret_key="test-secret-key",
            region="us-east-1",
        )

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
        assert_bounded(call_kwargs["config"])
        assert result is mock_client

    @pytest.mark.parametrize("secure,expected_protocol", [
        (True, "https"),
        (False, "http"),
    ])
    @patch("saq.storage.s3.boto3")
    @patch("saq.storage.s3.get_config")
    def test_uses_correct_protocol(self, mock_get_config, mock_boto3, secure, expected_protocol):
        """Endpoint URL protocol should match the secure setting."""
        mock_get_config.return_value.s3 = _mock_s3_config(secure=secure, cert_check=True)

        get_s3_client()

        call_kwargs = mock_boto3.client.call_args.kwargs
        assert call_kwargs["endpoint_url"] == f"{expected_protocol}://s3.local:9000"

    @patch("saq.storage.s3.boto3")
    @patch("saq.storage.s3.get_config")
    def test_region_parameter_ignored_when_self_hosted(self, mock_get_config, mock_boto3):
        """When self-hosted config exists, the region parameter is ignored in favor of config region."""
        mock_get_config.return_value.s3 = _mock_s3_config(region="config-region")

        get_s3_client(region="ignored-region")

        call_kwargs = mock_boto3.client.call_args.kwargs
        assert call_kwargs["region_name"] == "config-region"


class TestBotoConfigDefaults:
    """The values themselves, and that they survive the trip into botocore."""

    @patch("saq.storage.s3.get_config")
    def test_falls_back_to_schema_defaults_when_no_s3_config(self, mock_get_config):
        """The AWS-native branch is taken exactly BECAUSE get_config().s3 is None, so there is no
        S3Config to read. It must still be bounded, from the schema's own defaults rather than a
        second set of literals."""
        mock_get_config.return_value.s3 = None
        assert_bounded(build_boto_config())

    @patch("saq.storage.s3.get_config")
    def test_honors_configured_values(self, mock_get_config):
        mock_get_config.return_value.s3 = _mock_s3_config(
            connect_timeout=3, read_timeout=15, max_attempts=7
        )
        assert_bounded(build_boto_config(), connect=3, read=15, attempts=7)

    def test_schema_defaults_are_the_documented_values(self):
        fields = S3Config.model_fields
        assert fields["connect_timeout"].default == 10
        assert fields["read_timeout"].default == 60
        assert fields["max_attempts"].default == 3

    def test_read_timeout_default_matches_botocore(self):
        """read_timeout is deliberately left at botocore's own default.

        It is a per-socket-read timeout and transfers are multipart, so it is a per-part stall
        detector rather than a cap on a whole transfer. Lowering it imposes a per-stream throughput
        floor across up to 10 concurrent parts, which is the one knob here that could break a large
        transfer that works today. If this assertion ever fails, that trade is being made.
        """
        from botocore.config import Config as RealBotoConfig

        assert S3Config.model_fields["read_timeout"].default == RealBotoConfig().read_timeout


@pytest.mark.unit
def test_resolved_client_actually_carries_the_bounds():
    """Assert against a real resolved client, not just the kwargs we passed.

    The mocked tests above prove we BUILD the right config; this proves boto3 keeps it. Needs no
    network -- constructing a client performs no I/O -- so the bogus endpoint is never contacted.
    """
    import boto3

    from saq.storage.s3 import build_boto_config

    with patch("saq.storage.s3.get_config") as mock_get_config:
        mock_get_config.return_value.s3 = None
        config = build_boto_config()

    client = boto3.client(
        "s3",
        region_name="us-east-1",
        endpoint_url="http://127.0.0.1:1",
        aws_access_key_id="x",
        aws_secret_access_key="y",
        config=config,
    )

    resolved = client.meta.config
    assert resolved.connect_timeout == 10
    assert resolved.read_timeout == 60
    assert resolved.retries["total_max_attempts"] == 3
    assert resolved.retries["mode"] == "standard"


@pytest.mark.unit
@patch("saq.storage.s3.get_config")
def test_transfer_config_bounds_s3transfer_retries(mock_get_config):
    """s3transfer keeps its OWN retry counter on top of botocore's.

    Its default is 5, so an unbounded download would retry 5 x max_attempts. Everything else about
    transfer behavior (8MiB threshold and chunk size, 10-way concurrency) must stay at the default.
    """
    from boto3.s3.transfer import TransferConfig

    from saq.storage.s3 import build_transfer_config

    mock_get_config.return_value.s3 = _mock_s3_config(max_attempts=3)
    config = build_transfer_config()
    default = TransferConfig()

    assert config.num_download_attempts == 3
    assert default.num_download_attempts == 5, "s3transfer default changed; revisit this bound"
    assert config.multipart_threshold == default.multipart_threshold
    assert config.multipart_chunksize == default.multipart_chunksize
    assert config.max_concurrency == default.max_concurrency
