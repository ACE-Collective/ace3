import pytest
from unittest.mock import patch

from saq.configuration import get_config
from saq.qdrant_client import get_qdrant_client


@pytest.fixture
def mock_qdrant_config(monkeypatch):
    monkeypatch.setattr(get_config().qdrant, "url", "http://localhost:6333")
    monkeypatch.setattr(get_config().qdrant, "use_ssl", False)
    monkeypatch.setattr(get_config().qdrant, "timeout", 30)
    monkeypatch.setattr(get_config().qdrant, "search_timeout", 10)


@pytest.mark.unit
class TestGetQdrantClient:
    """A timeout must always be passed explicitly: when it is omitted qdrant-client leaves
    it out of the httpx client args entirely and httpx silently applies its own 5 second
    default, which is what caused vectorization to fail against a growing collection."""

    def test_timeout_defaults_to_config(self, mock_qdrant_config):
        with patch("saq.qdrant_client.QdrantClient") as mock_client:
            get_qdrant_client()

        assert mock_client.call_args.kwargs["timeout"] == 30

    def test_explicit_timeout_overrides_config(self, mock_qdrant_config):
        with patch("saq.qdrant_client.QdrantClient") as mock_client:
            get_qdrant_client(timeout=get_config().qdrant.search_timeout)

        assert mock_client.call_args.kwargs["timeout"] == 10

    def test_timeout_always_present(self, mock_qdrant_config):
        """Guards the regression directly: the kwarg must never be absent."""
        with patch("saq.qdrant_client.QdrantClient") as mock_client:
            get_qdrant_client()

        assert "timeout" in mock_client.call_args.kwargs

    def test_ssl_arguments_only_when_enabled(self, mock_qdrant_config, monkeypatch):
        with patch("saq.qdrant_client.QdrantClient") as mock_client:
            get_qdrant_client()
        assert "https" not in mock_client.call_args.kwargs

        monkeypatch.setattr(get_config().qdrant, "use_ssl", True)
        monkeypatch.setattr(get_config().qdrant, "ssl_ca_path", "ssl/ca-chain.cert.pem")
        monkeypatch.setattr(get_config().qdrant, "api_key", "test-key")

        with patch("saq.qdrant_client.QdrantClient") as mock_client:
            get_qdrant_client()

        assert mock_client.call_args.kwargs["https"] is True
        assert mock_client.call_args.kwargs["verify"] == "ssl/ca-chain.cert.pem"
        assert mock_client.call_args.kwargs["api_key"] == "test-key"
