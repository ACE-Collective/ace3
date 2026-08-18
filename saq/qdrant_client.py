from typing import Optional

from qdrant_client import QdrantClient

from saq.configuration.config import get_config


def get_qdrant_client(timeout: Optional[int] = None) -> QdrantClient:
    """Returns a qdrant client.

    Args:
        timeout: HTTP timeout in seconds. Defaults to the configured qdrant.timeout.
    """

    config = get_config().qdrant

    kwargs = {
        "url": config.url,
        "timeout": config.timeout if timeout is None else timeout,
    }

    if config.use_ssl:
        kwargs["https"] = True
        kwargs["verify"] = config.ssl_ca_path
        # Note: SSL certificate verification is handled by the underlying HTTP client
        # The ca_certs configuration is not directly supported in qdrant-client
        kwargs["api_key"] = config.api_key

    return QdrantClient(**kwargs)
