import ssl
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

    # the api key is independent of TLS: a plain-http qdrant with an api key configured
    # still requires it
    if config.api_key:
        kwargs["api_key"] = config.api_key

    if config.use_ssl:
        kwargs["https"] = True
        kwargs["verify"] = ssl.create_default_context(cafile=config.ssl_ca_path)
        # the client's server version probe does not use this verify setting, so against a
        # private CA it always fails and only emits a warning
        kwargs["check_compatibility"] = False

    return QdrantClient(**kwargs)
