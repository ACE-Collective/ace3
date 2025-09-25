from qdrant_client import QdrantClient

from saq.configuration.config import get_config_value, get_config_value_as_boolean
from saq.constants import CONFIG_QDRANT, CONFIG_QDRANT_API_KEY, CONFIG_QDRANT_SSL_CA_PATH, CONFIG_QDRANT_URL, CONFIG_QDRANT_USE_SSL


def get_qdrant_client():
    kwargs = {
        "url": get_config_value(CONFIG_QDRANT, CONFIG_QDRANT_URL)
    }

    if get_config_value_as_boolean(CONFIG_QDRANT, CONFIG_QDRANT_USE_SSL):
        kwargs["https"] = True
        kwargs["verify"] = get_config_value(CONFIG_QDRANT, CONFIG_QDRANT_SSL_CA_PATH)
        # Note: SSL certificate verification is handled by the underlying HTTP client
        # The ca_certs configuration is not directly supported in qdrant-client
        kwargs["api_key"] = get_config_value(CONFIG_QDRANT, CONFIG_QDRANT_API_KEY)

    return QdrantClient(**kwargs)
