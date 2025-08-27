from qdrant_client.models import ScoredPoint
from saq.configuration.config import get_config_value
from saq.constants import CONFIG_QDRANT, CONFIG_QDRANT_URL
from saq.llm.embedding.model import load_model
from saq.llm.embedding.vector import get_alert_collection_name, get_embedding_model


def search(search_term: str) -> list[ScoredPoint]:
    from qdrant_client import QdrantClient

    model = load_model(get_embedding_model())
    vector = model.encode(search_term).tolist()
    client = QdrantClient(url=get_config_value(CONFIG_QDRANT, CONFIG_QDRANT_URL))

    results = client.query_points(
        collection_name=get_alert_collection_name(),
        query=vector,
        query_filter=None,
        limit=30
    ).points

    return results