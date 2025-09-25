from qdrant_client.models import ScoredPoint
from saq.llm.embedding.model import load_model
from saq.llm.embedding.vector import get_alert_collection_name, get_embedding_model
from saq.qdrant_client import get_qdrant_client


def search(search_term: str) -> list[ScoredPoint]:

    model = load_model(get_embedding_model())
    vector = model.encode(search_term).tolist()
    client = get_qdrant_client()

    results = client.query_points(
        collection_name=get_alert_collection_name(),
        query=vector,
        query_filter=None,
        limit=30
    ).points

    return results