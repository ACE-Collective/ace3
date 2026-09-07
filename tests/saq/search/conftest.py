import re
from unittest.mock import Mock

import numpy as np
import pytest
from qdrant_client import models

from saq.configuration.config import get_config, get_service_config
from saq.constants import SERVICE_SEARCH_INDEXER


class WhitespaceTokenizer:
    """Stands in for a HuggingFace fast tokenizer: one token per whitespace-separated word."""

    def __call__(self, text, *, add_special_tokens=False, return_offsets_mapping=True, truncation=False):
        return {"offset_mapping": [(m.start(), m.end()) for m in re.finditer(r"\S+", text)]}


@pytest.fixture
def tokenizer():
    return WhitespaceTokenizer()


@pytest.fixture
def mock_model(tokenizer):
    """A model whose vectors are random but whose interface matches sentence-transformers."""
    model = Mock()
    model.tokenizer = tokenizer
    model.max_seq_length = 256
    model.get_sentence_embedding_dimension.return_value = 8

    def encode(texts, **kwargs):
        if isinstance(texts, str):
            return np.random.rand(8)
        return np.random.rand(len(texts), 8)

    model.encode.side_effect = encode
    return model


@pytest.fixture
def mock_qdrant(monkeypatch):
    """A qdrant client Mock installed everywhere the search package looks one up."""
    client = Mock()
    client.collection_exists.return_value = True
    client.get_collection.return_value = Mock(payload_schema={}, points_count=0, indexed_vectors_count=0, status="green")
    client.delete.return_value = Mock(status=models.UpdateStatus.COMPLETED)
    client.set_payload.return_value = Mock(status=models.UpdateStatus.COMPLETED)
    client.query_points_groups.return_value = Mock(groups=[])
    client.scroll.return_value = ([], None)

    monkeypatch.setattr("saq.search.index.get_qdrant_client", lambda *args, **kwargs: client)
    monkeypatch.setattr("saq.search.query.get_qdrant_client", lambda *args, **kwargs: client)
    return client


@pytest.fixture
def enable_indexer(monkeypatch):
    monkeypatch.setattr(get_service_config(SERVICE_SEARCH_INDEXER), "enabled", True)


@pytest.fixture
def search_config(monkeypatch):
    config = get_config().search
    monkeypatch.setattr(config, "chunk_tokens", 8)
    monkeypatch.setattr(config, "chunk_overlap", 2)
    monkeypatch.setattr(config, "max_chunks_per_document", 4)
    return config
