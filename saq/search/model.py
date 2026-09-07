"""Loading and using the dense embedding model.

The model is a sentence-transformers model selected by `search.embedding_model`, downloaded
once into the data directory and cached per process. Everything about the collection that
depends on the model (dimension, tokenizer, collection name) is read from the loaded model
rather than configured separately, so the two cannot drift.
"""

import logging
import os
import re
from typing import Any, Optional

from saq.configuration.config import get_config
from saq.environment import get_data_dir

# bump when the document/payload layout changes in a way that requires a re-index
SCHEMA_VERSION = 1

_loaded_models: dict[str, Any] = {}


def get_model_name() -> str:
    return get_config().search.embedding_model


def model_slug(model_name: Optional[str] = None) -> str:
    """A collection-name-safe form of the model name ("all-MiniLM-L6-v2" -> "all-minilm-l6-v2")."""
    name = model_name or get_model_name()
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def get_model_cache_dir() -> str:
    return os.path.join(get_data_dir(), get_config().search.model_cache_dir)


def get_model_cache_path(model_name: Optional[str] = None) -> str:
    return os.path.join(get_model_cache_dir(), model_slug(model_name))


def is_model_downloaded(model_name: Optional[str] = None) -> bool:
    return os.path.isdir(get_model_cache_path(model_name))


def clear_model_cache() -> None:
    """Forgets every loaded model (tests)."""
    _loaded_models.clear()


def download_model(model_name: str):
    """Downloads model_name and saves it into the model cache. Returns the loaded model."""
    # deferred: sentence_transformers pulls in torch, which takes seconds to import and must
    # not be paid by processes that only submit index tasks
    from sentence_transformers import SentenceTransformer

    os.makedirs(get_model_cache_dir(), exist_ok=True)
    logging.info(f"downloading embedding model {model_name}")
    model = SentenceTransformer(model_name, device="cpu")
    model.save(get_model_cache_path(model_name))
    return model


def load_model(model_name: Optional[str] = None):
    """Returns the (process-cached) embedding model, downloading it on first use."""
    # deferred: see download_model
    from sentence_transformers import SentenceTransformer

    name = model_name or get_model_name()
    if name not in _loaded_models:
        if is_model_downloaded(name):
            _loaded_models[name] = SentenceTransformer(get_model_cache_path(name), device="cpu")
        else:
            _loaded_models[name] = download_model(name)

    return _loaded_models[name]


def dense_dimension(model) -> int:
    return int(model.get_sentence_embedding_dimension())


def max_chunk_tokens(model) -> int:
    """The largest chunk the model can embed without truncation (special tokens excluded)."""
    configured = get_config().search.chunk_tokens
    limit = int(getattr(model, "max_seq_length", configured) or configured) - 2
    return max(1, min(configured, limit))


def encode_documents(model, texts: list[str], batch_size: int = 32) -> list[list[float]]:
    if not texts:
        return []

    vectors = model.encode(texts, batch_size=batch_size, normalize_embeddings=True, show_progress_bar=False)
    return [vector.tolist() for vector in vectors]


def encode_query(model, text: str) -> list[float]:
    prefix = get_config().search.query_prefix or ""
    vector = model.encode(f"{prefix}{text}", normalize_embeddings=True, show_progress_bar=False)
    return vector.tolist()
