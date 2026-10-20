"""Loading and using the dense embedding model.

The model is a sentence-transformers model selected by `search.embedding_model`, downloaded
once into the data directory and cached per process. Everything about the collection that
depends on the model (dimension, tokenizer, collection name) is read from the loaded model
rather than configured separately, so the two cannot drift.

Only download_model() fetches the model (`ace-setup`, the search indexer, `ace search
download-model`); load_model() never does, so the web processes, which may have the data
directory mounted read-only, never download anything.
"""

import fcntl
import logging
import os
import re
import shutil
import tempfile
import time
from typing import Any, Callable, Optional

from saq.configuration.config import get_config
from saq.environment import get_data_dir
from saq.shutdown import is_shutting_down

# bump when the document/payload layout changes in a way that requires a re-index
SCHEMA_VERSION = 1

# sentence-transformers writes this last when it saves a model, so a directory without it is
# a save that never finished
MODEL_COMPLETE_FILE = "modules.json"

# how long a process waits for another process that is downloading the same model
DEFAULT_DOWNLOAD_LOCK_TIMEOUT_SECONDS = 600

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
    return os.path.isfile(os.path.join(get_model_cache_path(model_name), MODEL_COMPLETE_FILE))


def clear_model_cache() -> None:
    """Forgets every loaded model (tests)."""
    _loaded_models.clear()


def _acquire_download_lock(lock_file, model_name: str, timeout: float, stopping: Callable[[], bool]) -> None:
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return
    except BlockingIOError:
        pass

    logging.info("search_model_download_waiting", extra={"model": model_name, "lock_path": lock_file.name, "timeout": timeout})
    deadline = time.monotonic() + timeout
    while True:
        if stopping():
            raise RuntimeError(f"shutting down while waiting for the download of embedding model {model_name}")
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out after {timeout}s waiting for another process to download embedding model {model_name} (lock {lock_file.name})")
        time.sleep(1)
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            continue


def download_model(model_name: Optional[str] = None, *, timeout: float = DEFAULT_DOWNLOAD_LOCK_TIMEOUT_SECONDS,
                   stopping: Callable[[], bool] = is_shutting_down) -> str:
    """Downloads model_name into the model cache unless it is already there; returns its path.

    Any number of processes may call this at once: one downloads while the others wait on a
    file lock and then find the model in place. The model is saved into a staging directory
    and renamed into place, so a process that is killed mid-download never leaves a directory
    that looks complete, and the Hugging Face hub cache lives in that staging directory too,
    so the only copy left is the one on the data volume."""
    name = model_name or get_model_name()
    path = get_model_cache_path(name)
    if is_model_downloaded(name):
        return path

    cache_dir = get_model_cache_dir()
    os.makedirs(cache_dir, exist_ok=True)
    staging_prefix = f".{model_slug(name)}-download-"

    with open(os.path.join(cache_dir, f".{model_slug(name)}.lock"), "a") as lock_file:
        _acquire_download_lock(lock_file, name, timeout, stopping)
        try:
            if is_model_downloaded(name):
                # another process downloaded it while we waited
                return path

            # holding the lock, so these belong to downloads that were killed
            for entry in os.listdir(cache_dir):
                if entry.startswith(staging_prefix):
                    shutil.rmtree(os.path.join(cache_dir, entry), ignore_errors=True)

            # deferred: sentence_transformers pulls in torch, which takes seconds to import and must
            # not be paid by processes that only submit index tasks
            from sentence_transformers import SentenceTransformer

            started = time.monotonic()
            logging.info("search_model_downloading", extra={"model": name, "path": path})
            staging = tempfile.mkdtemp(prefix=staging_prefix, dir=cache_dir)
            try:
                model = SentenceTransformer(name, device="cpu", cache_folder=os.path.join(staging, "hub"))
                model.save(os.path.join(staging, "model"))
                if os.path.isdir(path):
                    logging.warning("search_model_replacing_incomplete", extra={"model": name, "path": path})
                    shutil.rmtree(path)
                os.rename(os.path.join(staging, "model"), path)
            finally:
                # ignore_errors: the model is in place (or the original error is propagating);
                # a staging directory left behind is removed by the next download
                shutil.rmtree(staging, ignore_errors=True)

            logging.info("search_model_downloaded", extra={"model": name, "path": path, "elapsed_ms": int((time.monotonic() - started) * 1000)})
            return path
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def load_model(model_name: Optional[str] = None):
    """Returns the (process-cached) embedding model; raises FileNotFoundError if it has not been downloaded."""
    name = model_name or get_model_name()
    if name not in _loaded_models:
        path = get_model_cache_path(name)
        if not is_model_downloaded(name):
            raise FileNotFoundError(f"embedding model {name} has not been downloaded into {path} "
                                    "(the search indexer downloads it at startup, or run `ace search download-model`)")

        # deferred: see download_model
        from sentence_transformers import SentenceTransformer
        _loaded_models[name] = SentenceTransformer(path, device="cpu")

    return _loaded_models[name]


def dense_dimension(model) -> int:
    return int(model.get_embedding_dimension())


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
