
import os

from saq.environment import get_data_dir

#
# NOTE the import of SentenceTransformer is deferred until the function is called
# because it is a heavy dependency and takes a long time to load
#


# global cache of loaded models
_loaded_models = {}

def get_model_cache_folder() -> str:
    return os.path.join(get_data_dir(), "llm", "cache")

def get_model_cache_path(model: str) -> str:
    return os.path.join(get_model_cache_folder(), model)

def is_model_downloaded(model: str) -> bool:
    return os.path.exists(get_model_cache_path(model))

def download_model(model: str):
    """Downloads the model from the internet and caches it locally."""
    from sentence_transformers import SentenceTransformer
    cache_folder = get_model_cache_folder()
    if not os.path.exists(cache_folder):
        os.makedirs(cache_folder)

    target_path = get_model_cache_path(model)

    model = SentenceTransformer(model, device="cpu")
    model.save(target_path)
    return model

def load_model(model: str):
    """Loads the model from the cache. If the model has not been cached then it is downloaded."""
    from sentence_transformers import SentenceTransformer
    if model not in _loaded_models:
        # if we haven't downloaded the model then do so
        if not is_model_downloaded(model):
            _loaded_models[model] = download_model(model)
        else:
            # otherwise just load it from the cache
            _loaded_models[model] = SentenceTransformer(get_model_cache_path(model), device="cpu")

    return _loaded_models[model]
