"""Resolution of ai_query_backend_<name> config sections into AIQueryBackend instances.

Class import happens here, at the point of use, NOT at config-parse time: every ACE process
validates the configuration, but only the AI API process should ever import vendor query clients.
The raw config section is re-validated against the backend class's own get_config_class() so
backend-specific fields get full schema validation.
"""

import importlib
import logging

from saq.ai_query.interface import AIQueryBackend
from saq.configuration.config import get_config


def load_backend(name: str) -> AIQueryBackend:
    """Import and instantiate the configured backend class for ai_query_backend_<name>."""
    config = get_config()
    base_config = config.get_ai_query_backend_config(name)

    module = importlib.import_module(base_config.python_module)
    backend_class = getattr(module, base_config.python_class)

    if not issubclass(backend_class, AIQueryBackend):
        raise TypeError(
            f"ai query backend {name}: {base_config.python_module}.{base_config.python_class} "
            "is not an AIQueryBackend subclass")

    backend_config = backend_class.get_config_class().model_validate(config.get_ai_query_backend_raw(name))
    return backend_class(backend_config)


def build_backend_registry() -> dict[str, AIQueryBackend]:
    """Instantiate every enabled backend, keyed by name."""
    registry = {}
    for base_config in get_config().ai_query_backends:
        if not base_config.enabled:
            logging.debug("ai query backend %s is disabled", base_config.name)
            continue

        registry[base_config.name] = load_backend(base_config.name)
        logging.info("loaded ai query backend %s", base_config.name)

    return registry
