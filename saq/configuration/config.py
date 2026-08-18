import sys
from typing import TYPE_CHECKING

from pydantic import BaseModel

from saq.configuration.loader import load_configuration
from saq.configuration.schema import ACEConfig
from saq.constants import DB_ACE, SERVICE_ENGINE

if TYPE_CHECKING:
    from saq.configuration.schema import (
        AIQueryBackendConfig,
        DatabaseConfig,
        ProxyConfig,
        ServiceConfig,
        SplunkConfig,
    )
    from saq.engine.core import EngineServiceConfig
    from saq.modules.config import AnalysisModuleConfig

# parsed and validated configuration
CONFIG: ACEConfig | None = None

# registered integration configurations
REGISTERED_INTEGRATION_CONFIGURATIONS: dict[str, type[BaseModel]] = {}

# integration configurations
INTEGRATION_CONFIGURATIONS: dict[str, BaseModel] = {}

def get_config(name: str | None = None) -> ACEConfig:
    """Returns the global configuration object (YAMLConfig)."""
    if name is None:
        return CONFIG

    try:
        return INTEGRATION_CONFIGURATIONS[name]
    except KeyError:
        raise KeyError(f"integration configuration for {name} not found")

def get_database_config(name: str=DB_ACE) -> "DatabaseConfig":
    return get_config().get_database_config(name)

def get_engine_config() -> "EngineServiceConfig":
    return get_config().get_service_config(SERVICE_ENGINE)

def get_analysis_module_config(name: str) -> "AnalysisModuleConfig":
    return get_config().get_analysis_module_config(name)

def get_service_config(name: str) -> "ServiceConfig":
    return get_config().get_service_config(name)

def get_splunk_config(name: str = "default") -> "SplunkConfig":
    return get_config().get_splunk_config(name)

def get_proxy_config(name: str | None = None) -> "ProxyConfig":
    return get_config().get_proxy_config(name)

def get_ai_query_backend_config(name: str) -> "AIQueryBackendConfig":
    return get_config().get_ai_query_backend_config(name)

def set_config(config):
    global CONFIG
    CONFIG = config

def resolve_configuration(existing_config: ACEConfig):
    global CONFIG
    existing_config.resolve_all_values()
    CONFIG = ACEConfig.model_validate(existing_config.raw._data)
    CONFIG.raw = existing_config.raw

    # load integration configurations as separate objects
    for integration_name, integration_class in REGISTERED_INTEGRATION_CONFIGURATIONS.items():
        INTEGRATION_CONFIGURATIONS[integration_name] = integration_class.model_validate(existing_config.raw._data)

    # encrypted:<name> markers are no longer resolved eagerly -- they must land in a SecretRef field
    # (resolved lazily at point-of-use). Any that reached a plain-string field is an unmigrated secret
    # field that would otherwise silently receive the literal "encrypted:..." string. Fail loudly.
    _assert_no_unresolved_encrypted_markers(CONFIG)
    for integration_name, integration_config in INTEGRATION_CONFIGURATIONS.items():
        _assert_no_unresolved_encrypted_markers(integration_config, context=f"integration '{integration_name}'")


def _assert_no_unresolved_encrypted_markers(model: BaseModel, context: str = "configuration") -> None:
    """Raise if any plain-string field in a validated config model still holds an ``encrypted:`` marker.

    A surviving marker in a ``str`` field means that field was NOT typed ``SecretRef`` -- a missed
    migration. SecretRef fields hold a SecretRef object (never a str), so they are skipped naturally.
    """
    offenders: list[str] = []

    def _walk(value, path: str) -> None:
        if isinstance(value, BaseModel):
            for field_name in type(value).model_fields:
                _walk(getattr(value, field_name), f"{path}.{field_name}" if path else field_name)
        elif isinstance(value, dict):
            for k, v in value.items():
                _walk(v, f"{path}[{k!r}]")
        elif isinstance(value, (list, tuple)):
            for i, v in enumerate(value):
                _walk(v, f"{path}[{i}]")
        elif isinstance(value, str) and value.startswith("encrypted:"):
            offenders.append(path)

    _walk(model, "")
    if offenders:
        raise ValueError(
            f"unresolved encrypted: marker(s) in {context} at "
            f"{', '.join(offenders)} -- these config fields must be typed SecretRef "
            f"(saq.configuration.secret_ref) so the secret is resolved lazily"
        )

def register_integration_configuration(integration_name: str, integration_class: type[BaseModel]):
    if integration_name in REGISTERED_INTEGRATION_CONFIGURATIONS:
        raise ValueError(f"integration configuration for {integration_name} already registered")

    REGISTERED_INTEGRATION_CONFIGURATIONS[integration_name] = integration_class

def initialize_configuration(config_paths: list[str] | None=None):
    global CONFIG

    # load configuration files
    if config_paths is None:
        config_paths = []
    
    try:
        raw_config = load_configuration(config_paths=config_paths)
        CONFIG = ACEConfig.model_validate(raw_config._data)
        CONFIG.raw = raw_config
    except Exception as e:
        sys.stderr.write(f"ERROR: unable to load configuration: {e}")
        raise
