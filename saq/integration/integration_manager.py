from saq.configuration.config import get_config
from saq.configuration.schema import IntegrationConfig
from saq.integration.integration_util import get_integration_config_path


def is_integration_dir_enabled(dir_path: str) -> bool:
    """Returns False for an integration directory that is off: it declares at least one
    integration_*: section and every one of them is disabled (see load_configuration())."""
    return get_integration_config_path(dir_path) not in get_config().raw.disabled_integration_paths


def get_integration_dir_configs(dir_path: str) -> list[IntegrationConfig]:
    """Returns the configuration of each integration_*: section the integration directory declares."""
    sections = get_config().raw.integration_blocks.get(get_integration_config_path(dir_path), [])
    return [get_config().get_integration_config(section) for section in sections]
