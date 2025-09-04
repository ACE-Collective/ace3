import os


from saq.environment import g_list
from saq.constants import G_CONFIG_PATHS
from saq.configuration.yaml_parser import YAMLConfig


def load_configuration():
    """Unified configuration loader using YAML.

    Load order:
      1) etc/saq.default.yaml
      2) Overrides from G_CONFIG_PATHS (supports .yaml/.yml)
      3) Optional credential/config files
           - /docker-entrypoint-initdb.d/saq.database.passwords.{yaml,yml}
           - data/etc/saq.api-keys.{yaml,yml}
      4) verify() and apply_path_references()
    """

    default_yaml = os.path.join("etc", "saq.default.yaml")

    config = YAMLConfig()
    config.load_file(default_yaml)

    # Apply overrides from env/CLI consolidated list
    for config_path in g_list(G_CONFIG_PATHS):
        if config_path.endswith((".yaml", ".yml")):
            if isinstance(config, YAMLConfig):
                config.load_file(config_path)

    # Optional auto-generated passwords and API keys
    db_auto_yaml = os.path.join("/docker-entrypoint-initdb.d", "saq.database.passwords.yaml")
    api_auto_yaml = os.path.join("data", "etc", "saq.api-keys.yaml")

    def _load_optional(path_yaml: str) -> None:
        if os.path.exists(path_yaml):
            if isinstance(config, YAMLConfig):
                config.load_file(path_yaml)

    _load_optional(db_auto_yaml)
    _load_optional(api_auto_yaml)

    # Finalize
    config.verify()
    config.apply_path_references()
    return config


