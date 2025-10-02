import os
import sys
from typing import Optional


from saq.environment import g_boolean, get_base_dir
from saq.constants import G_UNIT_TESTING
from saq.configuration.yaml_parser import YAMLConfig


def load_configuration(config_paths: Optional[list[str]] = None):
    """Unified configuration loader using YAML.

    Args:
        config_paths: optional list of additional configuration files to load (passed in from the command line)

    Load order:
      1) etc/saq.default.yaml
      2) overrides from environment variables or command line
      3) Optional credential/config files
           - /docker-entrypoint-initdb.d/saq.database.passwords.yaml
      4) etc/saq.yaml
      5) etc/saq.unittest.default.yaml (when unit testing)
      6) verify() and apply_path_references()
    """

    default_yaml = os.path.join("etc", "saq.default.yaml")

    config = YAMLConfig()
    config.load_file(default_yaml)

    # add any config files specified in SAQ_CONFIG_PATHS env var (command separated)
    if "SAQ_CONFIG_PATHS" in os.environ:
        for config_path in os.environ["SAQ_CONFIG_PATHS"].split(","):
            config_path = config_path.strip()
            if not config_path:
                continue

            if not os.path.exists(config_path):
                sys.stderr.write(f"WARNING: config path {config_path} specified in SAQ_CONFIG_PATHS env var does not exist\n")
            else:
                config.load_file(config_path)

    # and then add any specified on the command line
    for config_path in config_paths:
        if not os.path.exists(config_path):
            sys.stderr.write(f"WARNING: config path {config_path} specified on the command line does not exist\n")
        else:
            config.load_file(config_path)

    if g_boolean(G_UNIT_TESTING):
        # unit testing loads different configurations
        config.load_file(os.path.join(get_base_dir(), "etc", "saq.unittest.default.yaml"))

    # optional auto-generated passwords and API keys
    db_auto_yaml = "/docker-entrypoint-initdb.d/saq.database.passwords.yaml"
    local_yaml = "etc/saq.yaml"

    def _load_optional(path_yaml: str) -> None:
        if os.path.exists(path_yaml):
            config.load_file(path_yaml)

    _load_optional(db_auto_yaml)
    if not g_boolean(G_UNIT_TESTING):
        _load_optional(local_yaml)

    config.verify()
    config.apply_path_references()
    return config


