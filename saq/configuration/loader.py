import os
import sys
from typing import Optional


from saq.environment import get_base_dir, get_global_runtime_settings
from saq.configuration.yaml_parser import YAMLConfig


def load_configuration(config_paths: Optional[list[str]] = None):
    """Unified configuration loader using YAML.

    Args:
        config_paths: optional list of additional configuration files to load (passed in from the command line)

    Load order:
      1) etc/saq.default.yaml
      2) integration configuration files (specified in G_INTEGRATION_CONFIG_PATHS)
      2) overrides from environment variables or command line
      3) Optional credential/config files
           - /docker-entrypoint-initdb.d/saq.database.passwords.yaml
      5) etc/saq.yaml or etc/saq.unittest.default.yaml (when unit testing)
      6) verify() and apply_path_references()
    """

    default_yaml = os.path.join("etc", "saq.default.yaml")

    config = YAMLConfig()
    config.load_file(default_yaml)

    # load any (automatically loaded) integration configuration files
    # these are autopopulated by the integration loader
    for config_path in get_global_runtime_settings().integration_config_paths:
        if not os.path.exists(config_path):
            sys.stderr.write(f"WARNING: integration config path {config_path} specified in G_INTEGRATION_CONFIG_PATHS does not exist\n")
        else:
            config.load_file(config_path)

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

    if get_global_runtime_settings().unit_testing:
        # unit testing loads different configurations
        config.load_file(os.path.join(get_base_dir(), "etc", "saq.unittest.default.yaml"))

    # optional auto-generated passwords and API keys
    db_auto_yaml = "/docker-entrypoint-initdb.d/saq.database.passwords.yaml"
    s3_test_yaml = "/docker-entrypoint-initdb.d/saq.s3.test.passwords.yaml"
    local_yaml = "etc/saq.yaml"

    def _load_optional(path_yaml: str) -> None:
        if os.path.exists(path_yaml):
            config.load_file(path_yaml)

    _load_optional(db_auto_yaml)
    if get_global_runtime_settings().unit_testing:
        _load_optional(s3_test_yaml)
    else:
        _load_optional(local_yaml)

    config.apply_path_references()
    return config


