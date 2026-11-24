import os
import sys
from typing import Any

from pydantic import TypeAdapter, ValidationError

from saq.configuration.yaml_parser import INTEGRATION_SECTION_PREFIX, YAMLConfig, resolve_value
from saq.environment import get_base_dir, get_global_runtime_settings

_BOOL = TypeAdapter(bool)


def _env_config_paths(env_var: str) -> list[str]:
    """The comma separated configuration files named by the given environment variable that exist."""
    if env_var not in os.environ:
        return []

    paths = []
    for config_path in os.environ[env_var].split(","):
        config_path = config_path.strip()
        if not config_path:
            continue

        if not os.path.exists(config_path):
            sys.stderr.write(f"WARNING: config path {config_path} specified in {env_var} env var does not exist\n")
        else:
            paths.append(config_path)

    return paths


def _config_layers(config_paths: list[str]) -> list[str]:
    """The files load_configuration() merges, in order, each of which exists."""
    layers = [os.path.join(get_base_dir(), "etc", "saq.default.yaml")]

    # these are autopopulated by the integration loader
    for config_path in get_global_runtime_settings().integration_config_paths:
        if not os.path.exists(config_path):
            sys.stderr.write(f"WARNING: integration config path {config_path} specified in G_INTEGRATION_CONFIG_PATHS does not exist\n")
        else:
            layers.append(config_path)

    layers.extend(_env_config_paths("SAQ_CONFIG_PATHS"))

    for config_path in config_paths:
        if not os.path.exists(config_path):
            sys.stderr.write(f"WARNING: config path {config_path} specified on the command line does not exist\n")
        else:
            layers.append(config_path)

    if get_global_runtime_settings().unit_testing:
        # unit testing loads different configurations
        layers.append(os.path.join(get_base_dir(), "etc", "saq.unittest.default.yaml"))
        # and then any overlays on top of those (the per-session database names)
        layers.extend(_env_config_paths("SAQ_UNITTEST_CONFIG_PATHS"))

    # optional auto-generated passwords and API keys
    optional = ["/docker-entrypoint-initdb.d/saq.database.passwords.yaml"]
    # the dev overlay is never part of a test run
    if not get_global_runtime_settings().unit_testing:
        local_yaml = os.path.join(get_base_dir(), "etc", "saq.yaml")
        if "SAQ_SKIP_LOCAL_SAQ_YAML" in os.environ:
            # a container with a curated SAQ_CONFIG_PATHS overlay (the AI API) must not have the
            # local dev overlay -- which may hold live credentials -- merged over it
            sys.stderr.write(f"NOTICE: skipping {local_yaml} because SAQ_SKIP_LOCAL_SAQ_YAML is set\n")
        else:
            optional.append(local_yaml)

    layers.extend(path for path in optional if os.path.exists(path))
    return layers


def _merge_layers(layers: list[str], disabled: set[str], parsed_files: dict[str, dict[str, Any]],
                  integration_files: dict[str, set[str]]) -> YAMLConfig:
    """Merges the layers, leaving out all but the integration_*: sections (and the observable
    classes) of the integration files in disabled and of the files they include. Fills
    integration_files with each integration file -> it and the files it included."""
    integration_paths = set(get_global_runtime_settings().integration_config_paths)
    config = YAMLConfig(parsed_files=parsed_files)

    for path in layers:
        if path not in integration_paths:
            config.load_file(path)
            continue

        if path in config.loaded_files:
            # named twice, or included by an earlier file: the sections were found the first time
            continue

        before = set(config.loaded_files)
        config.load_file(path, integration_sections_only=path in disabled)
        integration_files[path] = config.loaded_files - before
        config.integration_blocks[path] = sorted({
            key for loaded in integration_files[path] for key in parsed_files[loaded]
            if key.startswith(INTEGRATION_SECTION_PREFIX)})

    return config


def _section_enabled(key: str, section: Any) -> bool:
    """The merged enabled: of an integration_*: section. One that is not a valid bool counts as
    enabled, which leaves it to the IntegrationConfig validation to report."""
    if not isinstance(section, dict):
        return True

    try:
        return _BOOL.validate_python(resolve_value(section.get("enabled"), f"{key}.enabled"))
    except ValidationError:
        return True


def load_configuration(config_paths: list[str] | None = None):
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
         followed, when unit testing, by the files in SAQ_UNITTEST_CONFIG_PATHS
      6) verify() and apply_path_references()

    SAQ_UNITTEST_CONFIG_PATHS exists because SAQ_CONFIG_PATHS and the command line paths load
    *before* saq.unittest.default.yaml and so cannot override anything it sets. The test suite
    uses it to point the database settings at the databases it provisions for the session
    (see tests/unittest_database.py).

    An integration whose every integration_*: section is disabled is off: of its files, only those
    sections are merged. Any later layer can set enabled:, so that is known only after every layer
    is merged, and then the layers are merged again without the files of the integrations that are
    off. The second merge reuses the parsed files.

    A top-level key that one of those integrations declared before any other file did is its block
    (a service, a hunt type, a module group), and is left out with whatever later layers set on it:
    a site's service_<name>: enabled: alone is not a service. A key another integration that is on
    also declares is kept.
    """
    if config_paths is None:
        config_paths = []

    layers = _config_layers(config_paths)
    parsed_files: dict[str, dict[str, Any]] = {}
    integration_files: dict[str, set[str]] = {}
    config = _merge_layers(layers, set(), parsed_files, integration_files)

    disabled = {path for path, keys in config.integration_blocks.items()
                if keys and not any(_section_enabled(key, config._data.get(key)) for key in keys)}

    if disabled:
        disabled_files = set().union(*(integration_files[path] for path in disabled))
        enabled_keys = {key for path, files in integration_files.items() if path not in disabled
                        for loaded in files for key in parsed_files[loaded]}
        dropped = {key for key, path in config.first_declared_by.items()
                   if path in disabled_files and key not in enabled_keys
                   and not key.startswith(INTEGRATION_SECTION_PREFIX)}

        config = _merge_layers(layers, disabled, parsed_files, integration_files)
        for key in dropped:
            config._data.pop(key, None)

        config.disabled_integration_paths = disabled
        config.disabled_integration_keys = dropped

    config.apply_path_references()
    return config
