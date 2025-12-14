import copy
import os
import sys
import logging
from typing import Any, Optional

from deepmerge import Merger
import yaml

from saq.environment import get_global_runtime_settings
from saq.configuration.encryption import decrypt_password

ENV_PREFIX = "env:"
ENCRYPTED_PREFIX = "encrypted:"

custom_merger = Merger(
    # type strategies
    [
        (list, ["append"]),
        (dict, ["merge"]),
        (set, ["override"])
    ],
    # fallback strategy
    ["override"],
    # strategy when types conflict
    ["override"]
)


class YAMLConfig:
    """YAML-based configuration interface.
    - Supports recursive includes via top-level 'config' mapping or list of paths.
    """

    def __init__(self) -> None:
        self._data: dict[str, dict[str, Any]] = {}
        self.encrypted_password_cache: dict[str, Optional[str]] = {}
        self.loaded_files: set[str] = set()
        self._yaml_loader_cls = yaml.SafeLoader

    def copy(self) -> "YAMLConfig":
        """Return a deep copy of this YAMLConfig object."""
        new_config = YAMLConfig()
        new_config._data = copy.deepcopy(self._data)
        new_config.encrypted_password_cache = copy.deepcopy(self.encrypted_password_cache)
        new_config.loaded_files = copy.deepcopy(self.loaded_files)
        return new_config

    # do resolve behaviors
    def _resolve_value(self, value: Any) -> Any:
        # support string prefix forms
        if isinstance(value, str):
            if value.startswith(ENV_PREFIX):
                var = value[len(ENV_PREFIX) :]
                if var not in os.environ:
                    raise RuntimeError(
                        f"configuration referenced unknown environment variable {var}"
                    )

                return os.environ[var]

            if value.startswith(ENCRYPTED_PREFIX):
                key = value[len(ENCRYPTED_PREFIX) :]
                if not get_global_runtime_settings().encryption_initialized:
                    return value

                return self._get_decrypted_password(key)

        # otherwise no special handling
        return value

    def _get_decrypted_password(self, key: str) -> Optional[str]:
        try:
            return self.encrypted_password_cache[key]
        except KeyError:
            pass

        self.encrypted_password_cache[key] = decrypt_password(key)
        return self.encrypted_password_cache[key]

    def merge(self, other: dict[str, dict[str, Any]]) -> None:
        """Overlay configuration from another mapping-like object.

        For sections present in both, keys are overwritten by values from 'other'.
        """

        custom_merger.merge(self._data, other)

    def _load_yaml_file(self, path: str) -> dict[str, Any]:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.load(f, Loader=self._yaml_loader_cls) or {}

        if not isinstance(data, dict):
            raise ValueError(f"YAML configuration root must be a mapping: {path}")

        return data

    def load_file(self, path: str) -> bool:
        """Load a YAML configuration file and merge it into this config.

        Returns False if the file was already loaded, True otherwise.
        """
        if path in self.loaded_files:
            return False

        if not os.path.exists(path):
            sys.stderr.write(f"referenced YAML configuration file not found: {path}\n")
            return False

        if os.getenv("SAQ_DEBUG_CONFIG"):
            sys.stderr.write(f"loading YAML configuration file: {path}\n")

        yaml_root = self._load_yaml_file(path)

        self.merge(yaml_root)

        #for top_key, top_value in yaml_root.items():
            #if top_key == "config":
                ## handled by resolve_references
                #continue
#
            #if isinstance(top_value, dict):
                ##section_mapping: dict[str, Any] = {
                    ##str(k): v for k, v in top_value.items()
                ##}
#
                #if top_key in self._data:
                    #self._data[top_key].update(top_value)
                #else:
                    #self._data[top_key] = top_value
#
            #else:
                ## if a scalar is found at top-level, treat it as a section-less key by
                ## putting it under a pseudo section named by the key
                ##self._data[top_key] = top_value

        self.loaded_files.add(path)
        self.resolve_references(yaml_root)
        return True

    def resolve_references(self, yaml_root: dict[str, Any]) -> None:
        """Recursively load additional configuration files from 'config'.

        The 'config' field may be a mapping of names->path or a list of paths.
        """
        includes = yaml_root.get("config")
        if not includes:
            return

        # Normalize includes to a list of paths
        paths: list[str] = []
        if isinstance(includes, list):
            for entry in includes:
                if isinstance(entry, str):
                    paths.append(entry)
        elif isinstance(includes, dict):
            for _name, path in includes.items():
                if isinstance(path, str):
                    paths.append(path)

        while True:
            loaded_any = False
            for include_path in paths:
                if include_path in self.loaded_files:
                    continue

                if include_path.endswith((".yaml", ".yml")):
                    if not os.path.exists(include_path):
                        logging.info(f"skipping non-existent YAML include path in YAML config: {include_path}")
                        continue

                    loaded_any = self.load_file(include_path) or loaded_any
                else:
                    logging.warning(
                        f"skipping non-YAML include path in YAML config: {include_path}"
                    )

            if not loaded_any:
                break

    def apply_path_references(self) -> None:
        """Append any values under 'path' section to sys.path."""
        if "path" not in self._data:
            return

        path_mapping = self._data["path"]
        if not isinstance(path_mapping, dict):
            return

        for _key, value in path_mapping.items():
            resolved = self._resolve_value(value)
            if isinstance(resolved, str):
                sys.path.append(resolved)

    def decrypt_all_values(self) -> None:
        """Recursively decrypt all encrypted values in the configuration.

        The encryption key is stored in the database, and the database connection parameters
        are stored in the configuration. So we need to load the configuration first, then
        decrypt the values.
        """
        def _decrypt_recursive(mapping: dict[str, Any]) -> None:
            """Recursively decrypt values in a mapping."""
            for key, value in mapping.items():
                if isinstance(value, dict):
                    # Recursively process nested dictionaries
                    _decrypt_recursive(value)
                elif isinstance(value, list):
                    # Process list items
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            _decrypt_recursive(item)
                        elif isinstance(item, str) and item.startswith("encrypted:"):
                            # Decrypt list items that are encrypted strings
                            key_name = item[len("encrypted:"):]
                            try:
                                decrypted = self._get_decrypted_password(key_name)
                                if decrypted is not None:
                                    value[i] = decrypted
                            except Exception as e:
                                logging.warning(f"failed to decrypt value for key {key_name}: {str(e)}")
                elif isinstance(value, str) and value.startswith("encrypted:"):
                    # Decrypt string values that start with "encrypted:"
                    key_name = value[len("encrypted:"):]
                    try:
                        decrypted = self._get_decrypted_password(key_name)
                        if decrypted is not None:
                            mapping[key] = decrypted
                    except Exception as e:
                        logging.warning(f"failed to decrypt value for key {key_name}: {str(e)}")

        # Process all sections in the configuration
        for section_name, section_data in self._data.items():
            if isinstance(section_data, dict):
                _decrypt_recursive(section_data)

    def resolve_all_values(self) -> None:
        """Recursively decrypt all encrypted values and resolve all env:VAR_NAME values in the configuration.

        This function performs the same operations as decrypt_all_values, in addition to resolving
        any env:VAR_NAME string values and EnvVarRef objects to their corresponding environment
        variable values.
        """
        def _resolve_recursive(mapping: dict[str, Any]) -> None:
            """Recursively decrypt and resolve values in a mapping."""
            for key, value in mapping.items():
                if isinstance(value, dict):
                    _resolve_recursive(value)
                elif isinstance(value, list):
                    for index, item in enumerate(value):
                        if isinstance(item, dict):
                            _resolve_recursive(item)
                        elif isinstance(item, str):
                            if item.startswith("encrypted:"):
                                # decrypt list items that are encrypted strings
                                key_name = item[len("encrypted:"):]
                                try:
                                    decrypted = self._get_decrypted_password(key_name)
                                    if decrypted is not None:
                                        value[index] = decrypted
                                except Exception as e:
                                    logging.warning(f"failed to decrypt value for key {key_name}: {str(e)}")
                            elif item.startswith("env:"):
                                # resolve env:VAR_NAME values in lists
                                var = item[len("env:"):]
                                if var not in os.environ:
                                    raise RuntimeError(
                                        f"configuration referenced unknown environment variable {var}"
                                    )
                                value[index] = os.environ[var]
                elif isinstance(value, str):
                    if value.startswith("encrypted:"):
                        # decrypt string values that start with "encrypted:"
                        key_name = value[len("encrypted:"):]
                        try:
                            decrypted = self._get_decrypted_password(key_name)
                            if decrypted is not None:
                                mapping[key] = decrypted
                        except Exception as e:
                            logging.warning(f"failed to decrypt value for key {key_name}: {str(e)}")
                    elif value.startswith("env:"):
                        # resolve env:VAR_NAME string values
                        var = value[len("env:"):]
                        if var not in os.environ:
                            raise RuntimeError(
                                f"configuration referenced unknown environment variable {var}"
                            )
                        mapping[key] = os.environ[var]

        # process all values in the configuration
        for key, value in self._data.items():
            if isinstance(value, dict):
                _resolve_recursive(value)

