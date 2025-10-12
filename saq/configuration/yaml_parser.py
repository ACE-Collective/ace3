import copy
import os
import sys
import logging
from typing import Any, Iterable, Iterator, Mapping, MutableMapping, Optional

import yaml

from saq.constants import (
    G_ENCRYPTION_INITIALIZED,
)
from saq.environment import g_boolean
from saq.configuration.encryption import decrypt_password
from saq.configuration.error import ConfigurationException


class EnvVarRef:
    """Represents a reference to an environment variable in YAML."""

    def __init__(self, variable_name: str) -> None:
        self.variable_name = variable_name

    def __repr__(self) -> str:  # pragma: no cover - debug representation
        return f"EnvVarRef({self.variable_name!r})"


class EncryptedRef:
    """Represents a reference to an encrypted password in YAML."""

    def __init__(self, key: str) -> None:
        self.key = key

    def __repr__(self) -> str:  # pragma: no cover - debug representation
        return f"EncryptedRef({self.key!r})"


def _yaml_env_constructor(loader: yaml.Loader, node: yaml.Node) -> EnvVarRef:
    # Accept both scalar like "!env VAR_NAME" and mapping with {name: VAR_NAME}
    if isinstance(node, yaml.ScalarNode):
        return EnvVarRef(loader.construct_scalar(node))
    data = loader.construct_mapping(node)
    return EnvVarRef(str(data.get("name", "")))


def _yaml_enc_constructor(loader: yaml.Loader, node: yaml.Node) -> EncryptedRef:
    if isinstance(node, yaml.ScalarNode):
        return EncryptedRef(loader.construct_scalar(node))
    data = loader.construct_mapping(node)
    return EncryptedRef(str(data.get("key", "")))


class YAMLSectionProxy(MutableMapping[str, Any]):
    """A mapping-like proxy for a section that resolves special values on access.

    Applies interpolation when reading values.
    """

    def __init__(self, parent: "YAMLConfig", section_name: str, mapping: dict[str, Any]):
        self._parent = parent
        self.name = section_name
        self._mapping = mapping

    def __getitem__(self, key: str) -> Any:
        raw = self._mapping[key]
        return self._parent._resolve_value(raw)

    def get(self, key: str, fallback: Optional[Any] = None) -> Any:  # type: ignore[override]
        if key in self._mapping:
            return self.__getitem__(key)

        return fallback

    def getint(self, key: str, fallback: Optional[int] = None) -> Optional[int]:
        if key in self._mapping:
            return int(self._parent._resolve_value(self._mapping[key]))

        return fallback

    def getboolean(self, key: str, fallback: Optional[bool] = None) -> Optional[bool]:
        if key in self._mapping:
            return bool(self._parent._resolve_value(self._mapping[key]))

        return fallback

    def __setitem__(self, key: str, value: Any) -> None:
        self._mapping[key] = value

    def __delitem__(self, key: str) -> None:
        del self._mapping[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._mapping)

    def __len__(self) -> int:
        return len(self._mapping)

    def items(self) -> Iterable[tuple[str, Any]]:  # type: ignore[override]
        for k, v in self._mapping.items():
            yield k, self._parent._resolve_value(v)


class YAMLConfig(MutableMapping[str, YAMLSectionProxy]):
    """YAML-based configuration interface.

    - Top-level keys are treated as sections.
    - Values in sections are key/value pairs.
    - Supports references:
      - env:VAR and !env VAR
      - encrypted:KEY and !enc KEY
    - Supports recursive includes via top-level 'config' mapping or list of paths.
    """

    def __init__(self) -> None:
        self._data: dict[str, dict[str, Any]] = {}
        self.encrypted_password_cache: dict[str, Optional[str]] = {}
        self.loaded_files: set[str] = set()

        # Prepare YAML loader with custom tags
        class _Loader(yaml.SafeLoader):
            pass

        _Loader.add_constructor("!env", _yaml_env_constructor)
        _Loader.add_constructor("!enc", _yaml_enc_constructor)

        self._yaml_loader_cls = _Loader

    # MutableMapping protocol over sections
    def __getitem__(self, section: str) -> YAMLSectionProxy:
        return YAMLSectionProxy(self, section, self._data[section])

    def __setitem__(self, section: str, value: Mapping[str, Any]) -> None:
        # Accept raw dict-like for section assignment
        self._data[section] = dict(value)

    def __delitem__(self, section: str) -> None:
        del self._data[section]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def copy(self) -> "YAMLConfig":
        """Return a deep copy of this YAMLConfig object."""
        new_config = YAMLConfig()
        new_config._data = copy.deepcopy(self._data)
        new_config.encrypted_password_cache = copy.deepcopy(self.encrypted_password_cache)
        new_config.loaded_files = copy.deepcopy(self.loaded_files)
        return new_config

    def sections(self) -> list[str]:
        return list(self._data.keys())

    def has_section(self, section: str) -> bool:
        return section in self._data

    def add_section(self, section: str) -> None:
        self._data[section] = {}

    def get(self, section: str, key: str, fallback: Optional[Any] = None) -> Any:
        if section not in self._data:
            return fallback

        return self[section].get(key, fallback)

    def getint(self, section: str, key: str, fallback: Optional[int] = None) -> Optional[int]:
        if section not in self._data:
            return fallback

        return self[section].getint(key, fallback)
    
    def getboolean(self, section: str, key: str, fallback: Optional[bool] = None) -> Optional[bool]:
        if section not in self._data:
            return fallback

        return self[section].getboolean(key, fallback)

    # do resolve behaviors
    def _resolve_value(self, value: Any) -> Any:
        # handle YAML tagged references first
        if isinstance(value, EnvVarRef):
            var = value.variable_name
            if var not in os.environ:
                raise RuntimeError(
                    f"configuration referenced unknown environment variable {var}"
                )

            return os.environ[var]

        if isinstance(value, EncryptedRef):
            key = value.key
            if not g_boolean(G_ENCRYPTION_INITIALIZED):
                return f"encrypted:{key}"
            try:
                return self._get_decrypted_password(key)
            except Exception as e:
                # XXX this is wrong
                return str(e)

        # then support string prefix forms
        if isinstance(value, str):
            if value.startswith("env:"):
                var = value[len("env:") :]
                if var not in os.environ:
                    raise RuntimeError(
                        f"configuration referenced unknown environment variable {var}"
                    )

                return os.environ[var]

            if value.startswith("encrypted:"):
                key = value[len("encrypted:") :]
                if not g_boolean(G_ENCRYPTION_INITIALIZED):
                    return value
                try:
                    return self._get_decrypted_password(key)
                except Exception as e:
                    # XXX this is wrong
                    return str(e)

        # otherwise no special handling
        return value

    def _get_decrypted_password(self, key: str) -> Optional[str]:
        try:
            return self.encrypted_password_cache[key]
        except KeyError:
            pass

        self.encrypted_password_cache[key] = decrypt_password(key)
        return self.encrypted_password_cache[key]

    def apply(self, other: Mapping[str, Mapping[str, Any]]) -> None:
        """Overlay configuration from another mapping-like object.

        For sections present in both, keys are overwritten by values from 'other'.
        """
        for section_name, mapping in other.items():
            if section_name in self._data:
                self._data[section_name].update(dict(mapping))
            else:
                self._data[section_name] = dict(mapping)

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

        # support relative paths as-is (consistent with current behavior)
        yaml_root = self._load_yaml_file(path)

        # convert YAML root mapping into sections
        # each top-level key is a section
        # except an optional top-level 'config' used for includes (handled later)
        for top_key, top_value in yaml_root.items():
            if top_key == "config":
                # handled by resolve_references
                continue

            if isinstance(top_value, dict):
                # section mapping
                section_mapping: dict[str, Any] = {
                    str(k): v for k, v in top_value.items()
                }

                if top_key in self._data:
                    self._data[top_key].update(section_mapping)
                else:
                    self._data[top_key] = section_mapping

            else:
                # if a scalar is found at top-level, treat it as a section-less key by
                # putting it under a pseudo section named by the key
                self._data[top_key] = {"value": top_value}

        self.loaded_files.add(path)
        self.resolve_references(yaml_root)
        return True

    def resolve_references(self, yaml_root: Optional[dict[str, Any]] = None) -> None:
        """Recursively load additional configuration files from 'config'.

        The 'config' field may be a mapping of names->path or a list of paths.
        """
        if yaml_root is None:
            # reconstruct a synthetic root from current data to look for includes under a 'config' section
            yaml_root = {}
            if "config" in self._data:
                yaml_root["config"] = self._data["config"]

        includes = yaml_root.get("config") if isinstance(yaml_root, dict) else None
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
                        logging.info(f"Skipping non-existent YAML include path in YAML config: {include_path}")
                        continue

                    loaded_any = self.load_file(include_path) or loaded_any
                else:
                    logging.warning(
                        f"Skipping non-YAML include path in YAML config: {include_path}"
                    )

            if not loaded_any:
                break

    def verify(self) -> bool:
        """verify that no setting is left with value 'OVERRIDE'."""
        errors: dict[str, list[str]] = {}
        for section_name, mapping in self._data.items():
            if not isinstance(mapping, dict):
                continue

            for value_name, value in mapping.items():
                resolved = self._resolve_value(value)
                if resolved == "OVERRIDE":
                    errors.setdefault(section_name, []).append(value_name)

        if errors:
            for section_name, names in errors.items():
                sys.stderr.write(f"[{section_name}]\n")
                for value_name in names:
                    sys.stderr.write(f"{value_name} = \n")
                sys.stderr.write("\n")

            sys.stderr.write(
                "missing overrides detection in configuration settings\n"
            )

            sys.stderr.write(
                "you can copy-paste the above into your config file if you do not need these settings\n\n"
            )

            raise ConfigurationException("missing OVERRIDES in configuration")

        return True

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

