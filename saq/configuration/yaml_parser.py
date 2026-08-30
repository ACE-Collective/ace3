import copy
import os
import sys
import logging
from typing import Any

from deepmerge import Merger
import yaml

from saq.environment import get_base_dir

ENV_PREFIX = "env:"
ENCRYPTED_PREFIX = "encrypted:"
FILE_PREFIX = "file:"


class DuplicateKeyWarningLoader(yaml.SafeLoader):
    """SafeLoader that says something when a mapping declares the same key twice.

    YAML silently keeps the last value for a duplicate key, which makes a whole class of
    config defect invisible. A missing `analysis_mode_cli:` section header once left that
    mode's keys sitting inside the `analysis_mode_analysis:` mapping, quietly redefining
    the wrong mode and leaving the engine's default_analysis_mode pointing at nothing --
    and nobody noticed for months.

    Deliberately a warning rather than an error: a duplicate key anywhere in a site's own
    SAQ_CONFIG_PATHS overlay or an integration's etc/<name>.yaml would otherwise stop the
    engine from starting. Last-wins semantics are unchanged.
    """

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            try:
                key = self.construct_object(key_node, deep=deep)
            except Exception:
                # unhashable or unconstructable keys are the base class's problem, not ours
                continue

            try:
                if key in seen:
                    logging.warning(
                        "%s:%d: duplicate key %r in mapping - the last value wins",
                        key_node.start_mark.name,
                        key_node.start_mark.line + 1,
                        key,
                    )
                else:
                    seen.add(key)
            except TypeError:
                continue

        return super().construct_mapping(node, deep=deep)


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
        self.loaded_files: set[str] = set()
        self._yaml_loader_cls = DuplicateKeyWarningLoader

    def copy(self) -> "YAMLConfig":
        """Return a deep copy of this YAMLConfig object."""
        new_config = YAMLConfig()
        new_config._data = copy.deepcopy(self._data)
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

            # NOTE: encrypted:<name> is intentionally NOT resolved here. Encrypted secrets are now
            # resolved lazily at point-of-use via SecretRef (saq/configuration/secret_ref.py); the
            # marker is left intact so it validates into a SecretRef field. See resolve_all_values.

            if value.startswith(FILE_PREFIX):
                path = value[len(FILE_PREFIX):]
                if not os.path.isabs(path):
                    path = os.path.join(get_base_dir(), path)
                with open(path, "r", encoding="utf-8") as f:
                    return f.read().rstrip()

        # otherwise no special handling
        return value

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

    def resolve_all_values(self) -> None:
        """Recursively resolve env:VAR_NAME and file:PATH values in the configuration, in place.

        encrypted:<name> markers are intentionally left unresolved: encrypted secrets are resolved
        lazily at point-of-use via SecretRef (saq/configuration/secret_ref.py), so the marker must
        survive into model validation where it becomes a SecretRef field.
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
                            # encrypted:<name> is intentionally left unresolved -- resolved lazily at
                            # point-of-use via SecretRef (saq/configuration/secret_ref.py)
                            if item.startswith("env:"):
                                # resolve env:VAR_NAME values in lists
                                var = item[len("env:"):]
                                if var not in os.environ:
                                    raise RuntimeError(
                                        f"configuration referenced unknown environment variable {var}"
                                    )
                                value[index] = os.environ[var]
                            elif item.startswith("file:"):
                                file_path = item[len("file:"):]
                                if not os.path.isabs(file_path):
                                    file_path = os.path.join(get_base_dir(), file_path)
                                with open(file_path, "r", encoding="utf-8") as f:
                                    value[index] = f.read().rstrip()
                elif isinstance(value, str):
                    # encrypted:<name> is intentionally left unresolved -- resolved lazily at
                    # point-of-use via SecretRef (saq/configuration/secret_ref.py)
                    if value.startswith("env:"):
                        # resolve env:VAR_NAME string values
                        var = value[len("env:"):]
                        if var not in os.environ:
                            raise RuntimeError(
                                f"configuration referenced unknown environment variable {var}"
                            )
                        mapping[key] = os.environ[var]
                    elif value.startswith("file:"):
                        file_path = value[len("file:"):]
                        if not os.path.isabs(file_path):
                            file_path = os.path.join(get_base_dir(), file_path)
                        with open(file_path, "r", encoding="utf-8") as f:
                            mapping[key] = f.read().rstrip()

        # process all values in the configuration
        for key, value in self._data.items():
            if isinstance(value, dict):
                _resolve_recursive(value)

