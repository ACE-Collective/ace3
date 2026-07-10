import logging
import os
from typing import TYPE_CHECKING, Any, Type

import yaml

if TYPE_CHECKING:
    from saq.collectors.hunter.base_hunter import HuntConfig

INCLUDE_DIRECTIVE = "include"


def _get_observable_mapping_identity(item: Any) -> tuple[str, frozenset[str]] | None:
    """Returns a hashable identity for observable mapping dicts, or None.

    Identity is (type, frozenset(fields)) where fields is normalized from
    either the 'fields' list or the singular 'field' string. When both are
    present, 'fields' takes precedence (matching Pydantic validation behavior).
    """
    if not isinstance(item, dict) or "type" not in item:
        return None
    fields = item.get("fields")
    if not fields:
        field = item.get("field")
        if field:
            fields = [field]
        else:
            return None
    return (item["type"], frozenset(fields))


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Deeply merges two dictionaries.

    For each key in override:
    - If the value is a simple value (not dict or list), it replaces the base value
    - If the value is a list, new items are added to the base list, avoiding duplicates
    - If the value is a dict, it recursively merges with the base dict

    Args:
        base: The base dictionary to merge into
        override: The dictionary whose values will override/extend the base

    Returns:
        The merged dictionary
    """
    result = base.copy()

    for key, value in override.items():
        if key not in result:
            # key doesn't exist in base, just add it
            result[key] = value
        elif isinstance(value, dict) and isinstance(result[key], dict):
            # both are dicts, recursively merge
            result[key] = deep_merge(result[key], value)
        elif isinstance(value, list) and isinstance(result[key], list):
            # copy the list to avoid mutating the original base dict's list
            result[key] = list(result[key])
            # build identity map for observable mapping entries in the base list
            identity_map: dict[tuple[str, frozenset[str]], int] = {}
            for i, existing in enumerate(result[key]):
                identity = _get_observable_mapping_identity(existing)
                if identity is not None:
                    identity_map[identity] = i
            # merge override items
            for item in value:
                identity = _get_observable_mapping_identity(item)
                if identity is not None and identity in identity_map:
                    # replace matching observable mapping entry in place
                    result[key][identity_map[identity]] = item
                elif item not in result[key]:
                    result[key].append(item)
        else:
            # simple value or type mismatch, override
            result[key] = value

    return result

def _resolve_file_paths_in_dict(loaded_dict: dict[str, Any], yaml_dir: str) -> None:
    """Resolve relative file paths in a loaded YAML dict to absolute paths.

    Mutates the dict in-place. Resolves paths in command path fields relative
    to yaml_dir (the directory of the YAML file that defines them).
    """
    # Predefined commands (top-level)
    for cmd in loaded_dict.get("commands", []):
        if cmd.get("path") and not os.path.isabs(cmd["path"]):
            cmd["path"] = os.path.normpath(os.path.join(yaml_dir, cmd["path"]))
        for i, f in enumerate(cmd.get("files") or []):
            if not os.path.isabs(f):
                cmd["files"][i] = os.path.normpath(os.path.join(yaml_dir, f))

    # Inline executable commands in correlate logic
    rule = loaded_dict.get("rule", {})
    correlate = rule.get("correlate", {})
    if correlate:
        _resolve_command_paths_in_steps(correlate.get("logic", []), yaml_dir)


def _resolve_command_paths_in_steps(steps: list, yaml_dir: str) -> None:
    """Recursively walk correlate logic steps to resolve relative command paths."""
    for step in steps:
        if "transform" in step:
            transform = step["transform"]
            cmd = transform.get("command", {}) if isinstance(transform, dict) else {}
            if cmd.get("type") == "executable" and cmd.get("path") and not os.path.isabs(cmd["path"]):
                cmd["path"] = os.path.normpath(os.path.join(yaml_dir, cmd["path"]))
            for i, f in enumerate(cmd.get("files") or []):
                if not os.path.isabs(f):
                    cmd["files"][i] = os.path.normpath(os.path.join(yaml_dir, f))
        if "when" in step:
            _resolve_command_paths_in_steps(step.get("execute", []), yaml_dir)
            _resolve_command_paths_in_steps(step.get("else", []), yaml_dir)


def _load_and_merge_yaml(path: str, resolved_history: set[str]) -> dict[str, Any]:
    """Recursively loads and merges a YAML file with its includes.

    Args:
        path: the path to the YAML file to load
        resolved_history: set of already resolved file paths to prevent circular references

    Returns:
        The merged dictionary from this file and all its includes
    """
    logging.debug(f"loading {path}")

    try:
        with open(path, "r", encoding="utf-8") as fp:
            loaded_dict = yaml.safe_load(fp)
    except Exception as e:
        logging.error(f"unable to load file {path}: {e}")
        raise

    # Resolve relative file paths before merging so paths are relative to
    # the YAML file that defines them, not the root or including file.
    yaml_dir = os.path.dirname(os.path.abspath(path))
    _resolve_file_paths_in_dict(loaded_dict, yaml_dir)

    # start with empty result
    result: dict[str, Any] = {}

    # are there any include directives?
    if INCLUDE_DIRECTIVE in loaded_dict:
        # include directives must be a list of strings
        if not isinstance(loaded_dict[INCLUDE_DIRECTIVE], list):
            raise ValueError(f"include directives must be a list of strings in {path}")

        # process includes in order
        for include_path in loaded_dict[INCLUDE_DIRECTIVE]:
            # paths that are relative are relative to the current file
            if not os.path.isabs(include_path):
                include_path = os.path.join(os.path.dirname(path), include_path)

            # skip if we've already resolved this file (prevents circular references)
            if include_path in resolved_history:
                logging.debug(f"skipping already resolved {include_path}")
                continue

            # add to resolved history before recursing
            resolved_history.add(include_path)

            # recursively load and merge the included file
            logging.debug(f"including {include_path} from {path}")
            included_result = _load_and_merge_yaml(include_path, resolved_history)

            # merge the included file's result into our result
            result = deep_merge(result, included_result)

        # remove the include directive from the loaded dictionary
        loaded_dict.pop(INCLUDE_DIRECTIVE)

    # finally, merge the current file's content (which will override includes)
    result = deep_merge(result, loaded_dict)

    return result


def load_merged_yaml(path: str) -> tuple[dict[str, Any], set[str]]:
    """Loads and merges a hunt YAML (with includes) without pydantic validation.

    Returns:
        A tuple of (the merged raw dict, the set of all file paths that were loaded).
    """
    resolved_history: set[str] = set()
    resolved_history.add(path)
    result = _load_and_merge_yaml(path, resolved_history)
    return result, resolved_history


def peek_hunt_type(path: str) -> str:
    """Returns the `rule.type` field of a hunt YAML without validating the rest.

    Used when a caller needs to route to the correct hunt subclass before
    invoking that subclass's full pydantic validation.
    """
    merged, _ = load_merged_yaml(path)
    rule = merged.get("rule")
    if not isinstance(rule, dict):
        raise ValueError(f"hunt YAML {path} is missing top-level 'rule' mapping")
    hunt_type = rule.get("type")
    if not isinstance(hunt_type, str) or not hunt_type:
        raise ValueError(f"hunt YAML {path} is missing 'rule.type'")
    return hunt_type


def load_from_yaml(path: str, config_type: Type["HuntConfig"]) -> tuple["HuntConfig", set[str]]:
    """Loads a hunt configuration from a YAML file.

    Args:
        path: the path to the YAML file to load
        config_type: the type of configuration to load

    Returns:
        A tuple of (the loaded configuration object, set of all file paths that were loaded including the main file and all included files).
    """

    logging.debug(f"loading {path} from {config_type.__name__}")

    # recursively load and merge
    result, resolved_history = load_merged_yaml(path)

    # and then return the validated configuration object and all file paths that were loaded
    config = config_type.model_validate(result["rule"])

    # extract predefined commands from top-level YAML if present
    predefined_commands = []
    if "commands" in result:
        from saq.collectors.hunter.correlation.schema import PredefinedCommandConfig
        for cmd_data in result["commands"]:
            predefined_commands.append(PredefinedCommandConfig.model_validate(cmd_data))
    config._predefined_commands = predefined_commands

    return config, resolved_history
