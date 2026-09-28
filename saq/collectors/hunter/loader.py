import logging
import os
import re
from typing import TYPE_CHECKING, Any, Iterator, Type

import yaml

from saq.configuration import get_config
from saq.environment import get_data_dir
from saq.util import abs_path

if TYPE_CHECKING:
    from saq.collectors.hunter.base_hunter import HuntConfig

INCLUDE_DIRECTIVE = "include"

# a query pulls in another file with <include:path> (expanded by SplunkHunt.query)
QUERY_INCLUDE_PATTERN = re.compile(r"<include:([^>]+)>")


class HuntFileOutsideRootError(ValueError):
    """A hunt names a file outside the directory it is confined to."""


def _is_under(path: str, root: str) -> bool:
    real_root = os.path.realpath(root)
    return os.path.commonpath([os.path.realpath(path), real_root]) == real_root


def get_compiled_hunt_dir() -> str:
    """Return a directory for compiled hunt temp files that supports execution.

    The default temp directory (/tmp) may be mounted as a noexec tmpfs in Docker,
    preventing extracted scripts from being executed. This uses a configurable
    subdirectory under the data directory instead.
    """
    path = os.path.join(get_data_dir(), get_config().global_settings.compiled_hunt_dir)
    os.makedirs(path, exist_ok=True)
    return path


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


def _load_and_merge_yaml(path: str, resolved_history: set[str], file_root: str | None = None) -> dict[str, Any]:
    """Recursively loads and merges a YAML file with its includes.

    Args:
        path: the path to the YAML file to load
        resolved_history: set of already resolved file paths to prevent circular references
        file_root: when set, this file and every file it includes must lie under it;
            HuntFileOutsideRootError is raised before a file outside it is opened

    Returns:
        The merged dictionary from this file and all its includes
    """
    if file_root is not None and not _is_under(path, file_root):
        raise HuntFileOutsideRootError(f"hunt file {path} is outside {file_root}")

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
            included_result = _load_and_merge_yaml(include_path, resolved_history, file_root)

            # merge the included file's result into our result
            result = deep_merge(result, included_result)

        # remove the include directive from the loaded dictionary
        loaded_dict.pop(INCLUDE_DIRECTIVE)

    # finally, merge the current file's content (which will override includes)
    result = deep_merge(result, loaded_dict)

    return result


def load_merged_yaml(path: str, file_root: str | None = None) -> tuple[dict[str, Any], set[str]]:
    """Loads and merges a hunt YAML (with includes) without pydantic validation.

    Args:
        path: the hunt YAML
        file_root: when set, the hunt and every file it includes must lie under it (see
            _load_and_merge_yaml)

    Returns:
        A tuple of (the merged raw dict, the set of all file paths that were loaded).
    """
    resolved_history: set[str] = set()
    resolved_history.add(path)
    result = _load_and_merge_yaml(path, resolved_history, file_root)
    return result, resolved_history


def _strings_in(value: Any) -> Iterator[str]:
    """Every string anywhere in a loaded YAML value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings_in(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings_in(item)


def _commands_in(merged: dict[str, Any]) -> Iterator[dict]:
    """The predefined commands and every inline correlate command of a merged hunt."""
    for command in merged.get("commands") or []:
        if isinstance(command, dict):
            yield command

    rule = merged.get("rule")
    correlate = rule.get("correlate") if isinstance(rule, dict) else None
    steps = list(correlate.get("logic") or []) if isinstance(correlate, dict) else []
    while steps:
        step = steps.pop()
        if not isinstance(step, dict):
            continue
        transform = step.get("transform")
        if isinstance(transform, dict) and isinstance(transform.get("command"), dict):
            yield transform["command"]
        if "when" in step:
            for branch in (step.get("execute"), step.get("else")):
                if isinstance(branch, list):
                    steps.extend(branch)


def find_hunt_files_outside(path: str, root: str) -> list[str]:
    """Describe every file the hunt at path would read that lies outside root.

    The validation API materializes a submitted hunt into a directory of its own, and the hunt
    compiler only packages files from inside the package, so nothing a genuine submission names
    lies outside that directory. The hunt is still client-supplied, so this walks every way a hunt
    names a file -- `include:`, the query file (`search`), `<include:...>` markers in query text
    and in the files they pull in, and commands' executable `path` and `files` -- and reports the
    ones outside root. It never opens a file outside root.

    Raises whatever loading the hunt YAML raises (FileNotFoundError, yaml.YAMLError, ValueError).
    """
    try:
        merged, _ = load_merged_yaml(path, file_root=root)
    except HuntFileOutsideRootError as e:
        return [str(e)]

    problems: list[str] = []

    def inside(file_path: str, what: str) -> bool:
        if _is_under(file_path, root):
            return True

        problem = f"{what} {file_path} is outside the submitted hunt"
        if problem not in problems:
            problems.append(problem)

        return False

    rule = merged.get("rule") if isinstance(merged.get("rule"), dict) else {}

    # query text, plus the query file and the files its <include:...> markers pull in
    texts = list(_strings_in(rule))
    for field in ("search", "query_file_path"):
        query_file = rule.get(field)
        if not isinstance(query_file, str):
            continue

        # the hunt reads its query file through abs_path (saq.query.config.load_query_from_file)
        query_path = abs_path(query_file)
        if inside(query_path, "query file") and os.path.isfile(query_path):
            with open(query_path, "r", encoding="utf-8", errors="replace") as fp:
                texts.append(fp.read())

    seen: set[str] = set()
    while texts:
        for include in QUERY_INCLUDE_PATTERN.findall(texts.pop()):
            # SplunkHunt.query opens the path as written, relative to the working directory
            include_path = os.path.abspath(include)
            if include_path in seen:
                continue

            seen.add(include_path)
            if inside(include_path, "query include") and os.path.isfile(include_path):
                with open(include_path, "r", encoding="utf-8", errors="replace") as fp:
                    texts.append(fp.read())

    for command in _commands_in(merged):
        if command.get("type") == "executable" and isinstance(command.get("path"), str):
            inside(command["path"], "executable")
        files = command.get("files")
        for file_path in files if isinstance(files, list) else []:
            if isinstance(file_path, str):
                inside(file_path, "file")

    return problems


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
