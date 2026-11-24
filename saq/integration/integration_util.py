import logging
import os

from saq.environment import get_base_dir, get_data_dir

def get_integration_base_dir() -> str:
    """Returns the absolute path to where integrations are stored."""
    return os.path.join(get_base_dir(), "integrations")

def get_integration_var_base_dir() -> str:
    """Returns the absolute path to where integration state variables are stored."""
    return os.path.join(get_data_dir(), "var", "integrations")

def get_integration_config_path(dir_path: str) -> str:
    """Returns the path of the configuration file the loader merges for the integration directory."""
    return os.path.join(dir_path, "etc", "saq.integration.yaml")

def get_integration_name_from_path(dir_path: str) -> str:
    """Returns the name of the integration from the directory path."""
    if not dir_path:
        raise ValueError("integration directory path is empty")

    if dir_path.endswith("/"):
        raise ValueError(f"integration directory path {dir_path} must not end with a slash")

    return os.path.basename(dir_path)

def validate_integration_dir(dir_path: str) -> bool:
    """Validates an integration directory.

    Args:
        dir_path: The path to the integration directory.

    Returns:
        True if the integration directory is valid, False otherwise.
    """
    if not os.path.exists(dir_path):
        logging.debug(f"integration directory {dir_path} does not exist")
        return False

    if not os.path.isdir(dir_path):
        logging.debug(f"integration directory {dir_path} is not a directory")
        return False

    if not os.path.exists(os.path.join(dir_path, "integration.md")):
        logging.debug(f"integration directory {dir_path} does not contain an integration.md file")
        return False

    return True

def _recurse_integration_dirs(target_path: str) -> list[str]:
    """Recursively finds all integration directories in the given directory.

    Dot-directories are skipped: a repository holding several integrations has its .git beside
    them, and every ace command and service start runs this scan more than once.
    """
    valid_dirs: list[str] = []
    if not os.path.isdir(target_path):
        return []

    for target_name in os.listdir(target_path):
        if target_name.startswith("."):
            continue

        new_target_path = os.path.join(target_path, target_name)
        if validate_integration_dir(new_target_path):
            valid_dirs.append(new_target_path)
        elif os.path.isdir(new_target_path):
            valid_dirs.extend(_recurse_integration_dirs(new_target_path))

    return valid_dirs

def get_valid_integration_dirs() -> list[str]:
    """Returns a list of all valid integration directories."""
    return _recurse_integration_dirs(get_integration_base_dir())

def get_integration_path_from_name(name: str) -> str:
    """Returns the path to the integration directory whose basename matches ``name``.

    Searches recursively under :func:`get_integration_base_dir` for valid integration
    directories (those containing ``integration.md``) and returns the unique match.

    Raises:
        FileNotFoundError: no valid integration directory has the given basename.
        ValueError: more than one valid integration directory has the given basename.
    """
    matches = [d for d in get_valid_integration_dirs() if os.path.basename(d) == name]

    if not matches:
        raise FileNotFoundError(
            f"no integration directory with basename {name!r} found under {get_integration_base_dir()}"
        )
    if len(matches) > 1:
        raise ValueError(
            f"ambiguous integration name {name!r}: multiple directories match: {matches}"
        )
    return matches[0]
