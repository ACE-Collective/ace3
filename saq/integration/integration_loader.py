import importlib
import logging
import os
import sys

from saq.configuration.config import get_config
from saq.environment import get_global_runtime_settings
from saq.error import report_exception
from saq.integration.integration_manager import is_integration_enabled
from saq.integration.integration_util import get_integration_base_dir, get_integration_name_from_path

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
    """Recursively finds all integration directories in the given directory."""
    valid_dirs: list[str] = []
    if not os.path.isdir(target_path):
        return []

    for target_name in os.listdir(target_path):
        new_target_path = os.path.join(target_path, target_name)
        if validate_integration_dir(new_target_path):
            valid_dirs.append(new_target_path)
        elif os.path.isdir(new_target_path):
            valid_dirs.extend(_recurse_integration_dirs(new_target_path))

    return valid_dirs

def get_valid_integration_dirs() -> list[str]:
    """Returns a list of all valid integration directories."""
    return _recurse_integration_dirs(get_integration_base_dir())

def load_integrations() -> bool:
    """Loads all integrations. Returns True if all defined and enabled integrations were loaded successfully."""
    result = True

    for dir_path in get_valid_integration_dirs():
        try:
            if not is_integration_enabled(get_integration_name_from_path(dir_path)):
                logging.debug(f"integration {get_integration_name_from_path(dir_path)} is disabled, skipping")
                continue

            if load_integration_from_directory(dir_path):
                pass
            else:
                logging.error(f"failed to load integration from {dir_path}")
                result = False
        except Exception as e:
            logging.error(f"failed to load integration from {dir_path}: {e}")
            report_exception()
            result = False

    #initialize_integrations()
    return result

def load_integration_component_src(dir_path: str) -> bool:
    """Loads the source code for a component of an integration.

    Args:
        dir_path: The path to the integration directory.

    Returns:
        True if the source code was loaded successfully, False otherwise.
    """
    src_path = os.path.join(dir_path, "src")
    if os.path.exists(src_path):
        # modify the PYTHONPATH to include the integration directory
        if src_path not in sys.path:
            # NOTE we append rather than prepend here
            sys.path.append(src_path)

    return True

def load_integration_component_bin(dir_path: str) -> bool:
    """Loads the binary for a component of an integration.

    Args:
        dir_path: The path to the integration directory.

    Returns:
        True if the binary was loaded successfully, False otherwise.
    """
    bin_path = os.path.join(dir_path, "bin")
    if os.path.exists(bin_path):
        # modify the PATH to include the integration directory
        if bin_path not in os.environ["PATH"]:
            os.environ["PATH"] = f"{os.environ['PATH']}:{bin_path}"

    return True

def load_integration_component_etc(dir_path: str) -> bool:
    """Loads the configuration files for a component of an integration.

    Args:
        dir_path: The path to the integration directory.

    Returns:
        True if the configuration files were loaded successfully, False otherwise.
    """
    etc_path = os.path.join(dir_path, "etc")

    # load all the ini files found in the etc directory
    if os.path.exists(etc_path):
        auto_load_config_file = os.path.join(etc_path, "saq.integration.yaml")
        if os.path.exists(auto_load_config_file):
            logging.debug(f"auto loading integration configuration file {auto_load_config_file}")
            get_global_runtime_settings().integration_config_paths.append(auto_load_config_file)
            #get_config().load_file(auto_load_config_file)

    return True

def initialize_integrations():
    """Initializes all integrations. 
    This simply imports the module as defined by each integration, giving the module a chance to initialize itself."""
    for integration_config in get_config().integrations:

        #
        # this is what allows any hooks defined in the integration to execute
        #

        try:
            importlib.import_module(integration_config.python_module)
        except Exception as e:
            logging.error(f"failed to import integration module {integration_config.name}: {e}")
            report_exception()

def load_integration_from_directory(dir_path: str) -> bool:
    """Loads an ACE integration from a local directory.

    Args:
        dir_path: The path to the integration directory.

    Returns:
        True if the integration was loaded successfully, False otherwise.
    """
    result = load_integration_component_src(dir_path)
    result |= load_integration_component_bin(dir_path)
    result |= load_integration_component_etc(dir_path)

    # NOTE right now we are not calling verify() on the config
    return result
