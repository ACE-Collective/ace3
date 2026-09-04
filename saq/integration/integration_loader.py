import importlib
import logging
import os
import sys

from saq.configuration.config import get_config
from saq.environment import get_global_runtime_settings
from saq.error import report_exception
from saq.integration.integration_manager import is_integration_enabled
from saq.integration.integration_util import (
    get_integration_name_from_path,
    get_valid_integration_dirs,
)

# Warnings raised by initialize_integrations(), which runs at saq/environment.py:189 -- BEFORE
# initialize_logging() at :228. Anything logged there goes to the un-configured root logger and is
# lost, so stash it here and let the caller re-emit once logging is up.
DEFERRED_INTEGRATION_WARNINGS: list[str] = []


def discover_integration_packages(dir_path: str) -> list[str]:
    """Returns the importable top level package names under <dir_path>/src."""
    src_path = os.path.join(dir_path, "src")
    if not os.path.isdir(src_path):
        return []

    return sorted(
        name for name in os.listdir(src_path)
        if os.path.isfile(os.path.join(src_path, name, "__init__.py"))
    )


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
    imported: set[str] = set()

    for integration_config in get_config().integrations:

        #
        # this is what allows any hooks defined in the integration to execute
        #

        try:
            importlib.import_module(integration_config.python_module)
            imported.add(integration_config.python_module)
        except Exception as e:
            logging.error(f"failed to import integration module {integration_config.name}: {e}")
            report_exception()

    _warn_about_undeclared_integrations(imported)


def _warn_about_undeclared_integrations(imported: set[str]):
    """Warns about an integration directory that declares no integration_<name>: block.

    Such a directory is still discovered: its src/ goes on the path and its etc/saq.integration.yaml
    is merged, so its analysis modules and services look configured. But nothing ever imports the
    package, so every module level register_integration_configuration(), register_directive(),
    register_observable_action() and register_integration_blueprint_callback() call in it silently
    never runs. The resulting failures are invisible -- a missing integration config surfaces only as
    a swallowed constructor exception in saq/modules/adapter.py, and a missing observable action or
    GUI blueprint surfaces as nothing at all. This is what shipped broken in 3.0.101.
    """
    for dir_path in get_valid_integration_dirs():
        integration_name = get_integration_name_from_path(dir_path)

        if not is_integration_enabled(integration_name):
            continue

        packages = discover_integration_packages(dir_path)

        # warn per directory rather than per package: an integration with more than one package
        # under src/ only needs one of them declared for its hooks to run
        if not packages or any(package in imported for package in packages):
            continue

        for package in packages:
            message = (
                f"integration {integration_name} ({dir_path}) declares no 'integration_*:' block in "
                f"etc/saq.integration.yaml, so its package {package!r} is never imported and none of "
                f"its registration hooks run. Add:\n"
                f"integration_{integration_name}:\n"
                f"  name: {integration_name}\n"
                f"  enabled: true\n"
                f"  description: \"<describe the integration>\"\n"
                f"  python_module: {package}")

            DEFERRED_INTEGRATION_WARNINGS.append(message)
            # logging is not configured yet at this point in startup -- see the note on
            # DEFERRED_INTEGRATION_WARNINGS above
            sys.stderr.write(f"WARNING: {message}\n")

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
