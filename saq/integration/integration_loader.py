import importlib
import logging
import os
import sys

from saq.configuration.config import get_config
from saq.environment import get_global_runtime_settings
from saq.integration.integration_manager import is_integration_enabled
from saq.integration.integration_util import (
    get_integration_name_from_path,
    get_valid_integration_dirs,
)


def discover_integration_packages(dir_path: str) -> list[str]:
    """Returns the importable top level package names under <dir_path>/src."""
    src_path = os.path.join(dir_path, "src")
    if not os.path.isdir(src_path):
        return []

    return sorted(
        name for name in os.listdir(src_path)
        if os.path.isfile(os.path.join(src_path, name, "__init__.py"))
    )


def load_integrations():
    """Loads all enabled integrations. One that fails to load is logged and skipped."""
    for dir_path in get_valid_integration_dirs():
        try:
            if not is_integration_enabled(get_integration_name_from_path(dir_path)):
                logging.debug(f"integration {get_integration_name_from_path(dir_path)} is disabled, skipping")
                continue

            load_integration_from_directory(dir_path)
        except Exception as e:
            logging.exception(f"failed to load integration from {dir_path}: {e}")

def load_integration_component_src(dir_path: str):
    """Loads the source code for a component of an integration.

    Args:
        dir_path: The path to the integration directory.
    """
    src_path = os.path.join(dir_path, "src")
    if os.path.exists(src_path):
        # modify the PYTHONPATH to include the integration directory
        if src_path not in sys.path:
            # NOTE we append rather than prepend here
            sys.path.append(src_path)

def load_integration_component_bin(dir_path: str):
    """Loads the binary for a component of an integration.

    Args:
        dir_path: The path to the integration directory.
    """
    bin_path = os.path.join(dir_path, "bin")
    if os.path.exists(bin_path):
        # modify the PATH to include the integration directory
        if bin_path not in os.environ["PATH"]:
            os.environ["PATH"] = f"{os.environ['PATH']}:{bin_path}"

def load_integration_component_etc(dir_path: str):
    """Loads the configuration files for a component of an integration.

    Args:
        dir_path: The path to the integration directory.
    """
    etc_path = os.path.join(dir_path, "etc")

    # load all the ini files found in the etc directory
    if os.path.exists(etc_path):
        auto_load_config_file = os.path.join(etc_path, "saq.integration.yaml")
        if os.path.exists(auto_load_config_file):
            logging.debug(f"auto loading integration configuration file {auto_load_config_file}")
            get_global_runtime_settings().integration_config_paths.append(auto_load_config_file)
            #get_config().load_file(auto_load_config_file)

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
            logging.exception(f"failed to import integration module {integration_config.name}: {e}")

    _warn_about_undeclared_integrations(imported)


def _warn_about_undeclared_integrations(imported: set[str]):
    """Warns about an integration directory that declares no integration_<name>: block.

    Such a directory is still discovered: its src/ goes on the path and its etc/saq.integration.yaml
    is merged, so its analysis modules and services look configured. But nothing ever imports the
    package, so every module level register_integration_configuration(), register_directive(),
    register_observable_action(), register_integration_blueprint_callback() and
    register_integration_router() call in it silently never runs. The resulting failures are
    invisible -- a missing integration config surfaces only as a swallowed constructor exception in
    saq/modules/adapter.py, a missing observable action or GUI blueprint as nothing at all, and a
    missing API router as a 404. This is what shipped broken in 3.0.101.
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

            logging.warning(message)

def load_integration_from_directory(dir_path: str):
    """Loads an ACE integration from a local directory.

    Args:
        dir_path: The path to the integration directory.
    """
    load_integration_component_src(dir_path)
    load_integration_component_bin(dir_path)
    load_integration_component_etc(dir_path)

    # NOTE right now we are not calling verify() on the config
