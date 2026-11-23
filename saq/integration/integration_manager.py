import os
from saq.integration.integration_util import get_integration_var_base_dir

def _ensure_var_dir_exists(var_dir: str):
    if not os.path.exists(var_dir):
        os.makedirs(var_dir)

def _get_disabled_path(var_dir: str) -> str:
    return os.path.join(var_dir, "disabled")

def enable_integration(name: str) -> bool:
    """Enables the integration. This is done by removing the disabled file if it exists."""
    var_dir = os.path.join(get_integration_var_base_dir(), name)
    disabled_path = _get_disabled_path(var_dir)
    if os.path.exists(disabled_path):
        os.remove(disabled_path)

    return not os.path.exists(disabled_path)

def disable_integration(name: str):
    """Disables the integration. This is done by creating a disabled file in the integration's var directory."""
    var_dir = os.path.join(get_integration_var_base_dir(), name)
    _ensure_var_dir_exists(var_dir)
    disabled_path = _get_disabled_path(var_dir)
    if not os.path.exists(disabled_path):
        with open(disabled_path, "w") as _:
            pass

    return os.path.exists(disabled_path)

def is_integration_enabled(name: str) -> bool:
    """Returns True if the integration is enabled, False otherwise.
    
    Parameters
    ----------
    dir_path : str
        The path to the integration directory.
    """
    var_dir = os.path.join(get_integration_var_base_dir(), name)
    disabled_path = _get_disabled_path(var_dir)
    return not os.path.exists(disabled_path)