import configparser
import os
import sys
from typing import Any, Optional

from saq.configuration.loader import load_configuration

# global configuration singleton (INI or YAML-backed)
CONFIG = None

def get_config():
    """Returns the global configuration object (INI ConfigParser or YAMLConfig)."""
    return CONFIG

def get_config_value(section: str, name: str, default: Optional[Any] = None) -> Optional[str]:
    cfg = get_config()
    if section not in cfg:
        return default

    value = cfg[section].get(name, default)
    if value is None:
        return default

    return value if isinstance(value, str) else str(value)

def get_config_value_as_int(section: str, name: str, default: Optional[Any] = None) -> Optional[int]:
    cfg = get_config()
    if section not in cfg:
        return default

    section_proxy = cfg[section]
    if hasattr(section_proxy, 'getint'):
        try:
            return section_proxy.getint(name, default)  # type: ignore[attr-defined]
        except Exception:
            return default

    value = section_proxy.get(name, None) if hasattr(section_proxy, 'get') else None
    if value is None:
        return default
    if isinstance(value, int):
        return value

    try:
        return int(str(value).strip())
    except Exception:
        return default

def get_config_value_as_boolean(section: str, name: str, default: Optional[Any] = None) -> Optional[bool]:
    cfg = get_config()
    if section not in cfg:
        return default

    section_proxy = cfg[section]
    if hasattr(section_proxy, 'getboolean'):
        try:
            return section_proxy.getboolean(name, default)  # type: ignore[attr-defined]
        except Exception:
            return default

    value = section_proxy.get(name, None) if hasattr(section_proxy, 'get') else None
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    s = str(value).strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True

    if s in {"0", "false", "no", "off"}:
        return False

    return default

def get_config_value_as_list(section: str, name: str, default: Optional[list[str]] = None, sep: Optional[str] = ",", include_empty: Optional[bool] = True) -> Optional[list[str]]:
    cfg = get_config()
    if section not in cfg:
        return default

    section_proxy = cfg[section]
    value = section_proxy.get(name, None) if hasattr(section_proxy, 'get') else None
    if value is None:
        return default

    if isinstance(value, list):
        result = [str(v).strip() for v in value]
        return result if include_empty else [v for v in result if v]

    s = str(value)
    parts = [_.strip() for _ in s.split(sep)] if sep is not None else [s]
    return parts if include_empty else [p for p in parts if p]

def set_config(config):
    global CONFIG
    CONFIG = config

def initialize_configuration(config_paths: Optional[list[str]]=None):
    global CONFIG

    # load configuration files
    if config_paths is None:
        config_paths = []
    
    CONFIG_PATHS = []

    # add any config files specified in SAQ_CONFIG_PATHS env var (command separated)
    if "SAQ_CONFIG_PATHS" in os.environ:
        for config_path in os.environ["SAQ_CONFIG_PATHS"].split(","):
            config_path = config_path.strip()
            if not os.path.exists(config_path):
                sys.stderr.write(f"WARNING: config path {config_path} specified in SAQ_CONFIG_PATHS env var does not exist\n")
            else:
                if config_path not in CONFIG_PATHS:
                    CONFIG_PATHS.append(config_path)

    # and then add any specified on the command line
    for config_path in config_paths:
        if not os.path.isabs(config_path):
            if not os.path.exists(config_path):
                sys.stderr.write(f"WARNING: config path {config_path} specified on the command line does not exist\n")
            else:
                if config_path not in CONFIG_PATHS:
                    CONFIG_PATHS.append(config_path)

    try:
        CONFIG = load_configuration()
    except Exception as e:
        sys.stderr.write(f"ERROR: unable to load configuration: {e}")
        raise