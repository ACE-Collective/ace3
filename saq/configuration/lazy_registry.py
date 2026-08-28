"""Lazy resolution of plugin-specific configuration classes.

Several config block families (``service_*``, ``analysis_module_*``,
``observable_export_*``) declare a ``python_module`` / ``python_class`` pair whose
``get_config_class()`` returns the Pydantic subclass the block should really be
validated against. Doing that at config-parse time means *every* ACE process imports
*every* service and *every* analysis module just to read its own configuration -- a
couple of seconds and a couple hundred megabytes of resident memory in each of the
cron jobs, CLI commands and forked engine workers, almost none of which ever touch
those plugins.

``LazyConfigRegistry`` keeps the base validation eager (cheap, and it still catches a
missing ``name`` / ``enabled`` / ``python_module``) and defers the import plus the
subclass validation until someone actually asks for that block by name -- or iterates
the whole collection, which forces the lot.
"""

import importlib
import sys
import threading
from typing import Any, Generic, Optional, TypeVar

ConfigT = TypeVar("ConfigT")


class LazyConfigRegistry(Generic[ConfigT]):
    """A name -> config mapping that resolves each config's plugin subclass on demand.

    Entries arrive either as raw config data (:meth:`add_raw`, resolved lazily) or as an
    already-built config object (:meth:`add_resolved`, never imports anything). Once a
    name has been resolved, every later access returns *that same instance* -- callers
    such as ``ace correlate --disable-all`` mutate the config objects they iterate and
    expect the engine to read those mutations back.
    """

    def __init__(self, base_class: type, label: str):
        # the base Pydantic model every block is validated against up front
        self._base_class = base_class
        # human readable description of what this registry holds, used in error output
        # (e.g. "service config", "analysis module config")
        self._label = label
        # name -> config; holds the base config until the name is resolved
        self._configs: dict[str, ConfigT] = {}
        # name -> the raw config data, needed to re-validate against the plugin subclass
        self._raw: dict[str, Any] = {}
        # name -> the top level config key the block came from, used in error output
        self._config_keys: dict[str, str] = {}
        # names whose plugin subclass has already been resolved
        self._resolved: set[str] = set()
        # guards the cache write only -- never held across importlib.import_module, so a
        # plugin that reads configuration while being imported cannot deadlock on it
        self._lock = threading.Lock()

    def add_raw(self, config_key: str, raw: Any) -> ConfigT:
        """Validates raw config data against the base class and stores it for later resolution.

        Returns the base config. The plugin specific subclass is not resolved (and the
        plugin module is not imported) until :meth:`get` or :meth:`values` asks for it.
        """
        try:
            config = self._base_class.model_validate(raw)
        except Exception as e:
            sys.stderr.write(f"CONFIG ERROR: failed to validate {self._label} for {config_key}\n")
            raise e

        name = config.name
        self._configs[name] = config
        self._raw[name] = raw
        self._config_keys[name] = config_key
        self._resolved.discard(name)
        return config

    def add_resolved(self, name: str, config: ConfigT):
        """Stores an already-built config object. Nothing is ever imported for this entry."""
        self._configs[name] = config
        self._raw.pop(name, None)
        self._config_keys.pop(name, None)
        self._resolved.add(name)

    def get(self, name: str) -> ConfigT:
        """Returns the fully resolved config for name, importing its plugin module if needed.

        Raises KeyError if the name is unknown.
        """
        config = self._configs[name]
        if name in self._resolved:
            return config

        config_key = self._config_keys[name]
        try:
            module = importlib.import_module(config.python_module)
            class_definition = getattr(module, config.python_class)
            resolved = class_definition.get_config_class().model_validate(self._raw[name])
        except Exception as e:
            sys.stderr.write(f"CONFIG ERROR: failed to validate {self._label} for {config_key}\n")
            raise e

        with self._lock:
            # another thread may have resolved this name while we were importing -- the
            # duplicate work is harmless, handing out two different objects is not
            if name in self._resolved:
                return self._configs[name]

            self._configs[name] = resolved
            self._resolved.add(name)

        return resolved

    def values(self) -> list[ConfigT]:
        """Returns every config, fully resolved. This imports every plugin module."""
        return [self.get(name) for name in list(self._configs)]

    def resolve_all(self):
        """Forces resolution of every entry."""
        self.values()

    def names(self) -> list[str]:
        return list(self._configs)

    def is_resolved(self, name: str) -> bool:
        return name in self._resolved

    def __contains__(self, name: str) -> bool:
        return name in self._configs

    def __getstate__(self) -> dict:
        # a threading.Lock is neither picklable nor deep-copyable, and the test suite
        # deep-copies the entire configuration around every test
        state = self.__dict__.copy()
        del state["_lock"]
        return state

    def __setstate__(self, state: dict):
        self.__dict__.update(state)
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._configs)


def resolve_config_class(config: Any) -> Optional[type]:
    """Imports config.python_module and returns the config class declared by its plugin class."""
    module = importlib.import_module(config.python_module)
    class_definition = getattr(module, config.python_class)
    return class_definition.get_config_class()
