import importlib
import sys
from typing import Any, Callable


def lazy_getattr(package: str, exports: dict[str, str | tuple[str, str]]) -> Callable[[str], Any]:
    """The module __getattr__ (PEP 562) of a package init that re-exports names without importing them
    (docs/IMPORTS.md): each name in exports is imported from its module the first time it is asked for, and
    then set on the package so it is not asked for again.

    exports maps a name to the module that defines it, or to (module, attribute) where the package exports
    it under another name."""

    def __getattr__(name: str) -> Any:
        if name not in exports:
            raise AttributeError(f"module {package!r} has no attribute {name!r}")

        target = exports[name]
        module_name, attribute = target if isinstance(target, tuple) else (target, name)
        value = getattr(importlib.import_module(module_name), attribute)
        setattr(sys.modules[package], name, value)
        return value

    return __getattr__
