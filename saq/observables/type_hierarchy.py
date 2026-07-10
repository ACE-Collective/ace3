"""Process-global registry of per-observable-type configuration.

The YAML file referenced by ``observable_types.config_path`` in the saq config
is the single source of truth for everything in the registry: inheritance,
default display types, descriptions, and the deprecated flag. The default in
``saq.default.yaml`` points at ``etc/observable_types.yaml``; production
deployments override the path to their own analyst-curated file.

The registry tracks per-type information today:

1. **Inheritance.** Which observable type extends which. Cycles are rejected at
   load time without mutating the prior state.

2. **Default display type.** A fallback human label used when no code calls
   ``observable.display_type = "..."`` explicitly. Useful for hunt-defined
   types and other observables created without a Python module setting
   ``display_type`` at construction.

3. **Description.** Human-readable description, surfaced via the API.

4. **Deprecated flag.** Types that are recognized but should not be offered to
   analysts in pickers/forms.

Python ``Observable`` subclasses define *behavior* (validation, normalization,
serialization) for a type; they do not contribute inheritance, defaults, or
metadata to this registry. If you want analysis modules to dispatch on a
parent-child relationship, declare it in the YAML.

The schema is positioned to grow further per-type fields — add them to
:class:`ObservableTypeEntry` and the loader will route them through.

Consumers ask :meth:`TypeHierarchy.is_subtype` to answer "should a module
declaring ``email_address`` accept this ``return_path`` observable?", and
:meth:`TypeHierarchy.default_display_type_for` for the configured fallback
label of a given type.
"""

import logging
import os
import threading
import time
from typing import Optional

import yaml
from pydantic import BaseModel, Field, ValidationError

from saq.environment import get_base_dir


class ObservableTypeEntry(BaseModel):
    """Per-type configuration entry. All fields optional so an entry can carry
    just metadata, just inheritance, just a display-type default, or any
    combination."""

    extends: Optional[str] = Field(
        default=None,
        description="Parent observable type name. Module dispatch treats this type as a subtype of the parent.",
    )
    default_display_type: Optional[str] = Field(
        default=None,
        description="Fallback label for Observable.display_type when no explicit value is set.",
    )
    description: Optional[str] = Field(
        default=None,
        description="Human-readable description of this observable type.",
    )
    deprecated: bool = Field(
        default=False,
        description="If True, the type is recognized but should not be surfaced to analysts in pickers/forms.",
    )

    model_config = {"extra": "forbid"}


class ObservableTypesFile(BaseModel):
    """Top-level schema for the YAML file referenced by ``observable_types.config_path``."""

    types: dict[str, ObservableTypeEntry] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}


class TypeHierarchy:
    """Tracks per-observable-type configuration loaded from the YAML config."""

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}
        self._default_display_types: dict[str, str] = {}
        self._descriptions: dict[str, str] = {}
        self._deprecated_types: set[str] = set()
        self._yaml_declared_types: set[str] = set()
        self._ancestors_cache: dict[str, tuple[str, ...]] = {}
        # Runtime reload state. _config_path is set by load_yaml_config and is
        # what _maybe_reload re-stats. _reload_check_interval <= 0 disables it.
        self._config_path: Optional[str] = None
        self._last_mtime: Optional[float] = None
        self._next_reload_check: Optional[float] = None
        self._reload_check_interval: float = 60.0
        self._reload_lock = threading.Lock()

    def load_yaml_config(self, path: str) -> None:
        """Load the per-type YAML config and rebuild.

        Errors (missing file, unreadable file, bad encoding, bad YAML, cycles,
        schema violations) are logged and the prior state is preserved.

        Also records ``path`` and the file's mtime so :meth:`_maybe_reload`
        can detect changes on subsequent accessor calls.
        """
        try:
            mtime = os.stat(path).st_mtime
            # the encoding must be explicit: under an embedded interpreter (uwsgi)
            # utf-8 mode is off, so the locale decides and a C/POSIX locale means ascii
            with open(path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            config = ObservableTypesFile.model_validate(raw)
        except FileNotFoundError:
            logging.error("observable types config not found at %s", path)
            return
        except (yaml.YAMLError, ValidationError, UnicodeDecodeError, OSError) as e:
            logging.error("failed to parse observable types config %s: %s", path, e)
            return

        new_parent = {
            name: entry.extends
            for name, entry in config.types.items()
            if entry.extends is not None
        }
        new_default_display_types = {
            name: entry.default_display_type
            for name, entry in config.types.items()
            if entry.default_display_type is not None
        }
        new_descriptions = {
            name: entry.description
            for name, entry in config.types.items()
            if entry.description is not None
        }
        new_deprecated_types = {
            name for name, entry in config.types.items() if entry.deprecated
        }
        new_yaml_declared_types = set(config.types.keys())

        if (
            new_parent == self._parent
            and new_default_display_types == self._default_display_types
            and new_descriptions == self._descriptions
            and new_deprecated_types == self._deprecated_types
            and new_yaml_declared_types == self._yaml_declared_types
        ):
            # State unchanged, but still anchor the path + mtime so the
            # runtime-reload check keeps the right baseline.
            self._config_path = path
            self._last_mtime = mtime
            return

        try:
            _check_for_cycles(new_parent)
        except _CycleError as e:
            logging.error(
                "observable types config %s introduces a cycle (%s); keeping prior state",
                path,
                e,
            )
            return

        self._parent = new_parent
        self._default_display_types = new_default_display_types
        self._descriptions = new_descriptions
        self._deprecated_types = new_deprecated_types
        self._yaml_declared_types = new_yaml_declared_types
        self._ancestors_cache.clear()
        self._config_path = path
        self._last_mtime = mtime

        logging.info(
            "loaded %d observable type entries from %s "
            "(%d with extends, %d with default_display_type, %d with description, %d deprecated)",
            len(config.types),
            path,
            len(new_parent),
            len(new_default_display_types),
            len(new_descriptions),
            len(new_deprecated_types),
        )

    def parent_of(self, t: str) -> Optional[str]:
        return self._parent.get(t)

    def ancestors(self, t: str) -> tuple[str, ...]:
        """Return the chain of ancestors for ``t``, nearest first, root last.

        Does not include ``t`` itself.
        """
        cached = self._ancestors_cache.get(t)
        if cached is not None:
            return cached
        chain: list[str] = []
        seen = {t}
        current = self._parent.get(t)
        while current is not None and current not in seen:
            chain.append(current)
            seen.add(current)
            current = self._parent.get(current)
        result = tuple(chain)
        self._ancestors_cache[t] = result
        return result

    def is_subtype(self, t: str, parent: str) -> bool:
        """True if ``t`` is ``parent`` or transitively extends it."""
        if t == parent:
            return True
        return parent in self.ancestors(t)

    def default_display_type_for(self, type_str: str) -> Optional[str]:
        """Return the configured fallback display_type for this type, or None."""
        return self._default_display_types.get(type_str)

    def description_for(self, type_str: str) -> Optional[str]:
        """Return the configured description for this type, or None."""
        return self._descriptions.get(type_str)

    def is_deprecated(self, type_str: str) -> bool:
        """Return True if this type is flagged as deprecated in the config."""
        return type_str in self._deprecated_types

    def yaml_declared_types(self) -> set[str]:
        """Every type listed under `types:` in the loaded YAML, even with empty fields."""
        return set(self._yaml_declared_types)

    def all_known_types(self) -> set[str]:
        """All types known via inheritance, defaults, descriptions, or YAML declaration."""
        known: set[str] = set(self._yaml_declared_types)
        known.update(self._default_display_types.keys())
        known.update(self._descriptions.keys())
        known.update(self._deprecated_types)
        for child, parent in self._parent.items():
            known.add(child)
            known.add(parent)
        return known

    def reset(self) -> None:
        """Clear all registrations. Intended for tests."""
        self._parent.clear()
        self._default_display_types.clear()
        self._descriptions.clear()
        self._deprecated_types.clear()
        self._yaml_declared_types.clear()
        self._ancestors_cache.clear()
        self._config_path = None
        self._last_mtime = None
        self._next_reload_check = None

    def _maybe_reload(self) -> None:
        """Reload the YAML if its mtime has changed and the debounce has elapsed.

        No-op when the registry was never bootstrapped from a file
        (``_config_path is None``) or when ``_reload_check_interval`` is not
        positive. Bails immediately if another thread is already reloading.
        Errors during reload preserve prior state via :meth:`load_yaml_config`.
        """
        if self._config_path is None:
            return
        if self._reload_check_interval <= 0:
            return

        now = time.monotonic()
        if self._next_reload_check is not None and now < self._next_reload_check:
            return

        if not self._reload_lock.acquire(blocking=False):
            return
        try:
            # Recheck inside the lock; another thread may have just finished.
            now = time.monotonic()
            if self._next_reload_check is not None and now < self._next_reload_check:
                return

            try:
                current_mtime = os.stat(self._config_path).st_mtime
            except FileNotFoundError:
                logging.warning(
                    "observable types config %s vanished; keeping prior state",
                    self._config_path,
                )
                self._next_reload_check = now + self._reload_check_interval
                return

            if self._last_mtime is None or current_mtime > self._last_mtime:
                self.load_yaml_config(self._config_path)

            self._next_reload_check = now + self._reload_check_interval
        finally:
            self._reload_lock.release()


class _CycleError(RuntimeError):
    pass


def _check_for_cycles(parent_map: dict[str, str]) -> None:
    for start in parent_map:
        seen = {start}
        current = parent_map.get(start)
        while current is not None:
            if current in seen:
                raise _CycleError(f"cycle detected involving {sorted(seen)}")
            seen.add(current)
            current = parent_map.get(current)


_HIERARCHY = TypeHierarchy()


def get_type_hierarchy() -> TypeHierarchy:
    """Return the process-global type hierarchy registry.

    Triggers a debounced mtime check on the bootstrapped YAML so changes
    to the file on disk are picked up without a process restart. See
    :meth:`TypeHierarchy._maybe_reload`.
    """
    _HIERARCHY._maybe_reload()
    return _HIERARCHY


def get_all_valid_types() -> list[str]:
    """Return the sorted union of YAML-declared and Python-registered observable types.

    A type counts as "valid" if it has either a Python ``Observable`` subclass
    registered via :func:`saq.observables.generator.register_observable_type` or
    an entry in the YAML config loaded by :func:`bootstrap_type_hierarchy`.

    Lives in this module rather than ``saq.observables.__init__`` to avoid the
    package-init circular import path through aceapi_v2 presenters.

    Triggers the same debounced mtime check as :func:`get_type_hierarchy`.
    """
    from saq.observables.generator import OBSERVABLE_TYPE_MAPPING

    _HIERARCHY._maybe_reload()
    return sorted(set(OBSERVABLE_TYPE_MAPPING.keys()) | _HIERARCHY.yaml_declared_types())


def bootstrap_type_hierarchy() -> None:
    """Initialize the registry from the saq config's YAML file.

    Safe to call multiple times. If ``observable_types.config_path`` is
    unset/blank, no YAML is loaded and the registry stays empty (parent_of
    returns None for every type, is_subtype only returns True for the
    self-comparison).

    Also primes the runtime-reload interval from
    ``observable_types.reload_check_interval_seconds``; a value of 0 or
    less disables runtime reload.

    Imported lazily inside the function so this module can be imported during
    ``saq.observables`` package init (before configuration has been loaded)
    without pulling in the configuration machinery.
    """
    from saq.configuration import get_config

    try:
        observable_types_config = get_config().observable_types
    except AttributeError:
        return

    _HIERARCHY._reload_check_interval = observable_types_config.reload_check_interval_seconds

    config_path = observable_types_config.config_path
    if not config_path:
        return

    abs_path = config_path if os.path.isabs(config_path) else os.path.join(get_base_dir(), config_path)
    _HIERARCHY.load_yaml_config(abs_path)
