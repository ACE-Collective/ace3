"""Custom correlation command types.

A correlate `transform.command` has three built-in types (`query`, `executable`, `defined`). Any
other `type:` value names a *custom command type*: a CorrelationCommand subclass that an
integration registers through `hunter.correlation.command_types` in its saq.integration.yaml.

    command:
      type: wiz_lookup
      timeout: 2m
      cache: 1d
      options:
        ip: "{{ _event.src_ip }}"

Core renders `options` with jinja (`_event` and `_events` only), validates the result against
the type's `config_class`, handles `timeout`/`cache`, sanitizes the output and traces the call;
the handler only does the work. See "Extending correlation hunts" in docs/INTEGRATIONS.md for the
full contract.

This module must not import commands.py or engine.py (both import it).
"""

import datetime
import importlib
import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from pydantic import BaseModel

from saq.collectors.hunter.correlation.schema import BUILTIN_COMMAND_TYPES
from saq.configuration import get_config

COMMAND_TYPE_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")

_command_type_registry: dict[str, "CorrelationCommand"] = {}
_load_errors: dict[str, str] = {}
_loaded = False


@dataclass(frozen=True)
class CommandContext:
    """What a CorrelationCommand gets to see about the call it is serving.

    There is deliberately no `secrets` here: a handler reads its own credentials from its
    integration's configuration, the same way a QuerySource does.
    """

    command_type: str
    event: dict
    events: list[dict]
    transform_type: str  # "event" or "stream"
    hunt_start_time: datetime.datetime
    hunt_end_time: datetime.datetime
    timeout: datetime.timedelta
    temp_dir: str
    config: dict = field(default_factory=dict)


class CorrelationCommand(ABC):
    """Base class for a custom correlation command type.

    One instance is created per process from `hunter.correlation.command_types` (constructor
    kwargs come from the entry's `kwargs:`) and shared by every hunt thread, so implementations
    must be thread-safe and should build expensive clients lazily rather than in __init__.
    """

    # the pydantic model the rendered `options` are validated against. None means the type
    # takes no options. declare it with model_config = {"extra": "forbid"} so typos are caught.
    config_class: Optional[type[BaseModel]] = None

    # False means results must never be cached: a `cache:` on the command is ignored at run time
    # and reported as an error by hunt validation.
    cacheable: bool = True

    # False passes `options` through verbatim, for a type whose option values legitimately
    # contain `{{ }}` (e.g. it forwards a template to some other system).
    render_options: bool = True

    @abstractmethod
    def execute(self, context: CommandContext, options: Any) -> str:
        """Do the work and return the command output.

        `options` is the validated `config_class` instance (or `{}` when there is none). The
        output follows the same contract as the built-in types: JSONL for stream transforms and
        `property_type: list`, JSON for `property_type: dict`, otherwise any string. Return ""
        for "no data" rather than raising -- a raised exception is a step error, which makes the
        event fall through to an alert.

        Core cannot interrupt a running handler, so it must honour `context.timeout` itself.
        """
        raise NotImplementedError()

    def cache_key(self, context: CommandContext, options: Any) -> dict:
        """Return the values that identify this call for the persistent `cache:`.

        Core prefixes the command type. The default includes the input (the event, or the whole
        stream for a stream transform) because the handler can read it, so this is always
        correct. A handler whose output depends only on its options should override this and
        return just those, so the cache is shared across events.
        """
        return {
            "options": _dump_options(options),
            "input": context.events if context.transform_type == "stream" else context.event,
        }

    def render_summary(self, context: CommandContext, options: Any) -> Optional[str]:
        """Return the one-line description of this call shown in the correlation trace.

        The trace is persisted into alert details, so never include a credential here. Core
        still runs the result through the secret sanitizer.
        """
        return f"{context.command_type} {json.dumps(_dump_options(options), sort_keys=True, default=str)}"


def _dump_options(options: Any) -> Any:
    if isinstance(options, BaseModel):
        return options.model_dump(mode="json")
    return options


def register_command_type(name: str, handler: CorrelationCommand):
    """Register a custom correlation command type by name."""
    if name in BUILTIN_COMMAND_TYPES:
        raise ValueError(f"{name!r} is a built-in correlation command type and cannot be registered")
    if not COMMAND_TYPE_NAME_PATTERN.match(name):
        raise ValueError(
            f"invalid correlation command type name {name!r}: must match {COMMAND_TYPE_NAME_PATTERN.pattern}"
        )
    if not isinstance(handler, CorrelationCommand):
        raise TypeError(f"correlation command type {name!r} must be a CorrelationCommand instance")
    if name in _command_type_registry:
        logging.warning("overwriting existing correlation command type registration: %s", name)
    _command_type_registry[name] = handler
    logging.info("registered correlation command type: %s", name)


def get_command_type(name: str) -> CorrelationCommand:
    """Get a registered custom command type by name."""
    if name not in _command_type_registry:
        if name in _load_errors:
            raise ValueError(f"correlation command type {name!r} failed to load: {_load_errors[name]}")
        raise ValueError(f"unknown command type: {name!r}")
    return _command_type_registry[name]


def get_registered_command_types() -> dict[str, CorrelationCommand]:
    """Return the current registry (read-only view)."""
    return dict(_command_type_registry)


def get_command_type_load_errors() -> dict[str, str]:
    """Return the configured command types that failed to load, keyed on name."""
    return dict(_load_errors)


def clear_command_types():
    """Clear all registered command types. Primarily for testing."""
    _command_type_registry.clear()
    _load_errors.clear()


def load_command_types_from_config(force: bool = False):
    """Instantiate and register every command type declared under hunter.correlation.command_types."""
    global _loaded
    if _loaded and not force:
        return

    clear_command_types()

    hunter_cfg = getattr(get_config(), "hunter", None)
    correlation = getattr(hunter_cfg, "correlation", None) if hunter_cfg else None
    if not correlation:
        _loaded = True
        return

    for type_config in correlation.command_types:
        try:
            module = importlib.import_module(type_config.python_module)
            cls = getattr(module, type_config.python_class)
            register_command_type(type_config.name, cls(**type_config.kwargs))
        except Exception as e:
            # one broken type must not stop the hunter; hunts that use it fail per step instead,
            # and hunt validation reports this message rather than a bare "unknown type".
            _load_errors[type_config.name] = f"{type(e).__name__}: {e}"
            logging.error(
                "failed to load correlation command type %s (%s.%s)",
                type_config.name,
                type_config.python_module,
                type_config.python_class,
                exc_info=True,
            )

    _loaded = True


def reset_command_types_loaded_flag():
    """test helper: force the next load_command_types_from_config() call to reload"""
    global _loaded
    _loaded = False
