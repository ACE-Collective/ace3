"""Authoring-time checks for a hunt's correlate block.

These run in the hunt validation path (`ace hunt verify` / `POST /api/hunt/validate`), not
during normal hunt loading -- a production node should not refuse to load a hunt at startup.
The equivalent runtime guards in `commands.py` cover what gets past here.
"""

from collections.abc import Iterator
import logging
from typing import Optional, Union

from jinja2.sandbox import SandboxedEnvironment
from pydantic import ValidationError

from saq.collectors.hunter.correlation.command_types import (
    get_command_type_load_errors,
    get_registered_command_types,
)
from saq.collectors.hunter.correlation.expressions import build_jinja_context
from saq.collectors.hunter.correlation.schema import (
    BUILTIN_COMMAND_TYPES,
    CommandConfig,
    ConditionConfig,
    CorrelateConfig,
    PredefinedCommandConfig,
    StepConfig,
    TransformConfig,
)
from saq.configuration.config import get_config
from saq.configuration.yaml_parser import ENCRYPTED_PREFIX

_jinja_env = SandboxedEnvironment()

# stands in for a real credential while probing an env template, so a value that legitimately
# reads `_secrets` renders without needing the store.
_PROBE_SECRET = "PROBE_SECRET_VALUE"


class _ProbeSecrets(dict):
    """A `_secrets` stand-in that answers every lookup with the same placeholder."""

    def __missing__(self, key):
        return _PROBE_SECRET


def iter_correlate_commands(logic_steps: list[StepConfig]) -> Iterator[CommandConfig]:
    """Yield every command in a correlation logic tree, in document order.

    Transforms can be nested inside conditional steps, so this recurses through
    ConditionConfig.execute / else_ -- same shape as collect_correlate_steps in query_hunter.
    """
    for step_config in logic_steps:
        inner = step_config.step
        if isinstance(inner, TransformConfig):
            yield inner.command
        elif isinstance(inner, ConditionConfig):
            yield from iter_correlate_commands(inner.execute)
            if inner.else_:
                yield from iter_correlate_commands(inner.else_)


def check_env_for_encrypted_markers(
    correlate_config: Optional[CorrelateConfig],
    predefined_commands: Optional[list[PredefinedCommandConfig]] = None,
    config: Optional[dict] = None,
) -> list[str]:
    """Return one error string per `env:` value that renders to an unresolved secret marker.

    An `encrypted:<name>` marker survives unresolved in the raw merged config dict bound as
    `_config`, so reading a credential that way hands the marker to the helper script instead
    of the credential -- which fails against the vendor with an unrelated-looking auth error.

    Each template is rendered rather than parsed: rendering handles composed strings and
    dynamic indexing that a static read of the jinja expression would miss.
    """
    if config is None:
        try:
            config = get_config().raw._data
        except Exception:
            logging.warning("unable to load config for hunt env validation", exc_info=True)
            return []

    # isinstance rather than a None check: a hunt type without a correlate block, or one whose
    # config never parsed a `commands` list, simply has nothing to check here.
    commands: list[Union[CommandConfig, PredefinedCommandConfig]] = []
    if isinstance(correlate_config, CorrelateConfig):
        commands.extend(iter_correlate_commands(correlate_config.logic))
    if isinstance(predefined_commands, list):
        commands.extend(c for c in predefined_commands if isinstance(c, PredefinedCommandConfig))
    if not commands:
        return []

    context = build_jinja_context({}, [], config)
    context["_secrets"] = _ProbeSecrets()

    errors = []
    for command in commands:
        if not command.env:
            continue
        label = getattr(command, "name", None) or command.path
        for key, value in command.env.items():
            try:
                rendered = _jinja_env.from_string(value).render(**context)
            except Exception as e:
                # a render failure here is not necessarily a hunt error -- the probe context has
                # no event data -- so it is not reported as one.
                logging.debug("unable to probe env %s of %s: %s", key, label, e)
                continue
            if ENCRYPTED_PREFIX in rendered:
                errors.append(
                    f"command {label!r}: env {key} resolves to an unresolved "
                    f"{ENCRYPTED_PREFIX!r} marker ({rendered!r}). Encrypted secrets are not "
                    f"available through _config; read the secret with _secrets['<name>'] "
                    f"instead, keyed on the encrypted-password store key name."
                )

    return errors


def _is_template(value) -> bool:
    return isinstance(value, str) and ("{{" in value or "{%" in value)


def _check_custom_command(
    label: str,
    command: Union[CommandConfig, PredefinedCommandConfig],
) -> list[str]:
    """Return the problems with one custom-typed command, judged against this node's registry."""
    registered = get_registered_command_types()
    handler = registered.get(command.type)
    if handler is None:
        load_error = get_command_type_load_errors().get(command.type)
        if load_error is not None:
            return [f"{label}: command type {command.type!r} failed to load on this node: {load_error}"]
        known = ", ".join(sorted(BUILTIN_COMMAND_TYPES | registered.keys()))
        return [f"{label}: unknown command type {command.type!r} (known types: {known})"]

    errors = []
    if command.cache and not handler.cacheable:
        errors.append(f"{label}: command type {command.type!r} is not cacheable; remove 'cache'")

    if handler.config_class is None:
        if command.options:
            errors.append(
                f"{label}: command type {command.type!r} takes no options, got {sorted(command.options)}"
            )
        return errors

    try:
        handler.config_class.model_validate(command.options)
    except ValidationError as e:
        for error in e.errors():
            # a template cannot be judged before it is rendered against an event: "{{ _event.n }}"
            # is a fine value for an int field. the runtime validation after rendering covers it.
            if handler.render_options and _is_template(error.get("input")):
                continue
            location = ".".join(str(part) for part in error["loc"]) or "options"
            errors.append(f"{label}: options.{location}: {error['msg']}")

    return errors


def check_custom_command_types(
    correlate_config: Optional[CorrelateConfig],
    predefined_commands: Optional[list[PredefinedCommandConfig]] = None,
) -> list[str]:
    """Return one error string per problem with a custom (integration-provided) command type.

    Reports a type that is not registered on this node (or that failed to load), options that
    fail the type's `config_class`, and `cache:` on a type that is not cacheable. A `defined`
    command is checked as the command it resolves to, with its `arguments` applied.

    Options are validated un-rendered, so this is called by hunt validation, never at hunt load.
    """
    predefined: list[PredefinedCommandConfig] = []
    if isinstance(predefined_commands, list):
        predefined = [c for c in predefined_commands if isinstance(c, PredefinedCommandConfig)]
    predefined_by_name = {c.name: c for c in predefined}

    errors: list[str] = []

    for command in predefined:
        if command.type not in BUILTIN_COMMAND_TYPES:
            errors.extend(_check_custom_command(f"predefined command {command.name!r}", command))

    if isinstance(correlate_config, CorrelateConfig):
        for command in iter_correlate_commands(correlate_config.logic):
            if command.type == "defined":
                predef = predefined_by_name.get(command.name)
                if predef is None or predef.type in BUILTIN_COMMAND_TYPES or not command.arguments:
                    # an unargumented reference is exactly the predefined command, checked above
                    continue
                label = f"defined command {command.name!r}"
                try:
                    effective = predef.to_command_config(command.arguments)
                except ValidationError as e:
                    errors.append(f"{label}: {e}")
                    continue
                errors.extend(_check_custom_command(label, effective))
            elif command.type not in BUILTIN_COMMAND_TYPES:
                errors.extend(_check_custom_command(f"command {command.type!r}", command))

    # the same mistake reached through several references is one problem
    return list(dict.fromkeys(errors))
