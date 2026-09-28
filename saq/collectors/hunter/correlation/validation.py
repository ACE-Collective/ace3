"""Authoring-time checks for a hunt's correlate block.

These run in the hunt validation path (`ace hunt verify` / `POST /api/hunt/validate`), not
during normal hunt loading -- a production node should not refuse to load a hunt at startup.
What gets past here fails at runtime as a step error on the event it was evaluating.
"""

from collections.abc import Iterator
from typing import Optional, Union

from jinja2 import TemplateSyntaxError, meta
from jinja2.sandbox import SandboxedEnvironment
from pydantic import BaseModel, ValidationError

from saq.collectors.hunter.correlation.command_types import (
    get_command_type_load_errors,
    get_registered_command_types,
)
from saq.collectors.hunter.correlation.schema import (
    BUILTIN_COMMAND_TYPES,
    CommandConfig,
    ConditionConfig,
    CorrelateConfig,
    PredefinedCommandConfig,
    StepConfig,
    TransformConfig,
)

_jinja_env = SandboxedEnvironment()

# names that used to be bound in hunt templates and no longer are: a hunt has no path to
# configuration or credentials (see build_jinja_context).
REMOVED_TEMPLATE_NAMES = frozenset({"_secrets", "_config"})

# model fields that are never rendered, so a `{{` in them is literal text rather than a template
_UNRENDERED_FIELDS = frozenset({"description", "source_options"})


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


def _iter_strings(value) -> Iterator[str]:
    """Yield every string leaf of a parsed hunt config value.

    Walks models, dicts and lists generically so a template field added later is covered without
    this check having to know about it.
    """
    if isinstance(value, str):
        yield value
    elif isinstance(value, BaseModel):
        for name in type(value).model_fields:
            if name not in _UNRENDERED_FIELDS:
                yield from _iter_strings(getattr(value, name))
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_strings(item)


def check_templates_for_removed_names(
    correlate_config: Optional[CorrelateConfig],
    predefined_commands: Optional[list[PredefinedCommandConfig]] = None,
) -> list[str]:
    """Return one error string per hunt template that reads `_secrets` or `_config`.

    Neither is bound when a hunt renders, so such a template fails (or renders empty) on every
    event at runtime. Reporting it here turns that into a validation error with the reason.
    """
    sources: list[tuple[str, object]] = []
    if isinstance(correlate_config, CorrelateConfig):
        sources.append(("correlate", correlate_config))
    if isinstance(predefined_commands, list):
        sources.extend(
            (f"predefined command {c.name!r}", c)
            for c in predefined_commands
            if isinstance(c, PredefinedCommandConfig)
        )

    errors = []
    for label, source in sources:
        for value in _iter_strings(source):
            if not _is_template(value):
                continue
            try:
                names = meta.find_undeclared_variables(_jinja_env.parse(value))
            except TemplateSyntaxError:
                # a template that does not parse cannot render either, so it cannot read anything
                continue
            removed = sorted(names & REMOVED_TEMPLATE_NAMES)
            if removed:
                errors.append(
                    f"{label}: template {value!r} references {', '.join(removed)}. Hunts have no "
                    "access to secrets or configuration; a command that needs a credential must "
                    "be a custom command type that reads it from its integration's configuration."
                )

    return list(dict.fromkeys(errors))


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
