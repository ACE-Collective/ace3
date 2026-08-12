"""Authoring-time checks for a hunt's correlate block.

These run in the hunt validation path (`ace hunt validate` / `POST /api/hunt/validate`), not
during normal hunt loading -- a production node should not refuse to load a hunt at startup.
The equivalent runtime guards in `commands.py` cover what gets past here.
"""

from collections.abc import Iterator
import logging
from typing import Optional, Union

from jinja2.sandbox import SandboxedEnvironment

from saq.collectors.hunter.correlation.expressions import build_jinja_context
from saq.collectors.hunter.correlation.schema import (
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
