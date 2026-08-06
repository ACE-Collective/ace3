import logging
from dataclasses import dataclass
from typing import Optional

from jinja2.sandbox import SandboxedEnvironment

from saq.collectors.hunter.correlation.expressions import build_jinja_context
from saq.collectors.hunter.correlation.schema import ActionConfig

_jinja_env = SandboxedEnvironment()


@dataclass
class ActionResult:
    """Result of executing an action."""
    action_type: str  # filter, stop, discard, alert, log, timeout, continue
    queue_override: Optional[str] = None
    analysis_mode_override: Optional[str] = None

    @property
    def is_interrupt(self) -> bool:
        """Returns True if this action interrupts event processing."""

        return self.action_type in ("filter", "stop", "discard", "alert", "timeout")

    @property
    def is_stream_interrupt(self) -> bool:
        """Returns True if this action stops the entire stream."""
        return self.action_type in ("stop", "discard")


def execute_action(
    action: ActionConfig,
    event: dict,
    events: list[dict],
    config: dict | None = None,
) -> ActionResult:
    """Execute an action and return the result."""
    if action.type == "filter":
        result = ActionResult(action_type="filter")
    elif action.type == "stop":
        result = ActionResult(action_type="stop")
    elif action.type == "discard":
        result = ActionResult(action_type="discard")
    elif action.type == "alert":
        result = ActionResult(
            action_type="alert",
            queue_override=action.queue,
            analysis_mode_override=action.analysis_mode,
        )
    elif action.type == "log":
        result = ActionResult(action_type="log")
    else:
        raise ValueError(f"unknown action type: {action.type!r}")

    _log_action(action, event, events, config, result)
    return result


def _log_action(
    action: ActionConfig,
    event: dict,
    events: list[dict],
    config: dict | None,
    result: ActionResult,
):
    """Log a message for any action execution."""
    context = build_jinja_context(event, events, config)
    level = getattr(logging, action.log_level.upper(), logging.INFO)

    if action.log_message:
        try:
            message = _jinja_env.from_string(action.log_message).render(**context)
        except Exception:
            logging.error("failed to render log message template: %s", action.log_message, exc_info=True)
            return
    else:
        message = f"executed {action.type} action"

    logging.log(level, "correlation log: %s", message)
