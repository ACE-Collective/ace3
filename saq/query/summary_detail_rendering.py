# vim: sw=4:ts=4:et:cc=120

import json
import logging
from typing import Optional

import jinja2
from jinja2 import TemplateSyntaxError, UndefinedError
from jinja2.sandbox import SandboxedEnvironment

# Permissive environment: missing variables render as empty string.
_permissive_env = SandboxedEnvironment()
def _safe_fromjson(value):
    """Parse a JSON string, returning an empty dict on failure."""
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return {}

_permissive_env.filters['fromjson'] = _safe_fromjson

# Strict environment: missing variables raise UndefinedError.
_strict_env = SandboxedEnvironment(undefined=jinja2.StrictUndefined)
_strict_env.filters['fromjson'] = _safe_fromjson


def render_jinja_template(template_str: str, event: dict, strict: bool = False) -> Optional[str]:
    """Render a Jinja2 template with the event data.

    Args:
        template_str: The Jinja2 template string.
        event: The event dict to use as template context.
        strict: If True, raises UndefinedError on missing variables.
                If False, missing variables render as empty string.

    Returns:
        The rendered string, or None on template syntax errors.

    Raises:
        UndefinedError: If strict=True and a variable is missing.
    """
    env = _strict_env if strict else _permissive_env
    try:
        template = env.from_string(template_str)
        return template.render(**event)
    except UndefinedError:
        if strict:
            raise
        # should not happen in permissive mode, but handle defensively
        logging.error("unexpected UndefinedError in permissive mode for template: %s", template_str, exc_info=True)
        return None
    except TemplateSyntaxError:
        logging.error("jinja template syntax error in template: %s", template_str, exc_info=True)
        return None
    except Exception:
        logging.error("unexpected error rendering jinja template: %s", template_str, exc_info=True)
        return None
