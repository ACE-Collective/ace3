import fnmatch
import logging
import re

from jinja2.sandbox import SandboxedEnvironment

from saq.collectors.hunter.correlation.schema import ExpressionConfig
from saq.collectors.hunter.correlation.trace import ExpressionTrace

_jinja_env = SandboxedEnvironment()


class SecretLookupError(RuntimeError):
    """Raised when a template asks `_secrets` for something it cannot supply.

    Deliberately NOT a subclass of LookupError. Jinja's Environment.getitem catches
    (TypeError, LookupError) and turns them into Undefined, so a KeyError raised from a
    subscript renders as an empty string -- silently exporting an empty credential, which is
    the exact failure class this whole mechanism exists to prevent.
    """


class SecretNamespace(dict):
    """The decrypted secret store, bound as `_secrets` when rendering an `env:` block.

    A plain dict apart from subscript lookup, which raises rather than quietly producing a
    value that is not a credential: jinja renders a missing key as "" and a None value as the
    literal "None", and either would be handed to the subprocess as its API key.

    Read a required secret with `_secrets['<name>']`. `.get()` keeps normal dict semantics for
    the rare optional case, and so does not get the same protection.
    """

    def __getitem__(self, key):
        if not self:
            raise SecretLookupError(
                f"no secrets are loaded, cannot resolve {key!r} -- the secret export failed "
                "(no encryption key, or the database is unreachable) or the store is empty"
            )
        if key not in self:
            raise SecretLookupError(
                f"unknown secret {key!r} -- _secrets is keyed on encrypted-password store key "
                "names (the suffix of an 'encrypted:<name>' config marker), not config paths"
            )
        value = super().__getitem__(key)
        if value is None:
            raise SecretLookupError(f"secret {key!r} is present but could not be decrypted")
        return value


def build_jinja_context(
    event: dict,
    events: list[dict],
    config: dict | None = None,
    *,
    secrets: dict | None = None,
) -> dict:
    """Build a Jinja template context from event data.

    `_secrets` is bound ONLY when the caller passes `secrets`, and the only caller that does is
    the `env:` rendering loop of an executable command. That is the one channel where handing a
    credential to a local helper process is the point. Everything else -- query text, command
    `args` (argv is world-readable via /proc), `when:` expressions, action and log templates --
    is rendered without it, because those values go to third parties or into the persisted
    correlation trace.

    `secrets` is keyword-only: every existing caller passes `config` positionally, so a
    positional fourth argument would be a credential leak waiting on a refactor.
    """
    context = {"_events": events, "_event": event}
    if config is not None:
        context["_config"] = config
    if secrets is not None:
        # wrapped here rather than at the call site so a template always gets the raising
        # lookup, never a bare dict that would render a typo'd name as an empty credential.
        context["_secrets"] = SecretNamespace(secrets)
    return context


def evaluate_expression(
    expr: ExpressionConfig,
    event: dict,
    events: list[dict],
    config: dict | None = None,
) -> bool:
    """Evaluate an expression against an event and event stream.

    Returns True or False based on the expression type and value.
    """
    if expr.type == "jinja":
        return _evaluate_jinja(expr, event, events, config)
    elif expr.type == "equals":
        return _evaluate_equals(expr, event)
    elif expr.type == "glob":
        return _evaluate_glob(expr, event)
    elif expr.type == "regex":
        return _evaluate_regex(expr, event)
    elif expr.type == "and":
        return _evaluate_and(expr, event, events, config)
    elif expr.type == "or":
        return _evaluate_or(expr, event, events, config)
    elif expr.type == "not":
        return _evaluate_not(expr, event, events, config)
    else:
        raise ValueError(f"unknown expression type: {expr.type!r}")


def _evaluate_jinja(
    expr: ExpressionConfig,
    event: dict,
    events: list[dict],
    config: dict | None = None,
) -> bool:
    context = build_jinja_context(event, events, config)
    try:
        template = _jinja_env.from_string(str(expr.value))
        result = template.render(**context)
        return bool(result and result.strip() and result.strip().lower() not in ("false", "0", "none", ""))
    except Exception:
        logging.error("error evaluating jinja expression: %s", expr.value, exc_info=True)
        return False


def _get_property_value(expr: ExpressionConfig, event: dict):
    """Get the property value from the event, applying case sensitivity."""
    value = event.get(expr.property)
    if value is None:
        return None
    value = str(value)
    if not expr.case_sensitive:
        value = value.lower()
    return value


def _normalize_expr_value(expr: ExpressionConfig) -> str:
    """Normalize the expression value for comparison."""
    value = str(expr.value)
    if not expr.case_sensitive:
        value = value.lower()
    return value


def _evaluate_equals(expr: ExpressionConfig, event: dict) -> bool:
    prop_value = _get_property_value(expr, event)
    if prop_value is None:
        return False
    return prop_value == _normalize_expr_value(expr)


def _evaluate_glob(expr: ExpressionConfig, event: dict) -> bool:
    prop_value = _get_property_value(expr, event)
    if prop_value is None:
        return False
    return fnmatch.fnmatch(prop_value, _normalize_expr_value(expr))


def _evaluate_regex(expr: ExpressionConfig, event: dict) -> bool:
    prop_value = _get_property_value(expr, event)
    if prop_value is None:
        return False
    flags = 0 if expr.case_sensitive else re.IGNORECASE
    return bool(re.search(str(expr.value), prop_value, flags))


def _parse_sub_expression(value) -> ExpressionConfig:
    """Parse a sub-expression value into an ExpressionConfig."""
    if isinstance(value, ExpressionConfig):
        return value
    if isinstance(value, str):
        return ExpressionConfig(type="jinja", value=value)
    if isinstance(value, dict):
        return ExpressionConfig.model_validate(value)
    raise ValueError(f"invalid sub-expression: {value!r}")


def _evaluate_and(
    expr: ExpressionConfig,
    event: dict,
    events: list[dict],
    config: dict | None = None,
) -> bool:
    for sub in expr.value:
        sub_expr = _parse_sub_expression(sub)
        if not evaluate_expression(sub_expr, event, events, config):
            return False
    return True


def _evaluate_or(
    expr: ExpressionConfig,
    event: dict,
    events: list[dict],
    config: dict | None = None,
) -> bool:
    for sub in expr.value:
        sub_expr = _parse_sub_expression(sub)
        if evaluate_expression(sub_expr, event, events, config):
            return True
    return False


def _evaluate_not(
    expr: ExpressionConfig,
    event: dict,
    events: list[dict],
    config: dict | None = None,
) -> bool:
    sub_expr = _parse_sub_expression(expr.value)
    return not evaluate_expression(sub_expr, event, events, config)


def evaluate_expression_traced(
    expr: ExpressionConfig,
    event: dict,
    events: list[dict],
    config: dict | None = None,
) -> tuple[bool, ExpressionTrace]:
    """Evaluate an expression and return both the result and a trace of the evaluation."""
    if expr.type == "jinja":
        return _evaluate_jinja_traced(expr, event, events, config)
    elif expr.type in ("equals", "glob", "regex"):
        return _evaluate_comparison_traced(expr, event, events, config)
    elif expr.type == "and":
        return _evaluate_and_traced(expr, event, events, config)
    elif expr.type == "or":
        return _evaluate_or_traced(expr, event, events, config)
    elif expr.type == "not":
        return _evaluate_not_traced(expr, event, events, config)
    else:
        raise ValueError(f"unknown expression type: {expr.type!r}")


def _evaluate_jinja_traced(
    expr: ExpressionConfig,
    event: dict,
    events: list[dict],
    config: dict | None = None,
) -> tuple[bool, ExpressionTrace]:
    context = build_jinja_context(event, events, config)
    try:
        template = _jinja_env.from_string(str(expr.value))
        rendered = template.render(**context)
        result = bool(rendered and rendered.strip() and rendered.strip().lower() not in ("false", "0", "none", ""))
        return result, ExpressionTrace(
            expression_type="jinja",
            result=result,
            rendered_value=rendered,
        )
    except Exception as e:
        logging.error("error evaluating jinja expression: %s", expr.value, exc_info=True)
        return False, ExpressionTrace(
            expression_type="jinja",
            result=False,
            error=str(e),
        )


def _evaluate_comparison_traced(
    expr: ExpressionConfig,
    event: dict,
    events: list[dict],
    config: dict | None = None,
) -> tuple[bool, ExpressionTrace]:
    prop_value = _get_property_value(expr, event)
    compare_value = _normalize_expr_value(expr)
    result = evaluate_expression(expr, event, events, config)
    return result, ExpressionTrace(
        expression_type=expr.type,
        result=result,
        property_name=expr.property,
        property_value=str(prop_value) if prop_value is not None else None,
        compare_value=compare_value,
    )


def _evaluate_and_traced(
    expr: ExpressionConfig,
    event: dict,
    events: list[dict],
    config: dict | None = None,
) -> tuple[bool, ExpressionTrace]:
    sub_traces = []
    result = True
    for sub in expr.value:
        sub_expr = _parse_sub_expression(sub)
        sub_result, sub_trace = evaluate_expression_traced(sub_expr, event, events, config)
        sub_traces.append(sub_trace)
        if not sub_result:
            result = False
            break
    return result, ExpressionTrace(
        expression_type="and",
        result=result,
        sub_expressions=sub_traces,
    )


def _evaluate_or_traced(
    expr: ExpressionConfig,
    event: dict,
    events: list[dict],
    config: dict | None = None,
) -> tuple[bool, ExpressionTrace]:
    sub_traces = []
    result = False
    for sub in expr.value:
        sub_expr = _parse_sub_expression(sub)
        sub_result, sub_trace = evaluate_expression_traced(sub_expr, event, events, config)
        sub_traces.append(sub_trace)
        if sub_result:
            result = True
            break
    return result, ExpressionTrace(
        expression_type="or",
        result=result,
        sub_expressions=sub_traces,
    )


def _evaluate_not_traced(
    expr: ExpressionConfig,
    event: dict,
    events: list[dict],
    config: dict | None = None,
) -> tuple[bool, ExpressionTrace]:
    sub_expr = _parse_sub_expression(expr.value)
    sub_result, sub_trace = evaluate_expression_traced(sub_expr, event, events, config)
    result = not sub_result
    return result, ExpressionTrace(
        expression_type="not",
        result=result,
        sub_expressions=[sub_trace],
    )
