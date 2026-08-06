import fnmatch
import logging
import re

from jinja2.sandbox import SandboxedEnvironment

from saq.collectors.hunter.correlation.schema import ExpressionConfig
from saq.collectors.hunter.correlation.trace import ExpressionTrace

_jinja_env = SandboxedEnvironment()


def build_jinja_context(
    event: dict,
    events: list[dict],
    config: dict | None = None,
) -> dict:
    """Build a Jinja template context from event data.

    Credentials are deliberately not reachable from a correlation template. A hunt's YAML is
    rendered into query text, command arguments and command environment variables that are then
    handed to third parties, so anything bound here is a value the hunt can transmit off-box.
    Correlation steps that need a credential must receive it explicitly rather than by reading a
    shared namespace.
    """
    context = {"_events": events, "_event": event}
    if config is not None:
        context["_config"] = config
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
