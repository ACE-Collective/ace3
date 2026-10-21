# vim: sw=4:ts=4:et:cc=120
"""Hunt-config Jinja rendering with event pre-flatten and implicit list expansion.

This module is the engine for interpolating event data into hunt-config strings
(tags, pivot links, playbook URL, observable values, file names, etc.).

Two entry points:

- :func:`render_event_template` — single-string render. Use when the caller
  expects exactly one output (playbook URL, dedup key, pivot link URL/text,
  F_FILE file name, observable value, etc.).
- :func:`render_event_template_multi` — multi-string render. Use when the
  caller emits N artifacts per template (root tags, F_FILE per-file tags,
  per-observable tags). Templates that reference list-valued event fields
  expand naturally: same path → same iteration axis (paired); different paths
  → cartesian product; empty list → empty result.

Both helpers pre-flatten the event so Splunk/LogScale-style flat dotted keys
(``"device.hostname": "x"``) work with natural Jinja accessor syntax
(``{{ device.hostname }}``). Trailing ``{}`` markers on key segments (Splunk's
multi-value field indicator) are stripped during flatten.
"""

import copy
import itertools
import logging
from typing import Optional

import jinja2
from jinja2 import UndefinedError

from saq.query.summary_detail_rendering import render_jinja_template


_MISSING = object()


def render_event_template(template: str, event: dict, *, strict: bool = False) -> Optional[str]:
    """Render ``template`` against a pre-flattened ``event`` as a single string.

    Permissive mode: missing variables render as ``""``.
    Strict mode: missing variables raise :class:`jinja2.UndefinedError`.
    Returns ``None`` on template syntax errors (matches ``render_jinja_template``).
    """
    flat = _expand_dotted_keys(event)
    return render_jinja_template(template, flat, strict=strict)


def render_event_template_multi(template: str, event: dict, *, strict: bool = False) -> list[str]:
    """Render ``template`` once per combination of list-valued referenced paths.

    Each maximal static path referenced in the template is resolved against the
    pre-flattened event. Paths that resolve to a list become iteration axes;
    same path → same axis (pairing), different paths → cartesian product.
    Empty list short-circuits to ``[]``. Scalar-only templates produce a
    single-element list.

    In strict mode, an individual render raising :class:`UndefinedError` is
    propagated so the caller can skip that render (each axis combination is an
    independent render). In permissive mode, missing variables render as ``""``.
    """
    rows = render_event_templates_multi([template], event, strict=strict)
    return [row[0] for row in rows]


def render_event_templates_multi(
    templates: list[str], event: dict, *, strict: bool = False
) -> list[list[str]]:
    """Render multiple templates with shared iteration axes.

    Use this for tuples of related templates that should iterate together
    (e.g. a pivot link's url and text both referencing ``{{ app }}``). Returns
    a list of rows; each row contains one rendered string per input template,
    positionally aligned. Same-path references share an axis (paired) across
    all input templates; different-path list references combine as a cartesian
    product. Empty list short-circuits to ``[]``.
    """
    flat = _expand_dotted_keys(event)

    parsed_templates = []
    for template in templates:
        try:
            parsed_templates.append(jinja2.Environment().parse(template))
        except jinja2.TemplateSyntaxError:
            logging.warning("jinja template syntax error in template: %s", template, exc_info=True)
            return []

    all_paths: list[tuple] = []
    for parsed in parsed_templates:
        for path in _extract_paths(parsed):
            if path not in all_paths:
                all_paths.append(path)

    axes: dict[tuple, list] = {}
    for path in all_paths:
        value = _resolve_path(flat, path)
        if isinstance(value, list):
            if not value:
                return []
            axes[path] = value

    def _render_row(scoped: dict) -> Optional[list[str]]:
        row: list[str] = []
        for template in templates:
            rendered = render_jinja_template(template, scoped, strict=strict)
            if rendered is None:
                return None
            row.append(rendered)
        return row

    if not axes:
        row = _render_row(flat)
        return [] if row is None else [row]

    axis_paths = list(axes.keys())
    axis_values = [axes[p] for p in axis_paths]

    results: list[list[str]] = []
    for combo in itertools.product(*axis_values):
        scoped = copy.deepcopy(flat)
        for path, scalar in zip(axis_paths, combo):
            _set_path(scoped, path, scalar)
        row = _render_row(scoped)
        if row is not None:
            results.append(row)
    return results


def _expand_dotted_keys(event: dict) -> dict:
    """Convert flat dotted keys to nested dicts.

    ``{"device.hostname": "x"}`` → ``{"device": {"hostname": "x"}}``.

    Trailing ``{}`` markers on key segments are stripped — Splunk emits keys
    like ``"mitre_attack{}.technique_id"`` to mark the parent as multi-value;
    the marker doesn't belong in Jinja access syntax.

    Collisions (e.g. an event with both ``"a"`` and ``"a.b"`` as top-level
    keys, or two flat keys that share a prefix where the prefix value is
    non-dict) are resolved in favor of the nested form; the collision is
    logged so unexpected production data shows up in logs.
    """
    if not isinstance(event, dict):
        return event

    result: dict = {}
    collisions: list[str] = []

    for raw_key, value in event.items():
        if not isinstance(raw_key, str):
            # non-string keys can't be Jinja-addressed; keep verbatim
            result[raw_key] = value
            continue

        parts = [p.removesuffix("{}") for p in raw_key.split(".") if p]
        if not parts:
            continue

        cursor = result
        ok = True
        for i, part in enumerate(parts):
            is_last = i == len(parts) - 1
            if is_last:
                if part in cursor and isinstance(cursor[part], dict) and not isinstance(value, dict):
                    # nested form already populated; preserve it
                    collisions.append(raw_key)
                    ok = False
                    break
                cursor[part] = value
            else:
                existing = cursor.get(part, _MISSING)
                if existing is _MISSING:
                    cursor[part] = {}
                    cursor = cursor[part]
                elif isinstance(existing, dict):
                    cursor = existing
                else:
                    # collision: existing is non-dict, replacing with nested form
                    collisions.append(raw_key)
                    cursor[part] = {}
                    cursor = cursor[part]
        del ok  # silences linters; loop continues regardless

    if collisions:
        logging.warning(
            "event has flat keys that collide with nested forms; nested wins. keys: %s",
            collisions,
        )
    return result


def _extract_paths(parsed: jinja2.nodes.Template) -> list[tuple]:
    """Return the maximal static path chains referenced in the parsed template.

    Walks every ``Name``/``Getattr``/``Getitem`` node, reduces each to a path
    tuple (or skips if non-static), then deduplicates by dropping any tuple
    that is a strict prefix of a longer one (so ``{{ a.b }}`` emits only
    ``('a', 'b')``, not also ``('a',)``).
    """
    raw_chains: list[tuple] = []
    for node in parsed.find_all((jinja2.nodes.Name, jinja2.nodes.Getattr, jinja2.nodes.Getitem)):
        chain = _node_to_chain(node)
        if chain is not None:
            raw_chains.append(chain)

    # Dedupe by removing strict-prefix tuples. Sort longest-first so the kept
    # set is naturally maximal.
    raw_chains.sort(key=len, reverse=True)
    kept: list[tuple] = []
    for chain in raw_chains:
        if any(len(chain) < len(k) and k[: len(chain)] == chain for k in kept):
            continue
        if chain not in kept:
            kept.append(chain)
    return kept


def _node_to_chain(node) -> Optional[tuple]:
    """Reduce a ``Name``/``Getattr``/``Getitem`` AST node to a path tuple.

    Returns ``None`` if the chain contains non-static segments (function calls,
    expressions, non-const subscripts, etc.).
    """
    parts: list = []
    while True:
        if isinstance(node, jinja2.nodes.Name):
            parts.append(node.name)
            break
        if isinstance(node, jinja2.nodes.Getattr):
            parts.append(node.attr)
            node = node.node
        elif isinstance(node, jinja2.nodes.Getitem):
            if not isinstance(node.arg, jinja2.nodes.Const):
                return None
            arg_value = node.arg.value
            if not isinstance(arg_value, (str, int)):
                return None
            parts.append(arg_value)
            node = node.node
        else:
            return None
    return tuple(reversed(parts))


def _resolve_path(data: dict, path: tuple):
    """Return the value at ``path`` in ``data``, or :data:`_MISSING` if absent."""
    cursor = data
    for segment in path:
        if isinstance(cursor, dict) and segment in cursor:
            cursor = cursor[segment]
        elif isinstance(cursor, list) and isinstance(segment, int) and 0 <= segment < len(cursor):
            cursor = cursor[segment]
        else:
            return _MISSING
    return cursor


def _set_path(data: dict, path: tuple, value) -> None:
    """Set ``data[path] = value``, creating intermediate dicts as needed."""
    cursor = data
    for segment in path[:-1]:
        if not isinstance(cursor.get(segment), dict):
            cursor[segment] = {}
        cursor = cursor[segment]
    cursor[path[-1]] = value


__all__ = [
    "render_event_template",
    "render_event_template_multi",
    "render_event_templates_multi",
    "UndefinedError",
]
