import logging

import pytest
from jinja2 import UndefinedError

from saq.query.template_rendering import (
    _expand_dotted_keys,
    _extract_paths,
    _node_to_chain,
    _resolve_path,
    _set_path,
    render_event_template,
    render_event_template_multi,
    render_event_templates_multi,
)


# ---------- _expand_dotted_keys ----------


@pytest.mark.unit
def test_expand_dotted_keys_flat():
    """A flat event without dots passes through unchanged."""
    assert _expand_dotted_keys({"a": 1, "b": "x"}) == {"a": 1, "b": "x"}


@pytest.mark.unit
def test_expand_dotted_keys_nested():
    """`device.hostname: x` becomes `device: {hostname: x}`."""
    assert _expand_dotted_keys({"device.hostname": "x"}) == {"device": {"hostname": "x"}}


@pytest.mark.unit
def test_expand_dotted_keys_deep():
    """Multi-segment dotted keys nest deeply."""
    flat = {"a.b.c.d": 7}
    assert _expand_dotted_keys(flat) == {"a": {"b": {"c": {"d": 7}}}}


@pytest.mark.unit
def test_expand_dotted_keys_strips_curly_marker():
    """Trailing `{}` on any segment is stripped (Splunk multi-value marker)."""
    flat = {"mitre_attack{}.technique_id": ["T1", "T2"]}
    assert _expand_dotted_keys(flat) == {"mitre_attack": {"technique_id": ["T1", "T2"]}}


@pytest.mark.unit
def test_expand_dotted_keys_strips_curly_at_leaf():
    """Trailing `{}` on the leaf segment is also stripped."""
    flat = {"rule.mitre_tcodes{}": ["T1", "T2"]}
    assert _expand_dotted_keys(flat) == {"rule": {"mitre_tcodes": ["T1", "T2"]}}


@pytest.mark.unit
def test_expand_dotted_keys_collision_nested_wins(caplog):
    """When both flat-scalar and nested forms collide, nested wins; warn logged."""
    flat = {"a": "scalar", "a.b": "nested"}
    with caplog.at_level(logging.WARNING):
        result = _expand_dotted_keys(flat)
    # nested form preserved
    assert result["a"] == {"b": "nested"}
    assert "collide" in caplog.text


@pytest.mark.unit
def test_expand_dotted_keys_handles_non_string_keys():
    """Non-string keys are left verbatim (not split)."""
    flat = {0: "zero", "a.b": "ab"}
    result = _expand_dotted_keys(flat)
    assert result[0] == "zero"
    assert result["a"]["b"] == "ab"


@pytest.mark.unit
def test_expand_dotted_keys_non_dict_input():
    """Non-dict input passes through unchanged (defensive)."""
    assert _expand_dotted_keys("not a dict") == "not a dict"  # type: ignore[arg-type]


# ---------- _node_to_chain ----------


@pytest.mark.unit
def test_node_to_chain_static_chains():
    import jinja2

    env = jinja2.Environment()
    parsed = env.parse("{{ x }} {{ y.z }} {{ a.b.c }} {{ d['e'] }}")
    chains = [
        _node_to_chain(n)
        for n in parsed.find_all(
            (jinja2.nodes.Name, jinja2.nodes.Getattr, jinja2.nodes.Getitem)
        )
    ]
    # We see every level of every chain; the maximal-chain dedup is the job of _extract_paths.
    assert ("x",) in chains
    assert ("y", "z") in chains
    assert ("a", "b", "c") in chains
    assert ("d", "e") in chains


@pytest.mark.unit
def test_node_to_chain_non_static_returns_none():
    import jinja2

    env = jinja2.Environment()
    # function call within the chain
    parsed = env.parse("{{ a.b() }}")
    chains = [
        _node_to_chain(n)
        for n in parsed.find_all(
            (jinja2.nodes.Name, jinja2.nodes.Getattr, jinja2.nodes.Getitem)
        )
    ]
    # Name('a') resolves to ('a',); the Call is not a Name/Getattr/Getitem so isn't iterated.
    assert ("a",) in chains


# ---------- _extract_paths ----------


@pytest.mark.unit
def test_extract_paths_deduplicates_prefixes():
    """`{{ a.b }}` emits only the maximal chain, not the intermediate `('a',)`."""
    import jinja2

    parsed = jinja2.Environment().parse("{{ a.b }}")
    paths = _extract_paths(parsed)
    assert paths == [("a", "b")]


@pytest.mark.unit
def test_extract_paths_keeps_disjoint_references():
    """Two unrelated paths are both kept."""
    import jinja2

    parsed = jinja2.Environment().parse("{{ a.b }}-{{ c.d }}")
    paths = _extract_paths(parsed)
    assert set(paths) == {("a", "b"), ("c", "d")}


@pytest.mark.unit
def test_extract_paths_same_reference_collapses():
    """Two identical references collapse to a single entry."""
    import jinja2

    parsed = jinja2.Environment().parse("{{ a.b }}={{ a.b }}")
    paths = _extract_paths(parsed)
    assert paths == [("a", "b")]


@pytest.mark.unit
def test_extract_paths_explicit_subscript_form():
    """`{{ a['b'] }}` is treated the same as `{{ a.b }}`."""
    import jinja2

    parsed = jinja2.Environment().parse("{{ a['b'] }}")
    paths = _extract_paths(parsed)
    assert paths == [("a", "b")]


# ---------- _resolve_path / _set_path ----------


@pytest.mark.unit
def test_resolve_path_navigates_nested_dict():
    data = {"a": {"b": {"c": 7}}}
    assert _resolve_path(data, ("a", "b", "c")) == 7


@pytest.mark.unit
def test_resolve_path_missing_returns_sentinel():
    from saq.query.template_rendering import _MISSING

    assert _resolve_path({"a": 1}, ("a", "b")) is _MISSING
    assert _resolve_path({"a": 1}, ("b",)) is _MISSING


@pytest.mark.unit
def test_set_path_creates_intermediates():
    data: dict = {}
    _set_path(data, ("a", "b", "c"), 7)
    assert data == {"a": {"b": {"c": 7}}}


# ---------- render_event_template ----------


@pytest.mark.unit
def test_render_event_template_simple():
    assert render_event_template("hello {{ name }}", {"name": "world"}) == "hello world"


@pytest.mark.unit
def test_render_event_template_flat_dotted_key():
    """Splunk-style flat keys are accessible via Jinja dotted syntax post-flatten."""
    rendered = render_event_template(
        "{{ device.hostname }}", {"device.hostname": "host01"}
    )
    assert rendered == "host01"


@pytest.mark.unit
def test_render_event_template_permissive_missing_var():
    """Missing variables render as empty string in permissive mode."""
    assert render_event_template("x={{ missing }}", {}) == "x="


@pytest.mark.unit
def test_render_event_template_strict_missing_var_raises():
    """Missing variables raise UndefinedError in strict mode."""
    with pytest.raises(UndefinedError):
        render_event_template("{{ missing }}", {}, strict=True)


@pytest.mark.unit
def test_render_event_template_strips_curly_in_path():
    """A flat key with `{}` is reachable via Jinja syntax after marker stripping."""
    rendered = render_event_template(
        "{{ mitre_attack.technique_id }}",
        {"mitre_attack{}.technique_id": "T1059"},
    )
    assert rendered == "T1059"


# ---------- render_event_template_multi ----------


@pytest.mark.unit
def test_render_event_template_multi_scalar_only():
    """Scalar-only template produces a single-element list."""
    results = render_event_template_multi("hello {{ name }}", {"name": "world"})
    assert results == ["hello world"]


@pytest.mark.unit
def test_render_event_template_multi_single_list_axis():
    """A list-valued reference produces one render per element."""
    results = render_event_template_multi(
        "mitre:{{ technique }}", {"technique": ["T1059", "T1204"]}
    )
    assert results == ["mitre:T1059", "mitre:T1204"]


@pytest.mark.unit
def test_render_event_template_multi_same_path_paired():
    """Two references to the same path share an iteration axis (paired)."""
    results = render_event_template_multi(
        "{{ app }}-{{ app }}", {"app": ["a", "b"]}
    )
    assert results == ["a-a", "b-b"]


@pytest.mark.unit
def test_render_event_template_multi_different_paths_cartesian():
    """Two references to different list paths produce the cartesian product."""
    results = render_event_template_multi(
        "{{ a }}:{{ b }}", {"a": ["x", "y"], "b": ["1", "2"]}
    )
    assert sorted(results) == ["x:1", "x:2", "y:1", "y:2"]


@pytest.mark.unit
def test_render_event_template_multi_empty_list_short_circuits():
    """A list-valued reference resolving to `[]` short-circuits to `[]`."""
    results = render_event_template_multi("{{ a }}", {"a": []})
    assert results == []


@pytest.mark.unit
def test_render_event_template_multi_nested_list_axis():
    """List-valued nested path expands one render per element."""
    results = render_event_template_multi(
        "mitre:{{ mitre_attack.technique_id }}",
        {"mitre_attack{}.technique_id": ["T1059", "T1204"]},
    )
    assert results == ["mitre:T1059", "mitre:T1204"]


@pytest.mark.unit
def test_render_event_template_multi_missing_var_permissive():
    """A missing variable falls through to permissive single render."""
    results = render_event_template_multi("x={{ missing }}", {})
    assert results == ["x="]


@pytest.mark.unit
def test_render_event_template_multi_missing_var_strict_raises():
    """A missing variable in strict mode raises UndefinedError."""
    with pytest.raises(UndefinedError):
        render_event_template_multi("{{ missing }}", {}, strict=True)


@pytest.mark.unit
def test_render_event_template_multi_filters_apply_correctly():
    """Jinja filters work over the expanded values."""
    results = render_event_template_multi(
        "{{ app | upper }}", {"app": ["a", "b"]}
    )
    assert results == ["A", "B"]


@pytest.mark.unit
def test_render_event_template_multi_does_not_iterate_scalar_axis():
    """References resolving to scalars aren't iteration axes."""
    results = render_event_template_multi(
        "{{ host }}@{{ apps }}", {"host": "h1", "apps": ["a", "b"]}
    )
    assert results == ["h1@a", "h1@b"]


@pytest.mark.unit
def test_render_event_templates_multi_syntax_error_is_a_warning(caplog):
    """A malformed template renders nothing and is the hunt author's to fix."""
    with caplog.at_level(logging.WARNING):
        assert render_event_templates_multi(["{{ host }}", "{{ unclosed"], {"host": "h1"}) == []

    records = [r for r in caplog.records if "jinja template syntax error" in r.getMessage()]
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
