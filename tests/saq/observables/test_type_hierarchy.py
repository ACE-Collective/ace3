import pytest

from saq.observables.type_hierarchy import (
    ObservableTypeEntry,
    ObservableTypesFile,
    TypeHierarchy,
    get_type_hierarchy,
)


@pytest.mark.unit
def test_singleton_returns_same_instance():
    assert get_type_hierarchy() is get_type_hierarchy()


@pytest.mark.unit
def test_unknown_type_has_no_parent_or_ancestors():
    h = TypeHierarchy()
    assert h.parent_of("nope") is None
    assert h.ancestors("nope") == ()


@pytest.mark.unit
def test_is_subtype_of_self():
    h = TypeHierarchy()
    assert h.is_subtype("anything", "anything") is True


@pytest.mark.unit
def test_yaml_load_and_subtype():
    h = TypeHierarchy()
    yaml_path = _write_yaml(
        """
        types:
          return_path: { extends: email_address }
          pdf_file: { extends: file }
        """
    )
    h.load_yaml_config(yaml_path)

    assert h.parent_of("return_path") == "email_address"
    assert h.parent_of("pdf_file") == "file"
    assert h.is_subtype("return_path", "email_address") is True
    assert h.is_subtype("pdf_file", "file") is True


@pytest.mark.unit
def test_yaml_loads_inheritance_chain():
    h = TypeHierarchy()
    yaml_path = _write_yaml(
        """
        types:
          priority_return_path: { extends: return_path }
          return_path: { extends: email_address }
        """
    )
    h.load_yaml_config(yaml_path)

    assert h.ancestors("priority_return_path") == ("return_path", "email_address")
    assert h.is_subtype("priority_return_path", "email_address") is True
    assert h.is_subtype("priority_return_path", "return_path") is True


@pytest.mark.unit
def test_yaml_cycle_is_rejected_state_preserved(caplog):
    h = TypeHierarchy()
    good_yaml = _write_yaml(
        """
        types:
          return_path: { extends: email_address }
        """
    )
    h.load_yaml_config(good_yaml)
    assert h.parent_of("return_path") == "email_address"

    bad_yaml = _write_yaml(
        """
        types:
          return_path: { extends: email_address }
          email_address: { extends: return_path }
        """
    )
    with caplog.at_level("ERROR"):
        h.load_yaml_config(bad_yaml)

    # Prior YAML state intact, bad YAML not applied.
    assert h.parent_of("return_path") == "email_address"
    assert h.parent_of("email_address") is None
    assert any("cycle" in r.message.lower() for r in caplog.records)


@pytest.mark.unit
def test_yaml_missing_file_logs_and_no_state_change(caplog):
    h = TypeHierarchy()
    good_yaml = _write_yaml(
        """
        types:
          return_path: { extends: email_address }
        """
    )
    h.load_yaml_config(good_yaml)
    with caplog.at_level("ERROR"):
        h.load_yaml_config("/nonexistent/path/to/inheritance.yaml")

    assert h.parent_of("return_path") == "email_address"


@pytest.mark.unit
def test_yaml_schema_rejects_unknown_keys(caplog):
    h = TypeHierarchy()
    bad = _write_yaml(
        """
        types:
          return_path:
            extends: email_address
            color: red
        """
    )
    with caplog.at_level("ERROR"):
        h.load_yaml_config(bad)
    assert h.parent_of("return_path") is None


@pytest.mark.unit
def test_typed_config_model_validates():
    cfg = ObservableTypesFile.model_validate(
        {"types": {"a": {"extends": "b"}}}
    )
    assert cfg.types["a"].extends == "b"
    assert cfg.types["a"].default_display_type is None


@pytest.mark.unit
def test_observable_type_entry_all_fields_optional():
    # All fields optional — an entry can be empty.
    entry = ObservableTypeEntry()
    assert entry.extends is None
    assert entry.default_display_type is None
    assert entry.description is None
    assert entry.deprecated is False


@pytest.mark.unit
def test_default_display_type_unset_returns_none():
    h = TypeHierarchy()
    assert h.default_display_type_for("anything") is None


@pytest.mark.unit
def test_yaml_loads_default_display_type():
    h = TypeHierarchy()
    yaml_path = _write_yaml(
        """
        types:
          return_path:
            extends: email_address
            default_display_type: "Mail Return Path"
          azure_user_id:
            default_display_type: "Azure User ID"
        """
    )
    h.load_yaml_config(yaml_path)

    assert h.default_display_type_for("return_path") == "Mail Return Path"
    assert h.default_display_type_for("azure_user_id") == "Azure User ID"
    # azure_user_id has no extends, so it has no parent
    assert h.parent_of("azure_user_id") is None


@pytest.mark.unit
def test_yaml_entry_with_only_default_display_type_loads():
    """An entry can carry just default_display_type and no extends."""
    h = TypeHierarchy()
    yaml_path = _write_yaml(
        """
        types:
          azure_user_id:
            default_display_type: "Azure User ID"
        """
    )
    h.load_yaml_config(yaml_path)

    assert h.default_display_type_for("azure_user_id") == "Azure User ID"
    assert h.parent_of("azure_user_id") is None


@pytest.mark.unit
def test_yaml_reload_clears_removed_default_display_type():
    h = TypeHierarchy()
    first = _write_yaml(
        """
        types:
          azure_user_id:
            default_display_type: "Azure User ID"
        """
    )
    h.load_yaml_config(first)
    assert h.default_display_type_for("azure_user_id") == "Azure User ID"

    second = _write_yaml(
        """
        types:
          azure_user_id:
            extends: user
        """
    )
    h.load_yaml_config(second)
    assert h.default_display_type_for("azure_user_id") is None
    assert h.parent_of("azure_user_id") == "user"


@pytest.mark.unit
def test_description_unset_returns_none():
    h = TypeHierarchy()
    assert h.description_for("anything") is None


@pytest.mark.unit
def test_yaml_loads_description():
    h = TypeHierarchy()
    yaml_path = _write_yaml(
        """
        types:
          email_address:
            description: "email address"
          azure_user_id:
            description: "Azure user identifier"
        """
    )
    h.load_yaml_config(yaml_path)

    assert h.description_for("email_address") == "email address"
    assert h.description_for("azure_user_id") == "Azure user identifier"
    assert h.description_for("nope") is None


@pytest.mark.unit
def test_is_deprecated_default_false():
    h = TypeHierarchy()
    assert h.is_deprecated("anything") is False


@pytest.mark.unit
def test_yaml_loads_deprecated_flag():
    h = TypeHierarchy()
    yaml_path = _write_yaml(
        """
        types:
          email_address:
            description: "email address"
          pcap:
            description: "deprecated"
            deprecated: true
        """
    )
    h.load_yaml_config(yaml_path)

    assert h.is_deprecated("pcap") is True
    assert h.is_deprecated("email_address") is False


@pytest.mark.unit
def test_yaml_declared_types_includes_empty_entries():
    h = TypeHierarchy()
    yaml_path = _write_yaml(
        """
        types:
          empty_entry: {}
          described:
            description: "has a description"
          extends_one:
            extends: described
        """
    )
    h.load_yaml_config(yaml_path)

    declared = h.yaml_declared_types()
    assert declared == {"empty_entry", "described", "extends_one"}


@pytest.mark.unit
def test_yaml_reload_clears_removed_description_and_deprecated():
    h = TypeHierarchy()
    first = _write_yaml(
        """
        types:
          pcap:
            description: "old packet capture"
            deprecated: true
        """
    )
    h.load_yaml_config(first)
    assert h.description_for("pcap") == "old packet capture"
    assert h.is_deprecated("pcap") is True

    second = _write_yaml(
        """
        types:
          email_address:
            description: "email address"
        """
    )
    h.load_yaml_config(second)
    assert h.description_for("pcap") is None
    assert h.is_deprecated("pcap") is False


@pytest.mark.unit
def test_get_all_valid_types_combines_yaml_and_python():
    """A type counts as valid whether it has a Python class or only a YAML entry."""
    from saq.observables.generator import OBSERVABLE_TYPE_MAPPING
    from saq.observables.type_hierarchy import get_all_valid_types

    h = get_type_hierarchy()
    declared_snapshot = set(h._yaml_declared_types)
    h._yaml_declared_types.add("__pytest_yaml_only__")
    try:
        result = set(get_all_valid_types())
        assert "__pytest_yaml_only__" in result
        # A python-registered type that's not in YAML still appears.
        assert "test" in result  # F_TEST has a registered TestObservable class
        # Sanity: the result spans both sources
        assert set(OBSERVABLE_TYPE_MAPPING.keys()).issubset(result)
    finally:
        h._yaml_declared_types = declared_snapshot


@pytest.mark.unit
def test_yaml_non_ascii_description_is_decoded(tmpdir):
    """A utf-8 config must load regardless of the process locale."""
    h = TypeHierarchy()
    path = str(tmpdir / "types.yaml")
    em_dash = "—"
    with open(path, "wb") as f:
        f.write(
            (
                "types:\n"
                "  falcon_host_id:\n"
                f'    description: "Falcon agent ID {em_dash} unique per host"\n'
            ).encode("utf-8")
        )

    h.load_yaml_config(path)

    assert h.description_for("falcon_host_id") == f"Falcon agent ID {em_dash} unique per host"


@pytest.mark.unit
def test_yaml_undecodable_bytes_logs_and_state_preserved(caplog):
    """An undecodable config is logged, not raised, and prior state survives."""
    h = TypeHierarchy()
    good_yaml = _write_yaml(
        """
        types:
          return_path: { extends: email_address }
        """
    )
    h.load_yaml_config(good_yaml)
    assert h.parent_of("return_path") == "email_address"

    import os
    import tempfile

    fd, bad_path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "wb") as f:
        # \xff\xfe is not valid utf-8 in any position
        f.write(b'types:\n  bad:\n    description: "\xff\xfe"\n')

    with caplog.at_level("ERROR"):
        h.load_yaml_config(bad_path)

    assert h.parent_of("return_path") == "email_address"
    assert h.description_for("bad") is None
    assert any("failed to parse" in r.message.lower() for r in caplog.records)


@pytest.mark.unit
def test_yaml_loads_under_ascii_locale():
    """Regression: uwsgi embeds python with utf-8 mode off, so a C locale means
    the default open() encoding is ascii. The loader must not depend on it."""
    import os
    import subprocess
    import sys
    import textwrap

    import saq

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(saq.__file__)))
    script = textwrap.dedent(
        """
        import locale, sys
        assert locale.getpreferredencoding(False).lower() in ("ansi_x3.4-1968", "ascii"), (
            "expected an ascii locale, got %s" % locale.getpreferredencoding(False))
        assert sys.flags.utf8_mode == 0, "expected utf-8 mode off"

        from saq.observables.type_hierarchy import TypeHierarchy
        h = TypeHierarchy()
        h.load_yaml_config(sys.argv[1])
        assert h.description_for("t") == "a \\u2014 b", ascii(h.description_for("t"))
        print("OK")
        """
    )

    fd, yaml_path = __import__("tempfile").mkstemp(suffix=".yaml")
    with os.fdopen(fd, "wb") as f:
        f.write('types:\n  t:\n    description: "a — b"\n'.encode("utf-8"))

    env = dict(os.environ)
    env.update(
        {
            "PYTHONPATH": repo_root,
            "PYTHONUTF8": "0",
            "PYTHONCOERCECLOCALE": "0",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    result = subprocess.run(
        [sys.executable, "-X", "utf8=0", "-c", script, yaml_path],
        capture_output=True,
        text=True,
        env=env,
        cwd=repo_root,
    )
    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "OK" in result.stdout


def _write_yaml(content: str) -> str:
    import os
    import tempfile
    import textwrap

    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as f:
        f.write(textwrap.dedent(content))
    return path


def _rewrite_yaml(path: str, content: str, *, mtime_bump: float = 1.0) -> None:
    """Overwrite ``path`` with ``content`` and bump its mtime.

    Tests that exercise the runtime-reload path need the file's mtime to
    change so :meth:`TypeHierarchy._maybe_reload` notices. On fast hosts a
    rewrite within the same second can land with the same mtime under
    coarse-resolution filesystems, so we explicitly stat-then-bump.
    """
    import os
    import textwrap

    with open(path, "w") as f:
        f.write(textwrap.dedent(content))
    current = os.stat(path).st_mtime
    os.utime(path, (current, current + mtime_bump))


@pytest.mark.unit
def test_reload_picks_up_mtime_change():
    """A change to the file on disk is reflected after _maybe_reload runs."""
    h = TypeHierarchy()
    h._reload_check_interval = 60.0
    yaml_path = _write_yaml(
        """
        types:
          return_path: { extends: email_address }
        """
    )
    h.load_yaml_config(yaml_path)
    assert h.parent_of("return_path") == "email_address"
    assert h.parent_of("pdf_file") is None

    _rewrite_yaml(
        yaml_path,
        """
        types:
          pdf_file: { extends: file }
        """,
    )

    # Bypass the debounce window so the next accessor triggers a reload.
    h._next_reload_check = None
    h._maybe_reload()

    assert h.parent_of("pdf_file") == "file"
    # return_path was removed from the YAML, so it should be gone now too.
    assert h.parent_of("return_path") is None


@pytest.mark.unit
def test_reload_no_op_when_mtime_unchanged():
    """If nothing changed on disk, _maybe_reload doesn't rebuild state."""
    h = TypeHierarchy()
    h._reload_check_interval = 60.0
    yaml_path = _write_yaml(
        """
        types:
          return_path: { extends: email_address }
        """
    )
    h.load_yaml_config(yaml_path)
    parent_dict_before = h._parent  # identity, not value
    last_mtime_before = h._last_mtime

    h._next_reload_check = None
    h._maybe_reload()

    # Same dict instance — load_yaml_config was not called.
    assert h._parent is parent_dict_before
    assert h._last_mtime == last_mtime_before


@pytest.mark.unit
def test_reload_debounce_prevents_excessive_stats(monkeypatch):
    """Within the debounce window, repeated accessors stat the file at most once."""
    import os as os_mod

    h = TypeHierarchy()
    h._reload_check_interval = 60.0
    yaml_path = _write_yaml(
        """
        types:
          return_path: { extends: email_address }
        """
    )
    h.load_yaml_config(yaml_path)

    real_stat = os_mod.stat
    stat_paths: list[str] = []

    def counting_stat(p, *args, **kwargs):
        if p == yaml_path:
            stat_paths.append(p)
        return real_stat(p, *args, **kwargs)

    monkeypatch.setattr(os_mod, "stat", counting_stat)

    # First call after load may stat once if the next-check window has expired;
    # subsequent calls within the window must not stat at all.
    h._next_reload_check = None
    h._maybe_reload()
    first_count = len(stat_paths)
    for _ in range(20):
        h._maybe_reload()
    assert len(stat_paths) == first_count, (
        "expected debounce to suppress stats, got "
        f"{len(stat_paths) - first_count} extra calls"
    )


@pytest.mark.unit
def test_reload_preserves_state_on_bad_file(caplog):
    """A malformed file at reload time leaves the prior state intact."""
    h = TypeHierarchy()
    h._reload_check_interval = 60.0
    yaml_path = _write_yaml(
        """
        types:
          return_path: { extends: email_address }
        """
    )
    h.load_yaml_config(yaml_path)
    assert h.parent_of("return_path") == "email_address"

    _rewrite_yaml(
        yaml_path,
        """
        types:
          return_path:
            extends: email_address
            color: red
        """,
    )

    h._next_reload_check = None
    with caplog.at_level("ERROR"):
        h._maybe_reload()

    # Bad reload didn't clobber prior state.
    assert h.parent_of("return_path") == "email_address"


@pytest.mark.unit
def test_reload_disabled_when_interval_zero():
    """Setting reload_check_interval <= 0 disables runtime reload entirely."""
    h = TypeHierarchy()
    yaml_path = _write_yaml(
        """
        types:
          return_path: { extends: email_address }
        """
    )
    h.load_yaml_config(yaml_path)
    h._reload_check_interval = 0

    _rewrite_yaml(
        yaml_path,
        """
        types:
          pdf_file: { extends: file }
        """,
    )

    # Even with the debounce cleared and the file changed, no reload.
    h._next_reload_check = None
    h._maybe_reload()
    assert h.parent_of("pdf_file") is None
    assert h.parent_of("return_path") == "email_address"


@pytest.mark.unit
def test_reload_handles_vanished_file(caplog):
    """If the file disappears between bootstrap and a reload, prior state is kept."""
    import os as os_mod

    h = TypeHierarchy()
    h._reload_check_interval = 60.0
    yaml_path = _write_yaml(
        """
        types:
          return_path: { extends: email_address }
        """
    )
    h.load_yaml_config(yaml_path)
    assert h.parent_of("return_path") == "email_address"

    os_mod.remove(yaml_path)
    h._next_reload_check = None
    with caplog.at_level("WARNING"):
        h._maybe_reload()

    assert h.parent_of("return_path") == "email_address"
    assert any("vanished" in r.message.lower() for r in caplog.records)


@pytest.mark.unit
def test_reload_does_nothing_when_never_bootstrapped():
    """A registry that was never loaded from a file has no path to re-stat."""
    h = TypeHierarchy()
    assert h._config_path is None
    h._reload_check_interval = 60.0
    h._next_reload_check = None
    # Should not raise, should not change state.
    h._maybe_reload()
    assert h._config_path is None


@pytest.mark.unit
def test_get_type_hierarchy_triggers_reload(monkeypatch):
    """The module-level accessor calls _maybe_reload on every fetch."""
    from saq.observables import type_hierarchy as th

    calls = {"count": 0}

    def fake_maybe_reload(_self):
        calls["count"] += 1

    monkeypatch.setattr(TypeHierarchy, "_maybe_reload", fake_maybe_reload)
    th.get_type_hierarchy()
    th.get_type_hierarchy()
    assert calls["count"] == 2


@pytest.mark.unit
def test_get_all_valid_types_triggers_reload(monkeypatch):
    """get_all_valid_types also routes through _maybe_reload."""
    from saq.observables import type_hierarchy as th

    calls = {"count": 0}

    def fake_maybe_reload(_self):
        calls["count"] += 1

    monkeypatch.setattr(TypeHierarchy, "_maybe_reload", fake_maybe_reload)
    th.get_all_valid_types()
    assert calls["count"] == 1


@pytest.mark.unit
def test_reset_clears_reload_state():
    """reset() (test helper) wipes the runtime-reload bookkeeping too."""
    h = TypeHierarchy()
    yaml_path = _write_yaml(
        """
        types:
          return_path: { extends: email_address }
        """
    )
    h.load_yaml_config(yaml_path)
    assert h._config_path is not None
    assert h._last_mtime is not None

    h.reset()
    assert h._config_path is None
    assert h._last_mtime is None
    assert h._next_reload_check is None
