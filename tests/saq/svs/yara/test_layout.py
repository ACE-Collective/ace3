"""Which directories of a repository the yara service loads (saq.svs.yara.layout)."""

import os

import pytest

from saq.configuration.config import get_config
from saq.svs.yara.layout import LayoutError, Namespace, derive_layout, resolve_layout, tree_layout
from tests.saq.svs.yara.conftest import REPOSITORY


def _touch(path, content="rule x { condition: false }\n"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fp:
        fp.write(content)


@pytest.mark.unit
def test_signature_dir_inside_the_checkout_is_contained(tmp_path):
    (tmp_path / "repo" / "yara").mkdir(parents=True)
    layout = derive_layout("r", str(tmp_path / "repo"), str(tmp_path / "repo" / "yara"))
    assert layout.contained
    assert layout.signature_dir_path == "yara"

    layout = derive_layout("r", str(tmp_path / "repo"), str(tmp_path / "repo"))
    assert layout.signature_dir_path == ""


@pytest.mark.unit
def test_entries_linking_into_the_checkout_are_namespaces(tmp_path):
    (tmp_path / "repo" / "rules" / "acme").mkdir(parents=True)
    (tmp_path / "repo" / "rules" / "other").mkdir(parents=True)
    (tmp_path / "elsewhere").mkdir()
    signature_dir = tmp_path / "signatures"
    signature_dir.mkdir()
    os.symlink(tmp_path / "repo" / "rules" / "acme", signature_dir / "acme")
    os.symlink(tmp_path / "repo", signature_dir / "whole")
    os.symlink(tmp_path / "elsewhere", signature_dir / "unrelated")
    (signature_dir / "local").mkdir()
    (signature_dir / "loose.yar").write_text("")

    layout = derive_layout("r", str(tmp_path / "repo"), str(signature_dir))
    assert not layout.contained
    assert layout.namespaces == (Namespace("acme", "rules/acme"), Namespace("whole", ""))


@pytest.mark.unit
def test_a_checkout_that_feeds_nothing_is_an_error(tmp_path):
    (tmp_path / "repo").mkdir()
    (tmp_path / "signatures" / "local").mkdir(parents=True)
    with pytest.raises(LayoutError, match="holds no rules"):
        derive_layout("r", str(tmp_path / "repo"), str(tmp_path / "signatures"))


@pytest.mark.integration
def test_only_configured_repositories_resolve(svs_repository, monkeypatch):
    assert resolve_layout(REPOSITORY).signature_dir_path == "yara"

    monkeypatch.setattr(get_config().svs.yara, "repositories", [])
    with pytest.raises(LayoutError, match="not in svs.yara.repositories"):
        resolve_layout(REPOSITORY)

    monkeypatch.setattr(get_config().svs.yara, "repositories", ["nope"])
    with pytest.raises(LayoutError, match="no git_repo_nope section"):
        resolve_layout("nope")


@pytest.mark.unit
def test_tree_layout_lists_namespaces_and_what_is_not_loaded(tmp_path):
    tree = tmp_path / "tree"
    _touch(tree / "yara" / "acme" / "a.yar")
    _touch(tree / "yara" / "acme" / "B.YARA")
    _touch(tree / "yara" / "acme" / "notes.txt")
    _touch(tree / "yara" / "acme" / "deeper" / "c.yar")
    _touch(tree / "yara" / "loose.yar")
    _touch(tree / "docs" / "example.yar")
    (tree / "yara" / "empty").mkdir()

    layout = derive_layout("r", str(tmp_path / "checkout"), str(tmp_path / "checkout" / "yara"))
    result = tree_layout(layout, str(tree))

    assert [(namespace.name, [os.path.basename(path) for path in namespace.files]) for namespace in result.namespaces] == [
        ("acme", ["B.YARA", "a.yar"]), ("empty", [])]
    assert {(item.path, item.reason.split(":")[0]) for item in result.not_loaded} == {
        ("yara/acme/deeper/c.yar", "nested below a namespace directory"),
        ("yara/loose.yar", "loose in the signature directory"),
        ("docs/example.yar", "not in a directory the yara service loads"),
    }


@pytest.mark.unit
def test_tree_layout_of_a_linked_repository(tmp_path):
    (tmp_path / "checkout" / "rules" / "acme").mkdir(parents=True)
    (tmp_path / "checkout" / "rules" / "gone").mkdir(parents=True)
    signature_dir = tmp_path / "signatures"
    signature_dir.mkdir()
    os.symlink(tmp_path / "checkout" / "rules" / "acme", signature_dir / "acme")
    os.symlink(tmp_path / "checkout" / "rules" / "gone", signature_dir / "gone")
    layout = derive_layout("r", str(tmp_path / "checkout"), str(signature_dir))

    tree = tmp_path / "tree"
    _touch(tree / "rules" / "acme" / "a.yar")
    _touch(tree / "rules" / "new" / "b.yar")
    result = tree_layout(layout, str(tree))

    assert [namespace.name for namespace in result.namespaces] == ["acme"]
    assert result.absent == ["gone"]
    assert [item.path for item in result.not_loaded] == ["rules/new/b.yar"]
