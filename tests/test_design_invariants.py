"""Every code citation in docs/DESIGN_INVARIANTS.md still names something that exists.

The index cites code as `path::Name` instead of by line number so that ordinary edits leave it
correct. A rename or removal is what makes an entry wrong, and that is what this catches. /ace-review's
stale-reference check sees removed files and top-level names; this also sees methods and
module-level assignments.
"""

import ast
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[1]
INDEX = REPO / "docs" / "DESIGN_INVARIANTS.md"

SYMBOL_CITATION = re.compile(r"`([\w./-]+\.py)::([\w.]+)`")
PATH_CITATION = re.compile(r"`((?:[\w.-]+/)+[\w.-]+\.(?:py|sh|ya?ml|conf|md)|Dockerfile)`")
DOC_TAG = re.compile(r"(?<![\w/])docs/[\w.-]+\.md")


def _defined_names(body: list[ast.stmt]) -> dict[str, ast.AST]:
    names: dict[str, ast.AST] = {}
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names[node.name] = node
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names[target.id] = node
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names[node.target.id] = node
    return names


def resolve(path: Path, qualname: str) -> bool:
    """Whether qualname (a function, class, method, or module or class level assignment) is defined in path."""
    node: ast.AST = ast.parse(path.read_text(), filename=str(path))
    for part in qualname.split("."):
        # a function's locals are not citable, so only a module or a class has names to look in
        if not isinstance(node, (ast.Module, ast.ClassDef)):
            return False
        node = _defined_names(node.body).get(part)
        if node is None:
            return False
    return True


def test_resolve(tmp_path):
    source = tmp_path / "m.py"
    source.write_text("X = 1\nclass C:\n    y: int = 2\n    def m(self):\n        z = 3\ndef f():\n    pass\n")
    assert resolve(source, "X")
    assert resolve(source, "C.y")
    assert resolve(source, "C.m")
    assert resolve(source, "f")
    assert not resolve(source, "C.m.z")
    assert not resolve(source, "C.missing")
    assert not resolve(source, "g")


def test_symbol_citations_resolve():
    text = INDEX.read_text()
    citations = SYMBOL_CITATION.findall(text)
    assert citations, "no path::Name citations found; did the citation format change?"
    missing = []
    for path, qualname in citations:
        source = REPO / path
        if not source.is_file():
            missing.append(f"{path}::{qualname} (no such file)")
        elif not resolve(source, qualname):
            missing.append(f"{path}::{qualname}")
    assert not missing, "docs/DESIGN_INVARIANTS.md cites names that no longer exist:\n" + "\n".join(missing)


def test_path_citations_exist():
    text = INDEX.read_text()
    paths = set(PATH_CITATION.findall(text)) | set(DOC_TAG.findall(text))
    missing = sorted(p for p in paths if not (REPO / p).exists())
    assert not missing, "docs/DESIGN_INVARIANTS.md cites paths that no longer exist:\n" + "\n".join(missing)
