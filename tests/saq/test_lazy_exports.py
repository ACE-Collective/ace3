import os.path
import sys
import types

import pytest

from saq.lazy_exports import lazy_getattr

pytestmark = pytest.mark.unit


@pytest.fixture
def package(monkeypatch):
    module = types.ModuleType("fake_package")
    module.__getattr__ = lazy_getattr("fake_package", {"join": "os.path", "path_join": ("os.path", "join")})
    monkeypatch.setitem(sys.modules, "fake_package", module)
    return module


def test_a_name_is_imported_on_first_use_and_kept(package):
    assert "join" not in vars(package)
    assert package.join is os.path.join
    assert vars(package)["join"] is os.path.join


def test_a_name_can_be_exported_under_another_name(package):
    assert package.path_join is os.path.join


def test_an_unknown_name_raises_attribute_error(package):
    with pytest.raises(AttributeError, match="module 'fake_package' has no attribute 'nope'"):
        package.nope
