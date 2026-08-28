import importlib

import pytest
from pydantic import BaseModel, ValidationError

from saq.configuration.lazy_registry import LazyConfigRegistry

#
# a fake plugin: a base config, a subclass with an extra required field, and the class
# that declares the subclass through get_config_class()
#

class FakeBaseConfig(BaseModel):
    name: str
    python_module: str
    python_class: str
    enabled: bool = True


class FakeExtendedConfig(FakeBaseConfig):
    extra_setting: str


class FakePlugin:
    @staticmethod
    def get_config_class():
        return FakeExtendedConfig


def raw_config(name: str, **kwargs) -> dict:
    result = {
        "name": name,
        "python_module": "tests.saq.configuration.test_lazy_registry",
        "python_class": "FakePlugin",
        "enabled": True,
        "extra_setting": "value",
    }
    result.update(kwargs)
    return result


@pytest.fixture
def registry():
    return LazyConfigRegistry(FakeBaseConfig, "fake config")


@pytest.fixture
def import_counter(monkeypatch):
    """Counts calls to importlib.import_module made by the registry."""
    calls = []
    original = importlib.import_module

    def _counting_import_module(name, *args, **kwargs):
        calls.append(name)
        return original(name, *args, **kwargs)

    monkeypatch.setattr("saq.configuration.lazy_registry.importlib.import_module", _counting_import_module)
    return calls


@pytest.mark.unit
def test_add_raw_does_not_import(registry, import_counter):
    """add_raw validates against the base class without importing the plugin module"""
    config = registry.add_raw("fake_one", raw_config("one"))

    assert type(config) is FakeBaseConfig
    assert config.name == "one"
    assert import_counter == []
    assert not registry.is_resolved("one")


@pytest.mark.unit
def test_membership_and_length_do_not_resolve(registry, import_counter):
    """the read-only inspection API never forces resolution"""
    registry.add_raw("fake_one", raw_config("one"))
    registry.add_raw("fake_two", raw_config("two"))

    assert "one" in registry
    assert "missing" not in registry
    assert registry.names() == ["one", "two"]
    assert len(registry) == 2
    assert registry.is_resolved("one") is False
    assert import_counter == []


@pytest.mark.unit
def test_get_resolves_once_and_keeps_identity(registry, import_counter):
    """get() resolves the plugin subclass, caches it, and always returns the same object"""
    registry.add_raw("fake_one", raw_config("one"))

    config = registry.get("one")

    assert isinstance(config, FakeExtendedConfig)
    assert config.extra_setting == "value"
    assert import_counter == ["tests.saq.configuration.test_lazy_registry"]
    assert registry.is_resolved("one")

    # mutations made by a caller must be visible to the next caller
    config.enabled = False
    assert registry.get("one") is config
    assert registry.get("one").enabled is False

    # and no second import
    assert import_counter == ["tests.saq.configuration.test_lazy_registry"]


@pytest.mark.unit
def test_values_reuses_cached_instance(registry):
    """values() after a get() hands back the same object -- the `ace correlate` ordering"""
    registry.add_raw("fake_one", raw_config("one"))
    registry.add_raw("fake_two", raw_config("two"))

    first = registry.get("one")
    first.enabled = False

    values = registry.values()

    assert len(values) == 2
    assert values[0] is first
    assert values[0].enabled is False
    assert all(isinstance(config, FakeExtendedConfig) for config in values)

    # the reverse ordering also holds: mutate through values(), read back through get()
    values[1].enabled = False
    assert registry.get("two") is values[1]
    assert registry.get("two").enabled is False


@pytest.mark.unit
def test_get_unknown_name_raises_key_error(registry):
    with pytest.raises(KeyError):
        registry.get("missing")


@pytest.mark.unit
def test_add_resolved_never_imports(registry, import_counter):
    """add_resolved takes a finished object, even one whose python_module does not exist"""
    config = FakeExtendedConfig(
        name="one",
        python_module="does.not.exist",
        python_class="Nope",
        extra_setting="value")

    registry.add_resolved("one", config)

    assert registry.is_resolved("one")
    assert registry.get("one") is config
    assert registry.values() == [config]
    assert import_counter == []


@pytest.mark.unit
def test_add_resolved_replaces_in_place(registry):
    """replacing an existing name keeps its position in the collection"""
    registry.add_raw("fake_one", raw_config("one"))
    registry.add_raw("fake_two", raw_config("two"))

    replacement = FakeExtendedConfig(
        name="one",
        python_module="does.not.exist",
        python_class="Nope",
        extra_setting="replaced")
    registry.add_resolved("one", replacement)

    assert registry.names() == ["one", "two"]
    assert registry.values()[0] is replacement
    assert registry.get("one").extra_setting == "replaced"


@pytest.mark.unit
def test_add_raw_reports_base_validation_failure(registry, capsys):
    """a block that fails base validation fails immediately, with the config key named"""
    invalid = raw_config("one")
    del invalid["python_module"]

    with pytest.raises(ValidationError):
        registry.add_raw("fake_one", invalid)

    assert "CONFIG ERROR: failed to validate fake config for fake_one" in capsys.readouterr().err


@pytest.mark.unit
def test_get_reports_subclass_validation_failure(registry, capsys):
    """a block that only fails the plugin subclass fails at resolution, with the key named"""
    invalid = raw_config("one")
    del invalid["extra_setting"]

    registry.add_raw("fake_one", invalid)
    capsys.readouterr()

    with pytest.raises(ValidationError):
        registry.get("one")

    assert "CONFIG ERROR: failed to validate fake config for fake_one" in capsys.readouterr().err


@pytest.mark.unit
def test_get_reports_missing_module(registry, capsys):
    """an unimportable python_module is reported the same way, and still raises"""
    registry.add_raw("fake_one", raw_config("one", python_module="does.not.exist"))
    capsys.readouterr()

    with pytest.raises(ModuleNotFoundError):
        registry.get("one")

    assert "CONFIG ERROR: failed to validate fake config for fake_one" in capsys.readouterr().err


@pytest.mark.unit
def test_get_reports_missing_class(registry, capsys):
    """a python_class that is not in the module is reported the same way, and still raises"""
    registry.add_raw("fake_one", raw_config("one", python_class="NoSuchClass"))
    capsys.readouterr()

    with pytest.raises(AttributeError):
        registry.get("one")

    assert "CONFIG ERROR: failed to validate fake config for fake_one" in capsys.readouterr().err
