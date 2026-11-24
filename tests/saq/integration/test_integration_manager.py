"""Which integration directories are on, from the configuration (saq/integration/integration_manager.py)."""

import pytest

from saq.environment import get_global_runtime_settings
from saq.integration.integration_manager import get_integration_dir_configs, is_integration_dir_enabled
from tests.saq.helpers import configure_integrations

pytestmark = pytest.mark.unit


@pytest.fixture
def integration(tmp_path, monkeypatch):
    """Writes an integration directory with the given etc/saq.integration.yaml and registers its
    file the way load_integrations() does. Returns a function (name, body) -> its directory."""
    monkeypatch.setattr(get_global_runtime_settings(), "integration_config_paths", [])
    monkeypatch.delenv("SAQ_CONFIG_PATHS", raising=False)

    def create(name: str, body: str) -> str:
        integration_dir = tmp_path / name
        (integration_dir / "etc").mkdir(parents=True)
        (integration_dir / "etc" / "saq.integration.yaml").write_text(body)
        get_global_runtime_settings().integration_config_paths.append(str(integration_dir / "etc" / "saq.integration.yaml"))
        return str(integration_dir)

    return create


def _block(name: str, enabled: bool) -> str:
    return (f"integration_{name}:\n  name: {name}\n  enabled: {str(enabled).lower()}\n"
            f"  description: {name}\n  python_module: {name}\n")


def test_an_integration_is_off_when_its_every_section_is_disabled(integration, monkeypatch):
    on = integration("switched_on", _block("switched_on", True))
    off = integration("switched_off", _block("switched_off", False))
    half = integration("half", _block("half_on", True) + _block("half_off", False))
    undeclared = integration("undeclared", "")
    configure_integrations(monkeypatch)

    assert is_integration_dir_enabled(on)
    assert not is_integration_dir_enabled(off)
    assert is_integration_dir_enabled(half)
    assert is_integration_dir_enabled(undeclared)


def test_the_sections_of_an_integration(integration, monkeypatch):
    half = integration("half", _block("half_on", True) + _block("half_off", False))
    undeclared = integration("undeclared", "")
    configure_integrations(monkeypatch)

    assert sorted((config.name, config.enabled) for config in get_integration_dir_configs(half)) == [
        ("half_off", False), ("half_on", True)]
    assert get_integration_dir_configs(undeclared) == []
