"""The GUI module an integration declares (gui_module in its integration_<name>: block), which only the
GUI imports when it builds its app."""

import logging
import sys
import uuid
from types import SimpleNamespace

import pytest

import app.integration
from app.application import create_app
from saq.configuration.schema import IntegrationConfig
from saq.integration import integration_loader
from saq.integration.integration_loader import import_integration_modules

pytestmark = pytest.mark.integration


@pytest.fixture
def configured(monkeypatch) -> list[IntegrationConfig]:
    """No integration_<name>: blocks and no blueprint callbacks, so these tests do not see the
    integrations installed here. A test appends the blocks it needs to the list."""
    blocks: list[IntegrationConfig] = []
    monkeypatch.setattr(integration_loader, "get_config", lambda: SimpleNamespace(integrations=blocks))
    monkeypatch.setattr(app.integration, "_BLUEPRINT_CALLBACKS", [])
    return blocks


@pytest.fixture
def gui_module(tmp_path, monkeypatch) -> str:
    """The name of a module, importable but not yet imported, that registers a blueprint the way an
    integration's GUI module does."""
    name = f"vendor_gui_{uuid.uuid4().hex}"
    (tmp_path / f"{name}.py").write_text(
        "from flask import Blueprint\n"
        "from app.integration import register_integration_blueprint_callback\n"
        f"vendor_bp = Blueprint({name!r}, __name__, url_prefix='/vendor')\n"
        "@vendor_bp.route('/')\n"
        "def index():\n"
        "    return 'vendor'\n"
        "register_integration_blueprint_callback(lambda flask_app: flask_app.register_blueprint(vendor_bp))\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    yield name
    sys.modules.pop(name, None)


def _block(name: str, gui_module: str | None) -> IntegrationConfig:
    return IntegrationConfig(name=name, description="test", enabled=True, python_module="vendor",
                             gui_module=gui_module)


def test_imported_when_the_app_is_built(configured, gui_module):
    configured.append(_block("vendor", gui_module))

    flask_app = create_app()

    assert gui_module in sys.modules
    # its blueprint callback ran after the import, in the same create_app()
    assert gui_module in flask_app.blueprints


def test_a_block_without_one_imports_nothing(configured, monkeypatch):
    configured.append(_block("vendor", None))
    imported = []
    monkeypatch.setattr(integration_loader.importlib, "import_module", imported.append)

    import_integration_modules("gui_module")

    assert imported == []


def test_a_module_that_fails_to_import_is_logged_and_left_out(configured, gui_module, caplog):
    configured.append(_block("broken", "no_such_integration_gui_module"))
    configured.append(_block("vendor", gui_module))

    with caplog.at_level(logging.ERROR):
        flask_app = create_app()

    assert gui_module in flask_app.blueprints
    errors = [record for record in caplog.records
              if record.getMessage() == "unable to import the gui_module no_such_integration_gui_module of "
                                        "integration broken"]
    assert len(errors) == 1
    assert errors[0].levelno == logging.ERROR and errors[0].exc_info is not None
    assert errors[0].integration == "broken"
