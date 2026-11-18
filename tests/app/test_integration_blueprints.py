"""The GUI blueprints an integration declares with gui_blueprint in its integration_<name>: block."""

import logging
import sys
import uuid

import pytest

from app.application import create_app

pytestmark = pytest.mark.integration


@pytest.fixture
def blueprint_module(tmp_path, monkeypatch) -> str:
    """The name of a module, importable but not yet imported, with a function that registers a blueprint
    and one that raises."""
    name = f"vendor_gui_{uuid.uuid4().hex}"
    (tmp_path / f"{name}.py").write_text(
        "from flask import Blueprint\n"
        f"bp = Blueprint('{name}', __name__, url_prefix='/{name}')\n"
        "@bp.route('/')\n"
        "def index():\n"
        "    return 'vendor page'\n"
        "def register(flask_app):\n"
        "    flask_app.register_blueprint(bp)\n"
        "def broken(flask_app):\n"
        "    raise RuntimeError('cannot register')\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    yield name
    sys.modules.pop(name, None)


def test_registered_when_the_gui_is_built(declare_integration, blueprint_module):
    declare_integration("vendor", gui_blueprint=f"{blueprint_module}:register")
    assert blueprint_module not in sys.modules

    flask_app = create_app()

    assert blueprint_module in flask_app.blueprints
    response = flask_app.test_client().get(f"/{blueprint_module}/")
    assert response.status_code == 200
    assert response.text == "vendor page"


def test_a_disabled_integration_is_not_registered(declare_integration, blueprint_module):
    declare_integration("vendor", gui_blueprint=f"{blueprint_module}:register", enabled=False)

    assert blueprint_module not in create_app().blueprints
    assert blueprint_module not in sys.modules


@pytest.mark.parametrize("target", ["no_such_integration_module:register", "{module}:no_such_function",
                                    "{module}:broken"])
def test_one_that_fails_is_logged_and_the_gui_still_starts(declare_integration, blueprint_module, caplog, target):
    target = target.format(module=blueprint_module)
    declare_integration("broken", gui_blueprint=target)
    declare_integration("vendor", gui_blueprint=f"{blueprint_module}:register")

    with caplog.at_level(logging.ERROR):
        flask_app = create_app()

    assert blueprint_module in flask_app.blueprints
    errors = [record for record in caplog.records
              if record.getMessage() == f"unable to load the gui_blueprint of integration broken from {target}"]
    assert len(errors) == 1
    assert errors[0].levelno == logging.ERROR and errors[0].exc_info is not None
    assert (errors[0].integration, errors[0].hook, errors[0].target) == ("broken", "gui_blueprint", target)
