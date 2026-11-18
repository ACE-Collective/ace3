"""The integration_<name>: block (IntegrationConfig)."""

import pytest
from pydantic import ValidationError

from saq.configuration.schema import IntegrationConfig

pytestmark = pytest.mark.unit


def _config(name: str = "vendor", **kwargs) -> IntegrationConfig:
    return IntegrationConfig(name=name, description="vendor", enabled=True, python_module="vendor", **kwargs)


def test_the_hooks_are_optional():
    config = _config()

    assert config.api_router is None and config.gui_blueprint is None


@pytest.mark.parametrize("hook", ["api_router", "gui_blueprint"])
@pytest.mark.parametrize("target", ["vendor.api.router", "vendor.api:", ":router", "vendor api:router",
                                    "vendor.api:router.attr", "vendor..api:router"])
def test_a_hook_must_be_module_and_attribute(hook, target):
    with pytest.raises(ValidationError, match=f"{hook}: '{target}' is not module:attribute"):
        _config(**{hook: target})


@pytest.mark.parametrize("hook", ["api_router", "gui_blueprint"])
def test_a_hook_is_not_imported_when_the_config_is_validated(hook):
    # only the app that uses a hook imports it
    assert getattr(_config(**{hook: "no_such_integration_module:attr"}), hook) == "no_such_integration_module:attr"


@pytest.mark.parametrize("name", ["vendor", "vendor-api", "vendor_api", "v2"])
def test_a_router_name_that_is_a_url_prefix(name):
    assert _config(name, api_router="vendor.api:router").name == name


@pytest.mark.parametrize("name", ["Vendor", "a/b", "-a", "a-", "a_", "a b", ""])
def test_a_router_name_that_is_not_a_url_prefix(name):
    with pytest.raises(ValidationError, match="its name must be lowercase"):
        _config(name, api_router="vendor.api:router")


def test_the_name_of_an_integration_without_a_router_is_not_checked():
    assert _config("Vendor Integration").name == "Vendor Integration"
