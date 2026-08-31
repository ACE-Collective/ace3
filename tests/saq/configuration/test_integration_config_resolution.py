"""Integration configuration lookup must not depend on registration order.

Integration config classes are registered as an import side effect of the integration package
(``register_integration_configuration`` at the bottom of the package ``__init__``). Which process
imports which integration, and when, varies -- and since analysis module / service configs resolve
lazily, an integration package can first be imported long after ``resolve_configuration()`` has run.
A registration that arrives late must still be usable.
"""

import pytest
from pydantic import BaseModel

from saq.configuration import config as config_module
from saq.configuration.config import (
    get_config,
    register_integration_configuration,
    resolve_configuration,
)


class FakeIntegrationConfig(BaseModel):
    """Validated against the whole raw config dict, the way real integration configs are."""
    global_settings: dict = {}


@pytest.fixture(autouse=True, scope="function")
def restore_integration_registries():
    """The two registries are process globals shared with every other test."""
    saved_registered = dict(config_module.REGISTERED_INTEGRATION_CONFIGURATIONS)
    saved_resolved = dict(config_module.INTEGRATION_CONFIGURATIONS)
    saved_resolved_flag = config_module.CONFIG_RESOLVED

    yield

    config_module.CONFIG_RESOLVED = saved_resolved_flag

    config_module.REGISTERED_INTEGRATION_CONFIGURATIONS.clear()
    config_module.REGISTERED_INTEGRATION_CONFIGURATIONS.update(saved_registered)
    config_module.INTEGRATION_CONFIGURATIONS.clear()
    config_module.INTEGRATION_CONFIGURATIONS.update(saved_resolved)


@pytest.mark.unit
def test_integration_registered_after_resolve_configuration_still_resolves():
    """An integration imported after resolve_configuration() must still be readable.

    This is the shape of the v3.0.101 vt_hash_downloader failure: lazy analysis module resolution
    means the integration package is not imported until the engine constructs the module, which is
    after resolve_configuration() has already run.
    """
    resolve_configuration(get_config())

    # the integration package gets imported here -- after the snapshot
    register_integration_configuration("fake_late_integration", FakeIntegrationConfig)

    integration_config = get_config("fake_late_integration")

    assert isinstance(integration_config, FakeIntegrationConfig)


@pytest.mark.unit
def test_integration_registered_before_resolve_configuration_still_resolves():
    """The eager path keeps working: registration before the snapshot resolves as it always did."""
    register_integration_configuration("fake_early_integration", FakeIntegrationConfig)

    resolve_configuration(get_config())

    assert isinstance(get_config("fake_early_integration"), FakeIntegrationConfig)


@pytest.mark.unit
def test_unregistered_integration_raises():
    """A name no integration ever registered is still an error, with the message ops greps for."""
    with pytest.raises(KeyError, match="integration configuration for nope_not_here not found"):
        get_config("nope_not_here")


@pytest.mark.unit
def test_late_registration_populates_the_iterable_dict():
    """A late registration must land in INTEGRATION_CONFIGURATIONS, not just be reachable by name.

    aceapi_ai/startup_checks.py:74 *iterates* that dict to build the secret custody model list --
    a check whose docstring says it "errs loud, not silent". An integration that is only resolved
    when someone asks for it by name would be skipped by that sweep, so a plaintext credential in
    its config block would pass the check.
    """
    resolve_configuration(get_config())

    register_integration_configuration("fake_swept_integration", FakeIntegrationConfig)

    assert "fake_swept_integration" in config_module.INTEGRATION_CONFIGURATIONS


@pytest.mark.unit
def test_resolved_integration_config_is_cached():
    """Repeated lookups hand back the same object -- callers mutate these in place."""
    resolve_configuration(get_config())
    register_integration_configuration("fake_cached_integration", FakeIntegrationConfig)

    assert get_config("fake_cached_integration") is get_config("fake_cached_integration")
