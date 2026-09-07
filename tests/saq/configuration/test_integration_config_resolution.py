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
from tests.saq.helpers import (
    restore_integration_configurations,
    snapshot_integration_configurations,
)


class FakeIntegrationConfig(BaseModel):
    """Validated against the whole raw config dict, the way real integration configs are."""
    global_settings: dict = {}


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


@pytest.mark.unit
def test_integration_config_object_mutation_is_rolled_back():
    """A field written on a cached integration config must not outlive the test that wrote it.

    get_config(<name>) hands back a shared mutable pydantic object, and tests do write to it --
    ace_crowdstrike/tests/test_lib.py set crowdstrike.proxy that way. tests/conftest.py restores
    the ACEConfig with set_config(), which rolls back an add_proxy_config() but not a field set on
    an integration config object. That asymmetry left every later falcon module construction
    asking for a proxy that no longer existed, and only under the pytest-randomly orders that put
    the crowdstrike file first.
    """
    register_integration_configuration("fake_mutated_integration", FakeIntegrationConfig)
    snapshot = snapshot_integration_configurations()

    get_config("fake_mutated_integration").global_settings["leaked"] = True

    restore_integration_configurations(snapshot)

    assert "leaked" not in get_config("fake_mutated_integration").global_settings
