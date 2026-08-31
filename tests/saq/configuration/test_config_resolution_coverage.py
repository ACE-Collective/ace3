"""Forces full resolution of every plugin config block in etc/saq.default.yaml.

Service, analysis module and observable export configs are resolved lazily (see
saq/configuration/lazy_registry.py) so that an `ace` process only imports the plugins it
actually uses. That means a bad module-specific config key no longer fails at startup for
every command -- it fails the first time that block is used. These tests put the eager
check back where it belongs: in CI, once, instead of in every process, every time.
"""

import importlib

import pytest

from saq.configuration.loader import load_configuration
from saq.configuration.lazy_registry import resolve_config_class
from saq.configuration.schema import ACEConfig


def build_config() -> ACEConfig:
    """Builds a private ACEConfig from the real configuration files.

    Deliberately not get_config() -- the global config is mutated in place by other tests
    (add_service_config, module enable/disable) and half of it may already be resolved.
    """
    raw_config = load_configuration(config_paths=[])
    config = ACEConfig.model_validate(raw_config._data)
    config.raw = raw_config
    return config


@pytest.fixture(scope="module")
def resolved_config() -> ACEConfig:
    # module scoped: resolving everything imports every service and every analysis module,
    # which is the ~2s / ~200MB bill this change exists to keep out of production
    return build_config()


@pytest.mark.unit
def test_every_service_config_resolves(resolved_config):
    configs = resolved_config.services

    assert configs
    for config in configs:
        assert isinstance(config, resolve_config_class(config)), \
            f"service config {config.name} did not validate as its declared config class"


@pytest.mark.unit
def test_every_analysis_module_config_resolves(resolved_config):
    configs = resolved_config.analysis_modules

    assert configs
    for config in configs:
        assert isinstance(config, resolve_config_class(config)), \
            f"analysis module config {config.name} did not validate as its declared config class"


@pytest.mark.unit
def test_every_observable_export_config_resolves(resolved_config):
    configs = resolved_config.observable_exports

    assert configs
    for config in configs:
        assert isinstance(config, resolve_config_class(config)), \
            f"observable export config {config.name} did not validate as its declared config class"


@pytest.mark.unit
def test_parsing_the_configuration_resolves_nothing():
    """Parsing the configuration must not resolve (and therefore must not import) any plugin."""
    config = build_config()
    registries = {
        "services": config._ACEConfig__services,
        "analysis modules": config._ACEConfig__analysis_modules,
        "observable exports": config._ACEConfig__observable_exports,
    }

    for label, registry in registries.items():
        assert len(registry) > 0, f"no {label} were loaded at all"
        assert [name for name in registry.names() if registry.is_resolved(name)] == [], \
            f"parsing the configuration resolved {label}"

    # resolving one service by name resolves that service and nothing else
    services = registries["services"]
    target = services.names()[0]
    services.get(target)

    assert [name for name in services.names() if services.is_resolved(name)] == [target]
    for label in ("analysis modules", "observable exports"):
        registry = registries[label]
        assert [name for name in registry.names() if registry.is_resolved(name)] == []


# Modules whose __init__ builds an authenticated client and therefore cannot be constructed without
# real credentials, which no dev or CI environment has. Excluded deliberately and by name: the point
# of the test below is to catch structural breakage (a missing integration config, a bad config key,
# an import-time error), not to assert that this machine holds production secrets. Add to this list
# only after confirming the failure really is a missing credential.
MODULES_REQUIRING_CREDENTIALS = {
    "splunk_api",                 # saq.modules.splunk.SplunkAPIAnalyzer
    "wiz_ip_address_analyzer",    # wiz.modules.lookup.WizIpAddressAnalyzer
}


@pytest.mark.unit
def test_every_enabled_analysis_module_constructs(resolved_config):
    """Every enabled analysis module must actually be constructible.

    test_every_analysis_module_config_resolves above covers the import and the class lookup --
    saq/modules/adapter.py:228 and :236. It stops one line short of :253, the constructor, which is
    the line guarded by the "unable to load analysis module" handler. Anything a module does in
    __init__ (read a config key, build a client, open a file) fails only in a worker, as a single
    ERROR line, with the module silently absent from the engine.

    CAVEAT: this test is only reliable when run on its own. tests/conftest.py::pytest_sessionstart
    puts every integration src/ on sys.path before collection, and the integration test modules
    import their packages at module scope -- so in a full-suite run those packages are already
    imported (and their register_integration_configuration() calls already made) before any test
    executes. That is exactly what hid the 3.0.101 vt_hash_downloader regression. The guard that
    does not depend on collection order is
    tests/saq/configuration/test_integration_config_resolution.py, which uses a synthetic
    integration registered inside the test body.
    """
    failures = []

    for config in resolved_config.analysis_modules:
        if not config.enabled or config.name in MODULES_REQUIRING_CREDENTIALS:
            continue

        try:
            module = importlib.import_module(config.python_module)
            getattr(module, config.python_class)(config)
        except Exception as e:
            failures.append(f"{config.name} ({config.python_module}.{config.python_class}): {e}")

    assert not failures, "enabled analysis modules failed to construct:\n" + "\n".join(failures)
