"""Forces full resolution of every plugin config block in etc/saq.default.yaml.

Service, analysis module and observable export configs are resolved lazily (see
saq/configuration/lazy_registry.py) so that an `ace` process only imports the plugins it
actually uses. That means a bad module-specific config key no longer fails at startup for
every command -- it fails the first time that block is used. These tests put the eager
check back where it belongs: in CI, once, instead of in every process, every time.
"""

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
