"""An integration_<name>: block's enabled: false turns its integration off in the merged
configuration (saq/configuration/loader.py)."""

import yaml

import pytest

from saq.configuration.loader import load_configuration
from saq.configuration.schema import ACEConfig
from saq.environment import get_global_runtime_settings

pytestmark = pytest.mark.unit


@pytest.fixture
def integration(tmp_path, monkeypatch):
    """Writes an integration's etc/saq.integration.yaml and registers it the way load_integrations()
    does. Returns a function (name, body) -> the path of that file."""
    monkeypatch.setattr(get_global_runtime_settings(), "integration_config_paths", [])
    monkeypatch.delenv("SAQ_CONFIG_PATHS", raising=False)

    def create(name: str, body: str) -> str:
        etc = tmp_path / "integrations" / name / "etc"
        etc.mkdir(parents=True)
        path = etc / "saq.integration.yaml"
        path.write_text(body)
        get_global_runtime_settings().integration_config_paths.append(str(path))
        return str(path)

    return create


def _block(name: str, enabled: bool) -> str:
    return (f"integration_{name}:\n  name: {name}\n  enabled: {str(enabled).lower()}\n"
            f"  description: {name}\n  python_module: {name}\n")


def _module(name: str) -> str:
    return (f"analysis_module_{name}:\n  name: {name}\n  python_module: {name}.module\n"
            f"  python_class: Analyzer\n  enabled: true\n")


def _overlay(tmp_path, monkeypatch, body: str) -> None:
    path = tmp_path / "site.yaml"
    path.write_text(body)
    monkeypatch.setenv("SAQ_CONFIG_PATHS", str(path))


def test_a_disabled_integration_merges_only_its_block(integration):
    on = integration("switched_on", _block("switched_on", True) + _module("switched_on_module"))
    off = integration("switched_off", _block("switched_off", False) + _module("switched_off_module"))

    config = load_configuration(config_paths=[])

    assert "analysis_module_switched_on_module" in config._data
    assert "analysis_module_switched_off_module" not in config._data
    assert config._data["integration_switched_off"]["enabled"] is False
    assert config.disabled_integration_paths == {off}
    assert config.integration_blocks == {on: ["integration_switched_on"], off: ["integration_switched_off"]}


def test_what_a_disabled_integration_appends_is_left_out(integration):
    # lists append, so only merging again without the file takes its entries back out
    integration("switched_on", _block("switched_on", True) + "alert_routers:\n  - name: from_on\n")
    integration("switched_off", _block("switched_off", False) + "alert_routers:\n  - name: from_off\n")

    routers = [router["name"] for router in load_configuration(config_paths=[])._data["alert_routers"]]

    assert "from_on" in routers
    assert "from_off" not in routers


def test_a_later_file_disables_an_integration(integration, tmp_path, monkeypatch):
    path = integration("vendor", _block("vendor", True) + _module("vendor_module"))
    _overlay(tmp_path, monkeypatch, "integration_vendor:\n  enabled: false\n")

    config = load_configuration(config_paths=[])

    assert "analysis_module_vendor_module" not in config._data
    assert config.disabled_integration_paths == {path}
    # the later file still wins on the block
    assert config._data["integration_vendor"]["enabled"] is False


def test_a_later_file_enables_an_integration(integration, tmp_path, monkeypatch):
    integration("vendor", _block("vendor", False) + _module("vendor_module"))
    _overlay(tmp_path, monkeypatch, "integration_vendor:\n  enabled: true\n")

    config = load_configuration(config_paths=[])

    assert "analysis_module_vendor_module" in config._data
    assert config.disabled_integration_paths == set()


def test_an_environment_reference_disables_an_integration(integration, tmp_path, monkeypatch):
    integration("vendor", _block("vendor", True).replace("enabled: true", "enabled: env:VENDOR_ENABLED")
                + _module("vendor_module"))
    monkeypatch.setenv("VENDOR_ENABLED", "false")

    assert "analysis_module_vendor_module" not in load_configuration(config_paths=[])._data


def test_the_files_a_disabled_integration_includes_are_left_out(integration, tmp_path):
    included = tmp_path / "modules.yaml"
    included.write_text(_module("included_module") + _block("second", False))
    path = integration("vendor", f"config:\n  modules: {included}\n" + _block("vendor", False))

    config = load_configuration(config_paths=[])

    assert "analysis_module_included_module" not in config._data
    # a block in an included file belongs to the integration too, and is kept
    assert config._data["integration_second"]["enabled"] is False
    assert config.integration_blocks[path] == ["integration_second", "integration_vendor"]


@pytest.mark.parametrize("second_enabled, merged", [(True, True), (False, False)])
def test_an_integration_with_two_blocks_is_off_only_when_both_are(integration, second_enabled, merged):
    path = integration("vendor", _block("first", False) + _block("second", second_enabled) + _module("vendor_module"))

    config = load_configuration(config_paths=[])

    assert ("analysis_module_vendor_module" in config._data) is merged
    assert (path in config.disabled_integration_paths) is not merged


def test_an_integration_without_a_block_stays_on(integration):
    path = integration("undeclared", _module("undeclared_module"))

    config = load_configuration(config_paths=[])

    assert "analysis_module_undeclared_module" in config._data
    assert config.integration_blocks[path] == []
    assert config.disabled_integration_paths == set()


def test_each_file_is_parsed_once(integration, monkeypatch):
    integration("switched_off", _block("switched_off", False) + _module("switched_off_module"))
    parsed = []
    real_load = yaml.load

    def counting_load(stream, Loader):
        parsed.append(stream.name)
        return real_load(stream, Loader=Loader)

    monkeypatch.setattr(yaml, "load", counting_load)

    load_configuration(config_paths=[])

    assert parsed
    assert len(parsed) == len(set(parsed))


def test_an_integration_named_twice_is_found_once(integration):
    path = integration("switched_off", _block("switched_off", False) + _module("switched_off_module"))
    get_global_runtime_settings().integration_config_paths.append(path)

    config = load_configuration()

    assert "analysis_module_switched_off_module" not in config._data
    assert config.integration_blocks == {path: ["integration_switched_off"]}


@pytest.mark.parametrize("section", ["integration_vendor: not-a-mapping\n",
                                     "integration_vendor:\n  enabled: maybe\n"])
def test_an_invalid_section_counts_as_enabled(integration, section):
    # IntegrationConfig validation reports it, with the error it would give anyway
    integration("vendor", section + _module("vendor_module"))

    config = load_configuration(config_paths=[])

    assert "analysis_module_vendor_module" in config._data
    assert config.disabled_integration_paths == set()


def test_a_copy_keeps_what_the_loader_found(integration):
    path = integration("switched_off", _block("switched_off", False))
    config = load_configuration(config_paths=[])

    copied = config.copy()

    assert copied.integration_blocks == {path: ["integration_switched_off"]}
    assert copied.disabled_integration_paths == {path}
    assert copied.disabled_integration_keys == config.disabled_integration_keys
    assert copied.first_declared_by == config.first_declared_by
    copied.disabled_integration_paths.clear()
    assert config.disabled_integration_paths == {path}


def _service(name: str) -> str:
    return (f"service_{name}:\n  name: {name}\n  python_module: {name}.service\n"
            f"  python_class: Service\n  description: {name}\n  enabled: false\n")


def test_what_a_later_file_sets_on_a_disabled_integrations_block_is_left_out(integration, tmp_path, monkeypatch):
    path = integration("vendor", _block("vendor", True) + _service("vendor_collector")
                       + "module_group_vendor:\n  name: vendor\n  modules:\n    - vendor_module\n")
    # what docs/INTEGRATIONS.md tells a site to do, in a file that also configures the integration
    _overlay(tmp_path, monkeypatch, "integration_vendor:\n  enabled: false\n"
             "service_vendor_collector:\n  enabled: true\nmodule_group_vendor:\n  modules:\n    - site_module\n")

    raw = load_configuration(config_paths=[])

    assert "service_vendor_collector" not in raw._data
    assert "module_group_vendor" not in raw._data
    assert raw.disabled_integration_keys == {"service_vendor_collector", "module_group_vendor"}
    assert raw.disabled_integration_paths == {path}
    # the fragment would fail ServiceConfig validation and stop every process
    config = ACEConfig.model_validate(raw._data)
    config.raw = raw
    assert "vendor_collector" not in [service.name for service in config.services]


def test_a_block_a_disabled_integration_did_not_declare_first_is_kept(integration, tmp_path, monkeypatch):
    # the default configuration declares observable_types and alert_routers first
    integration("vendor", _block("vendor", False) + "alert_routers:\n  - name: from_vendor\n")
    _overlay(tmp_path, monkeypatch, "alert_routers:\n  - name: from_site\n")

    raw = load_configuration(config_paths=[])

    assert "from_site" in [router["name"] for router in raw._data["alert_routers"]]
    assert "from_vendor" not in [router["name"] for router in raw._data["alert_routers"]]
    assert "alert_routers" not in raw.disabled_integration_keys


def test_a_block_an_enabled_integration_also_declares_is_kept(integration):
    integration("switched_off", _block("switched_off", False) + _service("shared"))
    integration("switched_on", _block("switched_on", True) + _service("shared"))

    raw = load_configuration(config_paths=[])

    assert raw._data["service_shared"]["name"] == "shared"
    assert raw.disabled_integration_keys == set()


def test_a_disabled_integration_keeps_its_observable_classes(integration, tmp_path):
    # its src/ stays on sys.path so that saved alerts load, and their observables need the class
    included = tmp_path / "observables.yaml"
    included.write_text("observable_types:\n  classes:\n    vendor_other: \"vendor.observables:Other\"\n")
    integration("vendor", f"config:\n  observables: {included}\n" + _block("vendor", False)
                + "observable_types:\n  config_path: vendor.yaml\n"
                + "  classes:\n    vendor_thing: \"vendor.observables:Thing\"\n")

    raw = load_configuration(config_paths=[])

    classes = raw._data["observable_types"]["classes"]
    assert classes["vendor_thing"] == "vendor.observables:Thing"
    assert classes["vendor_other"] == "vendor.observables:Other"
    # only the class map: the rest of the block is the integration's configuration
    assert raw._data["observable_types"]["config_path"] != "vendor.yaml"
