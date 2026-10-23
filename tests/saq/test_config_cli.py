import uuid

import pytest
import yaml

import saq.cli.commands  # noqa: F401
from saq.cli.cli_main import get_cli_parser
from saq.configuration import get_config
from saq.configuration.config import get_analysis_module_config
from saq.constants import F_TEST
from saq.database.util.delayed_analysis import add_delayed_analysis_request
from saq.database.util.locking import acquire_lock
from saq.environment import get_global_runtime_settings


def _run(*argv):
    args = get_cli_parser().parse_args(list(argv))
    try:
        return args.func(args)
    except SystemExit as e:
        return e.code


@pytest.mark.integration
def test_modules_list(capsys):
    get_analysis_module_config("basic_test").enabled = True
    get_analysis_module_config("generic_test").enabled = True

    assert _run("modules", "list") == 0

    # it used to raise AttributeError for the first module it listed
    modules = capsys.readouterr().out.splitlines()
    assert modules == sorted(modules)
    assert {"basic_test", "generic_test"} <= set(modules)


@pytest.mark.unit
def test_config_section_and_key(capsys):
    assert _run("config", "global.instance_type") == 0
    assert yaml.safe_load(capsys.readouterr().out) == {"global": {"instance_type": "UNITTEST"}}

    assert _run("config", "-v", "global.instance_type") == 0
    assert capsys.readouterr().out == "UNITTEST\n"

    # globs, and a whole section
    assert _run("config", "analysis_module_basic_*.python_class") == 0
    assert yaml.safe_load(capsys.readouterr().out) == {"analysis_module_basic_test": {"python_class": "BasicTestAnalyzer"}}
    assert _run("config", "analysis_module_basic_test") == 0
    assert yaml.safe_load(capsys.readouterr().out)["analysis_module_basic_test"]["name"] == "basic_test"


@pytest.mark.unit
def test_config_value_of_a_list_setting(capsys):
    # a top level list used to raise AttributeError with -v
    assert _run("config", "-v", "disabled_modules") == 0
    assert capsys.readouterr().out == f"{get_config().raw._data['disabled_modules']}\n"

    assert _run("config", "disabled_modules") == 0
    assert yaml.safe_load(capsys.readouterr().out) == {"disabled_modules": get_config().raw._data["disabled_modules"]}


@pytest.mark.unit
def test_config_everything(capsys):
    assert _run("config") == 0
    assert set(yaml.safe_load(capsys.readouterr().out)) == set(get_config().raw._data)


@pytest.mark.unit
def test_config_global_environment(capsys):
    settings = get_global_runtime_settings()

    assert _run("config", "-g", "data_dir") == 0
    assert capsys.readouterr().out == f"data_dir = {settings.data_dir}\n"
    assert _run("config", "-g", "-v", "data_dir") == 0
    assert capsys.readouterr().out == f"{settings.data_dir}\n"
    assert _run("config", "-g") == 0
    assert capsys.readouterr().out == f"{settings}\n"


@pytest.mark.integration
def test_workload_display(root_analysis, capsys):
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_TEST, "test_1")
    root_analysis.save()
    root_analysis.schedule()

    class _Module:
        name = "basic_test"

    assert add_delayed_analysis_request(root_analysis, observable, _Module(), 1, 0, 0)
    lock_uuid = str(uuid.uuid4())
    assert acquire_lock(root_analysis.uuid, lock_uuid, f"{get_global_runtime_settings().saq_node}-1234")

    assert _run("workload", "display") == 0

    lines = capsys.readouterr().out.splitlines()
    assert ["test_groups", "1"] in [line.split() for line in lines]
    # the module name used to lose its first 16 characters
    assert [root_analysis.uuid, "basic_test", "1"] in [line.split() for line in lines]
    assert any(line.startswith(f"{root_analysis.uuid} {lock_uuid}") for line in lines)
