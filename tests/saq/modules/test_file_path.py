import pytest

from saq.analysis.root import load_root
from saq.configuration.config import get_config
from saq.constants import (
    ANALYSIS_MODULE_FILE_LOCATION_ANALYSIS,
    ANALYSIS_MODULE_FILE_PATH_ANALYSIS,
    F_FILE_LOCATION,
    F_FILE_NAME,
    F_FILE_PATH,
    F_HOSTNAME,
    F_USER,
)
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.file_path import FileLocationAnalysis, FilePathAnalysis
from saq.util.uuid import get_storage_dir


def _analyze(root_analysis, path):
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_FILE_PATH, path)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("file_path_analysis", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    return root_analysis.get_observable(observable.uuid).get_and_load_analysis(FilePathAnalysis)


def _values(analysis, observable_type):
    return [o.value for o in analysis.get_observables_by_type(observable_type)]


@pytest.mark.parametrize("path, file_name, user_name", [
    (r"C:\Users\bob\AppData\Local\Temp\invoice.exe", "invoice.exe", "bob"),
    (r"c:\users\Alice Smith\Downloads\scan.pdf.js", "scan.pdf.js", "Alice Smith"),
    (r"C:\Windows\System32\rundll32.exe", "rundll32.exe", None),
    ("/home/bob/.config/autostart/updater.desktop", "updater.desktop", None),
    # the user name is only taken from the start of the path
    (r"D:\backup\C:\Users\carol\notes.txt", "notes.txt", None),
])
@pytest.mark.integration
def test_file_name_and_user_name(root_analysis, path, file_name, user_name):
    analysis = _analyze(root_analysis, path)

    assert isinstance(analysis, FilePathAnalysis)
    assert analysis.file_name == file_name
    assert _values(analysis, F_FILE_NAME) == [file_name]
    assert analysis.user_name == user_name
    assert _values(analysis, F_USER) == ([user_name] if user_name else [])

    summary = analysis.generate_summary()
    assert summary.startswith(f"File Path Analysis: file name {file_name}")
    assert (f"user name {user_name}" in summary) is bool(user_name)


@pytest.mark.integration
def test_directory_path_has_no_file_name(root_analysis):
    analysis = _analyze(root_analysis, "C:\\Users\\bob\\Desktop\\")

    assert isinstance(analysis, FilePathAnalysis)
    assert analysis.file_name is None
    assert _values(analysis, F_FILE_NAME) == []
    assert analysis.user_name == "bob"
    assert analysis.generate_summary() == "File Path Analysis: user name bob"


@pytest.mark.integration
def test_a_bare_file_name_is_not_analyzed(root_analysis):
    assert _analyze(root_analysis, "invoice.exe") is False


@pytest.mark.unit
def test_summary_without_anything_extracted():
    assert FilePathAnalysis().generate_summary() is None


def _analyze_file_location(root_analysis, file_location, *module_names):
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_FILE_LOCATION, file_location)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    for module_name in module_names:
        engine.configuration_manager.enable_module(module_name, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    return root_analysis.get_observable(observable.uuid).get_and_load_analysis(FileLocationAnalysis)


@pytest.mark.parametrize("file_location, hostname, file_path", [
    (r"ws-1234@C:\Users\bob\Downloads\setup.msi", "ws-1234", r"C:\Users\bob\Downloads\setup.msi"),
    ("web01.example.com@/var/tmp/payload.sh", "web01.example.com", "/var/tmp/payload.sh"),
    # only the first @ separates the hostname from the path
    ("web01@/home/bob/backup@2026/notes.txt", "web01", "/home/bob/backup@2026/notes.txt"),
])
@pytest.mark.integration
def test_file_location_adds_hostname_and_file_path(root_analysis, file_location, hostname, file_path):
    analysis = _analyze_file_location(root_analysis, file_location, ANALYSIS_MODULE_FILE_LOCATION_ANALYSIS)

    assert isinstance(analysis, FileLocationAnalysis)
    assert analysis.hostname == hostname
    assert analysis.file_path == file_path
    assert _values(analysis, F_HOSTNAME) == [hostname]
    assert _values(analysis, F_FILE_PATH) == [file_path]
    assert analysis.generate_summary() == f"File Location Analysis: hostname {hostname} file path {file_path}"


@pytest.mark.integration
def test_file_location_path_is_analyzed_as_a_file_path(root_analysis):
    analysis = _analyze_file_location(
        root_analysis,
        r"ws-1234@C:\Users\bob\Downloads\setup.msi",
        ANALYSIS_MODULE_FILE_LOCATION_ANALYSIS,
        ANALYSIS_MODULE_FILE_PATH_ANALYSIS,
    )

    file_path = analysis.get_observable_by_type(F_FILE_PATH)
    file_path_analysis = file_path.get_and_load_analysis(FilePathAnalysis)
    assert isinstance(file_path_analysis, FilePathAnalysis)
    assert _values(file_path_analysis, F_FILE_NAME) == ["setup.msi"]
    assert _values(file_path_analysis, F_USER) == ["bob"]


@pytest.mark.unit
def test_file_location_summary_without_anything_extracted():
    assert FileLocationAnalysis().generate_summary() is None


@pytest.mark.unit
def test_file_location_analysis_runs_wherever_file_path_analysis_does():
    modules = get_config().get_module_group_config("file").modules
    assert ANALYSIS_MODULE_FILE_LOCATION_ANALYSIS in modules
    assert ANALYSIS_MODULE_FILE_PATH_ANALYSIS in modules
