import base64
import os
import pytest

from saq.analysis.root import load_root
from saq.constants import F_COMMAND_LINE, F_FILE, F_FILE_PATH
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.command_line import CommandLineAnalysis, KEY_BASE64, KEY_FILE_PATH
from saq.util.uuid import get_storage_dir

@pytest.mark.integration
def test_command_line_analyzer(root_analysis):
    root_analysis.analysis_mode = "test_groups"

    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, "\"C:\\WINDOWS\\system32\\cmd.exe\" /c COPY \"\\\\some_domain.some_host.com\\Shares\\Database.lnk\" \"C:\\Users\\john\\Desktop\\Database.lnk\"")
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    assert command_line_observable
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert isinstance(analysis, CommandLineAnalysis)
    assert analysis.load_details()
    assert len(analysis.file_paths) == 3
    assert r'C:\WINDOWS\system32\cmd.exe' in analysis.file_paths
    assert r'C:\Users\john\Desktop\Database.lnk' in analysis.file_paths
    assert r'\\some_domain.some_host.com\Shares\Database.lnk' in analysis.file_paths

    assert analysis.find_observable(lambda o: o.type == F_FILE_PATH and o.value == r'C:\WINDOWS\system32\cmd.exe')
    assert analysis.find_observable(lambda o: o.type == F_FILE_PATH and o.value == r'C:\Users\john\Desktop\Database.lnk')
    assert analysis.find_observable(lambda o: o.type == F_FILE_PATH and o.value == r'\\some_domain.some_host.com\Shares\Database.lnk')


@pytest.mark.integration
def test_command_line_base64_extraction_powershell_encoded_command(root_analysis):
    """test that base64 encoded payloads in powershell -EncodedCommand are extracted and decoded"""
    root_analysis.analysis_mode = "test_groups"

    # create a base64 encoded command (powershell expects UTF-16LE encoded commands)
    original_command = "Write-Host 'Hello World'"
    encoded_command = base64.b64encode(original_command.encode('utf-16le')).decode('ascii')

    command_line = f"powershell.exe -EncodedCommand {encoded_command}"
    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    assert command_line_observable
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert isinstance(analysis, CommandLineAnalysis)
    assert analysis.load_details()

    # verify base64 payload was extracted
    assert len(analysis.base64_payloads) == 1
    payload = analysis.base64_payloads[0]
    assert payload[KEY_BASE64] == encoded_command
    assert os.path.exists(payload[KEY_FILE_PATH])

    # verify file observable was created and tagged
    file_observable = analysis.find_observable(lambda o: o.type == F_FILE and o.has_tag('base64'))
    assert file_observable

    # verify decoded content
    with open(payload[KEY_FILE_PATH], 'rb') as fp:
        decoded_content = fp.read()
        assert decoded_content == original_command.encode('utf-16le')


@pytest.mark.integration
def test_command_line_base64_extraction_with_short_flag(root_analysis):
    """test that base64 extraction works with powershell short -e flag"""
    root_analysis.analysis_mode = "test_groups"

    original_command = "Invoke-WebRequest http://malicious.com"
    encoded_command = base64.b64encode(original_command.encode('utf-16le')).decode('ascii')

    command_line = f"powershell.exe -e {encoded_command}"
    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    assert len(analysis.base64_payloads) == 1
    assert analysis.base64_payloads[0][KEY_BASE64] == encoded_command


@pytest.mark.integration
def test_command_line_base64_extraction_with_forward_slash_flag(root_analysis):
    """test that base64 extraction works with /EncodedCommand flag variant"""
    root_analysis.analysis_mode = "test_groups"

    original_command = "Get-Process"
    encoded_command = base64.b64encode(original_command.encode('utf-16le')).decode('ascii')

    command_line = f"powershell.exe /EncodedCommand {encoded_command}"
    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    assert len(analysis.base64_payloads) == 1


@pytest.mark.integration
def test_command_line_base64_minimum_length_respected(root_analysis):
    """test that base64 payloads below minimum length are ignored (unless after -e flag)"""
    root_analysis.analysis_mode = "test_groups"

    # create a short base64 string that would normally be ignored
    short_payload = base64.b64encode(b"short").decode('ascii')

    # command line with short base64 not following -EncodedCommand flag
    command_line = f"some_command {short_payload}"
    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    # short payload should be ignored
    assert len(analysis.base64_payloads) == 0


@pytest.mark.integration
def test_command_line_base64_minimum_length_ignored_with_encoded_flag(root_analysis):
    """test that minimum length restriction is bypassed for -EncodedCommand parameters"""
    root_analysis.analysis_mode = "test_groups"

    # create a short base64 string
    short_payload = base64.b64encode(b"short").decode('ascii')

    # when following -e flag, even short payloads should be extracted
    command_line = f"powershell.exe -e {short_payload}"
    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    # short payload should be extracted when after -e flag
    assert len(analysis.base64_payloads) == 1


@pytest.mark.integration
def test_command_line_base64_extraction_with_large_payload(root_analysis):
    """test extraction of large base64 payloads that exceed minimum length"""
    root_analysis.analysis_mode = "test_groups"

    # create a payload that exceeds the default minimum length of 128 bytes
    large_payload_data = b"A" * 200
    encoded_payload = base64.b64encode(large_payload_data).decode('ascii')

    command_line = f"cmd.exe /c echo {encoded_payload}"
    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    assert len(analysis.base64_payloads) == 1
    payload = analysis.base64_payloads[0]

    # verify the decoded content matches
    with open(payload[KEY_FILE_PATH], 'rb') as fp:
        decoded_content = fp.read()
        assert decoded_content == large_payload_data


@pytest.mark.integration
def test_command_line_base64_extraction_with_quoted_payload(root_analysis):
    """test that base64 payloads within quotes are properly extracted"""
    root_analysis.analysis_mode = "test_groups"

    original_command = "Get-ChildItem"
    encoded_command = base64.b64encode(original_command.encode('utf-16le')).decode('ascii')

    # wrap the base64 in quotes
    command_line = f"powershell.exe -EncodedCommand \"{encoded_command}\""
    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    assert len(analysis.base64_payloads) == 1
    assert analysis.base64_payloads[0][KEY_BASE64] == encoded_command


@pytest.mark.integration
def test_command_line_base64_extraction_multiple_payloads(root_analysis):
    """test extraction of multiple base64 payloads in a single command line"""
    root_analysis.analysis_mode = "test_groups"

    # create two separate large base64 payloads
    payload1_data = b"B" * 150
    payload2_data = b"C" * 160
    encoded_payload1 = base64.b64encode(payload1_data).decode('ascii')
    encoded_payload2 = base64.b64encode(payload2_data).decode('ascii')

    command_line = f"cmd.exe /c process {encoded_payload1} and {encoded_payload2}"
    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    # should have extracted both payloads
    assert len(analysis.base64_payloads) == 2

    # verify both payloads were decoded correctly
    decoded_contents = []
    for payload in analysis.base64_payloads:
        with open(payload[KEY_FILE_PATH], 'rb') as fp:
            decoded_contents.append(fp.read())

    assert payload1_data in decoded_contents
    assert payload2_data in decoded_contents


@pytest.mark.integration
def test_command_line_base64_unique_filenames(root_analysis):
    """test that each extracted base64 payload gets a unique filename"""
    root_analysis.analysis_mode = "test_groups"

    # create multiple payloads to ensure unique naming
    payloads = []
    for i in range(3):
        payload_data = f"payload_{i}".encode() * 20
        encoded = base64.b64encode(payload_data).decode('ascii')
        payloads.append(encoded)

    command_line = f"cmd.exe {' '.join(payloads)}"
    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    assert len(analysis.base64_payloads) == 3

    # verify all file paths are unique
    file_paths = [p[KEY_FILE_PATH] for p in analysis.base64_payloads]
    assert len(set(file_paths)) == 3

    # verify all files exist
    for file_path in file_paths:
        assert os.path.exists(file_path)


@pytest.mark.integration
def test_command_line_base64_observable_tagged(root_analysis):
    """test that file observables created from base64 payloads are tagged with 'base64'"""
    root_analysis.analysis_mode = "test_groups"

    payload_data = b"D" * 150
    encoded_payload = base64.b64encode(payload_data).decode('ascii')

    command_line = f"powershell.exe -e {encoded_payload}"
    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    # find the file observable and verify it has the 'base64' tag
    file_observable = analysis.find_observable(lambda o: o.type == F_FILE)
    assert file_observable
    assert file_observable.has_tag('base64')


@pytest.mark.integration
def test_command_line_analysis_summary_with_base64(root_analysis):
    """test that analysis summary includes base64 payload count"""
    root_analysis.analysis_mode = "test_groups"

    payload_data = b"E" * 150
    encoded_payload = base64.b64encode(payload_data).decode('ascii')

    command_line = f"powershell.exe -e {encoded_payload} C:\\Windows\\file.exe"
    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    summary = analysis.generate_summary()
    assert summary
    assert "1 file paths" in summary or "file paths" in summary
    assert "1 base64 payloads" in summary or "base64 payloads" in summary


@pytest.mark.integration
def test_command_line_analysis_summary_no_extraction(root_analysis):
    """test that analysis summary returns None when nothing is extracted"""
    root_analysis.analysis_mode = "test_groups"

    # command line with no file paths or base64
    command_line = "echo hello"
    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    summary = analysis.generate_summary()
    assert summary is None


@pytest.mark.integration
def test_command_line_combined_file_paths_and_base64(root_analysis):
    """test that both file paths and base64 payloads are extracted from the same command line"""
    root_analysis.analysis_mode = "test_groups"

    payload_data = b"F" * 150
    encoded_payload = base64.b64encode(payload_data).decode('ascii')

    command_line = f"powershell.exe -e {encoded_payload} -File C:\\Scripts\\test.ps1"
    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    # should have extracted both file path and base64 payload
    assert len(analysis.file_paths) >= 1
    assert len(analysis.base64_payloads) == 1
    assert r'C:\Scripts\test.ps1' in analysis.file_paths