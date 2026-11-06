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
    engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
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
def test_command_line_analyzer_powershell_command_with_escaped_quotes(root_analysis):
    """test that file paths embedded in PowerShell -Command script bodies with escaped quotes are extracted"""
    root_analysis.analysis_mode = "test_groups"

    command_line_value = r'powershell.exe -Command "$jarFilePath = \"C:\Program Files (x86)\Hive Streaming\application\lib\log4j-core-2.20.0.jar\"; Copy-Item $jarFilePath -Destination \"C:\Temp\output\""'
    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line_value)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    assert command_line_observable
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert isinstance(analysis, CommandLineAnalysis)
    assert analysis.load_details()
    assert r'C:\Program Files (x86)\Hive Streaming\application\lib\log4j-core-2.20.0.jar' in analysis.file_paths
    assert r'C:\Temp\output' in analysis.file_paths
    # C:\Program should NOT be extracted — it is a prefix substring of the full path
    assert r'C:\Program' not in analysis.file_paths
    assert len(analysis.file_paths) == 2

    assert analysis.find_observable(lambda o: o.type == F_FILE_PATH and o.value == r'C:\Program Files (x86)\Hive Streaming\application\lib\log4j-core-2.20.0.jar')
    assert analysis.find_observable(lambda o: o.type == F_FILE_PATH and o.value == r'C:\Temp\output')
    assert not analysis.find_observable(lambda o: o.type == F_FILE_PATH and o.value == r'C:\Program')


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
    engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
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
    engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
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
    engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
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
    engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    # short payload should be ignored
    assert len(analysis.base64_payloads) == 0


@pytest.mark.integration
@pytest.mark.parametrize("flag", [
    "-e", "-ec", "-enc", "-EncodedCommand", "/EncodedCommand",
    # powershell also takes a double dash and the en dash, em dash and horizontal bar
    "--EncodedCommand", "\u2013enc", "\u2014e", "\u2015ec",
])
def test_command_line_base64_minimum_length_ignored_with_encoded_flag(root_analysis, flag):
    """test that minimum length restriction is bypassed for -EncodedCommand and its abbreviations"""
    root_analysis.analysis_mode = "test_groups"

    # create a short base64 string
    short_payload = base64.b64encode(b"short").decode('ascii')

    # when following the encoded command flag, even short payloads should be extracted
    command_line = f"powershell.exe {flag} {short_payload}"
    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    # short payload should be extracted when after -e flag
    assert len(analysis.base64_payloads) == 1


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
    engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
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
    engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
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
    engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    # the path after the payload is extracted too
    assert analysis.file_paths == [r'C:\Windows\file.exe']
    assert len(analysis.base64_payloads) == 1

    summary = analysis.generate_summary()
    assert "1 file paths" in summary
    assert "1 base64 payloads" in summary


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
    engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    summary = analysis.generate_summary()
    assert summary is None


@pytest.mark.integration
def test_command_line_base64_extraction_nested_in_command_body(root_analysis):
    """a payload inside a quoted -Command script body is part of a larger shlex token and must still be found"""
    root_analysis.analysis_mode = "test_groups"

    original_command = "Start-Process 'C:\\Temp\\example\\report.pbip'; $exitCode = $?; Out-File -LiteralPath 'C:\\Temp\\example.log'"
    encoded_command = base64.b64encode(original_command.encode('utf-16le')).decode('ascii')

    command_line = (
        '"pwsh.exe" -NoProfile -Command "$p = Start-Process -PassThru -FilePath \'pwsh.exe\' '
        f'-ArgumentList \'-NoProfile -NonInteractive -EncodedCommand {encoded_command}\' -WindowStyle Hidden; '
        '$p.WaitForExit()"'
    )
    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    assert len(analysis.base64_payloads) == 1
    payload = analysis.base64_payloads[0]
    assert payload[KEY_BASE64] == encoded_command
    with open(payload[KEY_FILE_PATH], 'rb') as fp:
        assert fp.read() == original_command.encode('utf-16le')

    file_observable = analysis.find_observable(lambda o: o.type == F_FILE and o.has_tag('base64'))
    assert file_observable


@pytest.mark.integration
def test_command_line_base64_undecodable_run_in_command_body_skipped(root_analysis):
    """a long run of base64 characters that does not decode is skipped and the payloads after it are still found"""
    root_analysis.analysis_mode = "test_groups"

    # 173 data characters is one more than a multiple of 4, which no padding makes decodable
    undecodable = "A" * 172 + "-"
    payload_data = b"G" * 150
    encoded_payload = base64.b64encode(payload_data).decode('ascii')
    command_line = f'powershell.exe -Command "Write-Output \'{undecodable}\'; Write-Output \'{encoded_payload}\'"'
    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    assert len(analysis.base64_payloads) == 1
    payload = analysis.base64_payloads[0]
    assert payload[KEY_BASE64] == encoded_payload
    with open(payload[KEY_FILE_PATH], 'rb') as fp:
        assert fp.read() == payload_data


@pytest.mark.integration
@pytest.mark.parametrize("command_line", [
    "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\test.ps1",
    "powershell.exe -ex RemoteSigned -File C:\\Scripts\\test.ps1",
    "pwsh.exe -ErrorAction Stop -File C:\\Scripts\\test.ps1",
    # a bare dash is an empty flag name, which every name starts with
    "powershell.exe - Bypass -File C:\\Scripts\\test.ps1",
])
def test_command_line_base64_minimum_length_kept_after_other_e_flags(root_analysis, command_line):
    """a flag that only starts with e (-ExecutionPolicy) does not lift the size limit on the word after it"""
    root_analysis.analysis_mode = "test_groups"

    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    assert analysis.base64_payloads == []
    assert r'C:\Scripts\test.ps1' in analysis.file_paths


@pytest.mark.integration
@pytest.mark.parametrize("command_line", [
    "docker run -e KEY=value nginx",
    "sed -e s/foo/bar/ input.txt",
    "xcopy /e /i dist out",
])
def test_command_line_base64_minimum_length_kept_after_e_flag_of_other_programs(root_analysis, command_line):
    """-e and /e lift the size limit only for powershell, where they abbreviate -EncodedCommand"""
    root_analysis.analysis_mode = "test_groups"

    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, command_line)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    assert analysis.base64_payloads == []


@pytest.mark.integration
@pytest.mark.parametrize("program", [
    "cmd.exe /c powershell",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe",
    "\"C:\\Program Files\\PowerShell\\7\\pwsh.exe\"",
    "/usr/bin/pwsh",
])
def test_command_line_base64_minimum_length_ignored_with_encoded_flag_of_powershell(root_analysis, program):
    """every way a command line names powershell lets -e lift the size limit"""
    root_analysis.analysis_mode = "test_groups"

    short_payload = base64.b64encode(b"short").decode('ascii')
    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, f"{program} -e {short_payload}")
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    command_line_observable = root_analysis.get_observable(command_line_observable.uuid)
    analysis = command_line_observable.get_and_load_analysis(CommandLineAnalysis)
    assert analysis.load_details()

    assert [payload[KEY_BASE64] for payload in analysis.base64_payloads] == [short_payload]
