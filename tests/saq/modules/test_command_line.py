import pytest

from saq.analysis.root import load_root
from saq.constants import F_COMMAND_LINE, F_FILE_PATH
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.command_line import CommandLineAnalysis
    
@pytest.mark.integration
def test_command_line_analyzer(root_analysis):
    root_analysis.analysis_mode = "test_groups"

    command_line_observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, "\"C:\\WINDOWS\\system32\\cmd.exe\" /c COPY \"\\\\some_domain.some_host.com\\Shares\\Database.lnk\" \"C:\\Users\\john\\Desktop\\Database.lnk\"")
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(root_analysis.storage_dir)
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