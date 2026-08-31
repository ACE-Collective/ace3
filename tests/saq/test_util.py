from datetime import timedelta
import json
import os
from typing import Optional
import pytest

from saq.analysis.adapter import RootAnalysisAdapter
from saq.analysis.root import RootAnalysis
from saq.configuration import get_config
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.engine_configuration import EngineConfiguration
from saq.filesystem.adapter import FileSystemAdapter
from saq.modules.context import AnalysisModuleContext
from saq.util.filesystem import extract_windows_filepaths, is_nt_path, map_mimetype_to_file_ext, safe_file_name
from saq.util.networking import fully_qualified
from saq.util.parsing import json_parse
from saq.util.time import create_timedelta
from saq.util.url import fang
from saq.util.hashing import sha256

@pytest.mark.unit
def test_sha256(datadir):
    assert sha256(datadir / 'data.txt') == '5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03'

@pytest.mark.unit
@pytest.mark.parametrize("mime_type,file_ext", [
    ("application/andrew-inset", "ez"), # single value
    ("application/heythere", "bin"), # unknown value
    ("application/inkml+xml", "ink"), # multiple values
    (None, "bin"), # invalid value
])
def test_map_mimetype_to_file_ext(mime_type, file_ext):
    assert map_mimetype_to_file_ext(mime_type) == file_ext

@pytest.mark.unit
def test_fully_qualified(monkeypatch):
    monkeypatch.setattr(get_config().global_settings, "local_domains", ["test"])

    assert fully_qualified(None) is None
    assert fully_qualified("host") == "host.test"
    assert fully_qualified("host.domain") == "host.domain"
    monkeypatch.setattr(get_config().global_settings, "local_domains", [])
    assert fully_qualified("host") == "host"

@pytest.mark.unit
def test_create_timedelta():
    assert create_timedelta('01') == timedelta(seconds=1)
    assert create_timedelta('01:00') == timedelta(minutes=1)
    assert create_timedelta('01:00:00') == timedelta(hours=1)
    assert create_timedelta('01:00:00:00') == timedelta(days=1)
    assert create_timedelta('07:00:00:00') == timedelta(days=7)

@pytest.mark.unit
def test_json_parse(tmpdir):
    json_value = { 'Hello': 'world' }

    # read a single JSON object out of a file
    temp_file = tmpdir / "data.json"
    with temp_file.open("w") as fp:
        json.dump(json_value, fp)

    file_size = os.path.getsize(temp_file)

    with temp_file.open() as fp:
        result = list(json_parse(fp))

    assert len(result) == 1
    result = result[0]
    assert result[0] == json_value
    assert result[1] == file_size

    # read two JSON objects out of a file
    json_value_1 = { 'Hello': 'world1' }
    json_value_2 = { 'Hello': 'world2' }
    with temp_file.open("w") as fp:
        json.dump(json_value_1, fp)
        position_1 = fp.tell()
        json.dump(json_value_2, fp)
        position_2 = fp.tell()

    file_size = os.path.getsize(temp_file)

    with temp_file.open() as fp:
        result = list(json_parse(fp))

    assert len(result) == 2
    assert result[0][0] == json_value_1
    assert result[0][1] == position_1
    assert result[1][0] == json_value_2
    assert result[1][1] == position_2

    # read two, write some more, then read another
    with temp_file.open("a") as fp_out:
        with temp_file.open() as fp_in:
            fp_out.flush()
            result = list(json_parse(fp_in))
            assert len(result) == 2
            json.dump({ 'Hello': 'world' }, fp_out)
            fp_out.flush()
            result = list(json_parse(fp_in))
            assert len(result) == 1

    # write one and then write the other one partially
    with temp_file.open("w") as fp_out:
        with temp_file.open() as fp_in:
            json.dump(json_value_1, fp_out)
            position_1 = fp_out.tell()

            data = json.dumps(json_value_2)
            d1 = data[:int(len(data) / 2)]
            d2 = data[len(d1):]
            assert d1 + d2 == data
            fp_out.write(d1)
            fp_out.flush()

            result = list(json_parse(fp_in))
            assert len(result) == 1
            result[0][0] == json_value_1
            result[0][1] == position_1

            fp_out.write(d2)
            position_2 = fp_out.tell()

    with temp_file.open() as fp_in:
        fp_in.seek(position_1)
        result = list(json_parse(fp_in))
        assert result[0][0] == json_value_2
        assert result[0][1] == position_2


@pytest.mark.parametrize("input, expected", [
    ('hxxp://local.local', 'http://local.local'),
    ('hXXp://local.local', 'http://local.local'),
    ('http://local.local', 'http://local.local'),
])
@pytest.mark.unit
def test_fang(input: str, expected: str):
    assert fang(input) == expected

@pytest.mark.parametrize("path, expected", [
    (r'C:\Users\john\test.txt', True),
    (r'\\server\some\path.txt', True),
    (r'/some/unix/path.txt', False),
    (r'file.txt', False),
    (r'C:\<Users\john\test.txt', False),
    (r'C:\>Users\john\test.txt', False),
    (r'C:\:Users\john\test.txt', False),
    (r'C:\"Users\john\test.txt', False),
    (r'C:\/Users\john\test.txt', False),
    (r'C:\|Users\john\test.txt', False),
    (r'C:\?Users\john\test.txt', False),
    (r'C:\*Users\john\test.txt', False),
])
@pytest.mark.unit
def test_is_nt_path(path: str, expected: bool):
    assert is_nt_path(path) == expected

@pytest.mark.parametrize("input, expected", [
    (r'test.txt', 'test.txt'),
    (r'../test.txt', '_test.txt'),
    (r'../../test.txt', '_test.txt'),
    (r'../../../test.txt', '_test.txt'),
    (r'\\../../test.txt', '_test.txt'),
    (r'\\.\\.\\/test.txt', '_._._test.txt'),
    (r'/some/path/test.txt', '_some_path_test.txt'),
    (r'//////test.txt', '_test.txt'),
    (r'~john/test', '_john_test'),
])
@pytest.mark.unit
def test_safe_file_name(input: str, expected: str):
    assert safe_file_name(input) ==  expected

@pytest.mark.parametrize("input, expected", [
        ("\"C:\\Windows\\SysWOW64\\mshta.exe\" \"\\\\hostname\\shares\\Applications\\EUPT\\Operations\\Shared_Services\\Item_Processing\\Databases\\Item Processing Database\\DB_FILES\\IP Database.hta\" ", [ 
            r'C:\Windows\SysWOW64\mshta.exe', r'\\hostname\shares\Applications\EUPT\Operations\Shared_Services\Item_Processing\Databases\Item Processing Database\DB_FILES\IP Database.hta' ])
])
@pytest.mark.unit
def test_extract_windows_filepaths(input: str, expected: str):
    extract_windows_filepaths(input) == expected

def create_test_context(root: Optional[RootAnalysis] = None, configuration_manager: Optional[ConfigurationManager] = None, shutdown_interface=None):
    from saq.modules.state_repository import StateRepositoryFactory
    root_analysis = root or RootAnalysis()
    return AnalysisModuleContext(
        delayed_analysis_interface=None,
        configuration_manager=configuration_manager or ConfigurationManager(config=EngineConfiguration()),
        root=RootAnalysisAdapter(root_analysis),
        filesystem=FileSystemAdapter(),
        state_repository=StateRepositoryFactory.create_root_analysis_repository(
            RootAnalysisAdapter(root_analysis)
        ),
        shutdown_interface=shutdown_interface,
    )