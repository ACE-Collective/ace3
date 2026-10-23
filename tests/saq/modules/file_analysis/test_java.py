
import os
import pytest

from saq.analysis.root import load_root
from saq.constants import F_FILE
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.file_analysis.java import JavaClassDecompilerAnalysis, decompile_java_class_file
from saq.util.uuid import get_storage_dir


@pytest.mark.unit
def test_decompile_java_class_file(tmp_path, datadir):
    class_file = str(datadir / 'VxUGJsAplRNavewkjKujp.class')
    assert os.path.exists(class_file)

    java_file = decompile_java_class_file(class_file)
    assert os.path.getsize(java_file) > 0

    with open(java_file) as fp:
        java_code = fp.read()
        assert 'HBrowserNativeApis.PygDMDiPgHIHFKYIMuHMd' in java_code

    # if we do it a second time we'll get a different file name
    java_file_2 = decompile_java_class_file(class_file)
    assert os.path.exists(java_file_2)
    assert java_file_2 != java_file

    # if we pass a missing file we get None back
    assert decompile_java_class_file('does_not_exist.java') is None

    # if we pass something that is not a java class file we get None back
    not_class_file = tmp_path / 'not_a_class_file.class'
    not_class_file.write_text("This is not a class file.")
    not_class_file = str(not_class_file)

    assert decompile_java_class_file(not_class_file) is None

def _analyze_with_decompiler(root_analysis, path):
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_file_observable(str(path))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("java_class_decompiler", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    return root_analysis.get_observable(observable.uuid).get_and_load_analysis(JavaClassDecompilerAnalysis)


@pytest.mark.integration
def test_decompiler_adds_the_decompiled_source(root_analysis, datadir):
    analysis = _analyze_with_decompiler(root_analysis, datadir / 'VxUGJsAplRNavewkjKujp.class')

    assert isinstance(analysis, JavaClassDecompilerAnalysis)
    assert analysis.display_name == "Java Class Decompiler"
    assert len(analysis.decompiled_files) == 1

    decompiled = analysis.get_observables_by_type(F_FILE)
    assert len(decompiled) == 1
    assert decompiled[0].file_name == 'VxUGJsAplRNavewkjKujp.class-0-decompiled.java'
    assert decompiled[0].has_tag("decompiled")
    assert "type=script.java.decompiled" in decompiled[0].yara_meta_tags
    with open(decompiled[0].full_path) as fp:
        assert 'HBrowserNativeApis.PygDMDiPgHIHFKYIMuHMd' in fp.read()


@pytest.mark.integration
def test_decompiler_keeps_an_empty_analysis_when_decompiling_fails(root_analysis, tmp_path):
    # the class file magic, then nothing a decompiler can read
    broken = tmp_path / 'broken.class'
    broken.write_bytes(b'\xCA\xFE\xBA\xBE' + b'\x00' * 16)

    analysis = _analyze_with_decompiler(root_analysis, broken)

    assert isinstance(analysis, JavaClassDecompilerAnalysis)
    assert analysis.decompiled_files == []
    assert analysis.get_observables_by_type(F_FILE) == []


@pytest.mark.parametrize("content", [b'', b'not a class file'])
@pytest.mark.integration
def test_decompiler_skips_other_files(root_analysis, tmp_path, content):
    path = tmp_path / 'other.class'
    path.write_bytes(content)

    assert _analyze_with_decompiler(root_analysis, path) is False
