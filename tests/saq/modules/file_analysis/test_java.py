
import logging
import os
import shutil

import pytest

from saq.analysis.root import load_root
from saq.constants import F_FILE
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.configuration.config import get_analysis_module_config, get_config
from saq.modules.file_analysis import java
from saq.modules.file_analysis.java import JavaClassDecompilerAnalysis, JavaClassDecompilerAnalysisModule, strip_banner
from saq.sandbox.runner import SandboxResult
from tests.saq.test_util import create_test_context
from saq.util.uuid import get_storage_dir


@pytest.mark.unit
def test_decompile_java_class_file(tmp_path, datadir):
    module = JavaClassDecompilerAnalysisModule(context=create_test_context(),
                                               config=get_analysis_module_config("java_class_decompiler"))
    class_file = str(datadir / 'VxUGJsAplRNavewkjKujp.class')
    assert os.path.exists(class_file)

    java_file = module.decompile_class_file(class_file)
    assert os.path.getsize(java_file) > 0

    with open(java_file) as fp:
        java_code = fp.read()
        assert 'HBrowserNativeApis.PygDMDiPgHIHFKYIMuHMd' in java_code
        # cfr's banner is cut
        assert 'Decompiled with CFR' not in java_code

    # if we do it a second time we'll get a different file name
    java_file_2 = module.decompile_class_file(class_file)
    assert os.path.exists(java_file_2)
    assert java_file_2 != java_file

    # if we pass a missing file we get None back
    assert module.decompile_class_file('does_not_exist.java') is None

    # if we pass something that is not a java class file we get None back
    not_class_file = tmp_path / 'not_a_class_file.class'
    not_class_file.write_text("This is not a class file.")
    not_class_file = str(not_class_file)

    assert module.decompile_class_file(not_class_file) is None


@pytest.mark.unit
def test_strip_banner():
    source = "/*\n * Decompiled with CFR 0.151.\n */\npublic class A {\n    /* a comment */\n}\n"
    assert strip_banner(source) == "public class A {\n    /* a comment */\n}\n"


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


def _decompiler():
    return JavaClassDecompilerAnalysisModule(context=create_test_context(),
                                             config=get_analysis_module_config("java_class_decompiler"))


@pytest.mark.unit
@pytest.mark.parametrize("cannot_start,error", [
    # too little address space for the heap it is told to reserve
    (lambda monkeypatch: monkeypatch.setattr(get_config().tool_sandbox, "memory_limit", 1024 ** 3),
     "Error occurred during initialization of VM"),
    # its java.security, under /etc/java-<version>-openjdk, is not readable
    (lambda monkeypatch: monkeypatch.setattr(java, "jvm_conf_dirs", lambda: []), "Error loading java.security file"),
], ids=["memory", "configuration"])
def test_a_jvm_the_sandbox_keeps_from_starting_is_reported(datadir, monkeypatch, caplog, cannot_start, error):
    cannot_start(monkeypatch)
    class_file = shutil.copy(datadir / 'VxUGJsAplRNavewkjKujp.class', datadir / 'copy.class')

    assert _decompiler().decompile_class_file(class_file) is None

    # the JVM's error is not the decompiled source
    assert not os.path.exists(f"{class_file}-0-decompiled.java")
    [record] = [r for r in caplog.records if "in the sandbox" in r.getMessage()]
    assert record.levelno == logging.ERROR
    assert record.exc_info
    assert error in record.getMessage()


@pytest.mark.unit
@pytest.mark.parametrize("result", [None, SandboxResult(1, "class Partial {", "Exception in thread \"main\"")],
                         ids=["stopped", "failed"])
def test_a_decompilation_that_does_not_finish_writes_nothing(datadir, monkeypatch, result):
    module = _decompiler()
    monkeypatch.setattr(module, "run_sandboxed_tool", lambda *args, **kwargs: result)
    class_file = str(datadir / 'VxUGJsAplRNavewkjKujp.class')

    assert module.decompile_class_file(class_file) is None
    assert not os.path.exists(f"{class_file}-0-decompiled.java")


@pytest.mark.unit
def test_a_jvm_configuration_that_cannot_be_found_is_logged(tmp_path, monkeypatch, caplog):
    # another JDK build or version, laid out differently
    monkeypatch.setattr(java.shutil, "which", lambda name: str(tmp_path / "bin" / "java"))

    assert java.jvm_conf_dirs() == []
    [record] = [r for r in caplog.records if "configuration" in r.getMessage()]
    assert record.levelno == logging.WARNING
