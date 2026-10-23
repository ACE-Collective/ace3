import os
from pathlib import Path

import pytest

from saq.analysis.root import load_root
from saq.configuration.config import get_analysis_module_config
from saq.constants import DIRECTIVE_SANDBOX, F_FILE
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.environment import get_data_dir
from saq.modules.file_analysis.mse import MicrosoftScriptEncodingAnalysis
from saq.util.uuid import get_storage_dir

MODULE = "microsoft_script_encoding_analysis"
ENCODED = b"#@~^CAAAAA==C^+m4Ix~~CgMAAA==^#~@"


def _analyze(root_analysis, path: Path):
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(path))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module(MODULE, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root_analysis.uuid))
    return root.get_observable(file_observable.uuid)


@pytest.fixture
def decoder():
    """A stand-in for bin/jscript.decode.pl: prints what it would decode to."""
    def _decoder(output: str, stderr: str = ""):
        # /tmp is mounted noexec
        script = Path(get_data_dir()) / "decode.sh"
        script.write_text(f"#!/bin/sh\nprintf '%s' '{output}'\nprintf '%s' '{stderr}' >&2\n")
        script.chmod(0o755)
        get_analysis_module_config(MODULE).decryption_program = str(script)
    return _decoder


@pytest.mark.integration
@pytest.mark.parametrize("name, decoded_name", [
    ("script.vbe", "script.vbe.decrypted.vbs"),
    ("script.jse", "script.jse.decrypted.js"),
    ("script.bin", "script.bin.decrypted"),
])
def test_decodes_encoded_script(root_analysis, tmp_path, decoder, name, decoded_name):
    decoder('WScript.Echo "decoded"')
    path = tmp_path / name
    path.write_bytes(ENCODED)

    target = _analyze(root_analysis, path)

    assert target.has_tag("microsoft_script_encoding")
    assert target.has_directive(DIRECTIVE_SANDBOX)
    analysis = target.get_and_load_analysis(MicrosoftScriptEncodingAnalysis)
    [decoded] = [o for o in analysis.observables if o.type == F_FILE]
    assert decoded.file_name == decoded_name
    assert decoded.redirection.uuid == target.uuid
    assert analysis.analysis_output == decoded.file_path
    with open(decoded.full_path) as fp:
        assert fp.read() == 'WScript.Echo "decoded"'


@pytest.mark.integration
def test_decoder_output_nothing(root_analysis, tmp_path, decoder):
    decoder("", stderr="bad input")
    path = tmp_path / "script.vbe"
    path.write_bytes(ENCODED)

    target = _analyze(root_analysis, path)

    analysis = target.get_and_load_analysis(MicrosoftScriptEncodingAnalysis)
    # still flagged for the sandbox, with nothing decoded
    assert target.has_directive(DIRECTIVE_SANDBOX)
    assert analysis.analysis_output is None
    with open(f"{target.full_path}.decrypted.stderr") as fp:
        assert fp.read() == "bad input"


@pytest.mark.integration
def test_decoded_file_not_added(root_analysis, tmp_path, decoder, monkeypatch, caplog):
    decoder("decoded")
    # e.g. the root is at its file observable limit
    monkeypatch.setattr("saq.modules.file_analysis.mse.MicrosoftScriptEncodingAnalysis.add_file_observable", lambda self, *a, **kw: None)
    path = tmp_path / "script.vbe"
    path.write_bytes(ENCODED)

    target = _analyze(root_analysis, path)

    assert target.get_and_load_analysis(MicrosoftScriptEncodingAnalysis).analysis_output is None
    assert not [r for r in caplog.records if "MicrosoftScriptEncodingAnalyzer) failed on" in r.getMessage()]


@pytest.mark.integration
@pytest.mark.parametrize("content", [b"WScript.Echo 1", b""])
def test_not_encoded(root_analysis, tmp_path, content):
    path = tmp_path / "script.vbs"
    path.write_bytes(content)

    target = _analyze(root_analysis, path)

    assert not target.get_and_load_analysis(MicrosoftScriptEncodingAnalysis)
    assert not os.path.exists(f"{target.full_path}.decrypted")


@pytest.mark.integration
def test_real_decoder(root_analysis, tmp_path):
    """bin/jscript.decode.pl itself runs and writes its output."""
    path = tmp_path / "script.vbe"
    path.write_bytes(ENCODED)

    target = _analyze(root_analysis, path)

    assert target.get_and_load_analysis(MicrosoftScriptEncodingAnalysis)
    assert os.path.exists(f"{target.full_path}.decrypted.vbs")
