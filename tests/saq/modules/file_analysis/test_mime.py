import os
import stat
from pathlib import Path

import pytest

from saq.analysis.root import load_root
from saq.constants import DIRECTIVE_ORIGINAL_EMAIL, F_FILE, R_EXTRACTED_FROM
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.file_analysis.mime import ActiveMimeAnalysis, HiddenMIMEAnalysis
from saq.util.uuid import get_storage_dir
from tests.saq.test_mime_extractor import SYNTHETIC_PAYLOAD, _build_active_mime

# a MIME document hidden in what is otherwise a web page
HIDDEN_MIME = b"""<html><body>nothing to see</body></html>
Content-Type: multipart/related; boundary="----=_NextPart_01"

------=_NextPart_01
Content-Type: text/plain
Content-Transfer-Encoding: base64

aGlkZGVuIHBheWxvYWQ=
------=_NextPart_01
Content-Type: application/octet-stream
Content-Transfer-Encoding: base64

U0VDT05EIFBBWUxPQUQ=
------=_NextPart_01--
"""


def _analyze(root_analysis, path: Path, module: str, directive: str = None):
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(path))
    if directive:
        file_observable.add_directive(directive)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    # hidden_mime depends on file_type
    for name in ("file_type", module):
        engine.configuration_manager.enable_module(name, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root_analysis.uuid))
    return root.get_observable(file_observable.uuid)


def _contents(observable) -> bytes:
    with open(observable.full_path, "rb") as fp:
        return fp.read()


@pytest.mark.integration
def test_hidden_mime(root_analysis, tmp_path):
    path = tmp_path / "page.html"
    path.write_bytes(HIDDEN_MIME)

    target = _analyze(root_analysis, path, "hidden_mime")

    analysis = target.get_and_load_analysis(HiddenMIMEAnalysis)
    extracted = sorted((o for o in analysis.observables if o.type == F_FILE), key=lambda o: o.file_name)
    assert [_contents(o) for o in extracted] == [b"hidden payload", b"SECOND PAYLOAD"]
    for observable in extracted:
        assert observable.get_relationship_by_type(R_EXTRACTED_FROM).target.uuid == target.uuid


@pytest.mark.integration
def test_hidden_mime_in_a_read_only_file(root_analysis, tmp_path):
    path = tmp_path / "page.html"
    path.write_bytes(HIDDEN_MIME)
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(path))
    # the attachment can be a read-only hard link to where it came from
    os.chmod(file_observable.full_path, stat.S_IRUSR)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("file_type", "test_groups")
    engine.configuration_manager.enable_module("hidden_mime", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root_analysis.uuid))
    assert root.get_observable(file_observable.uuid).get_and_load_analysis(HiddenMIMEAnalysis)


@pytest.mark.integration
@pytest.mark.parametrize("name, content, directive", [
    # the email itself is parsed by the email analyzer
    ("message.eml", HIDDEN_MIME, DIRECTIVE_ORIGINAL_EMAIL),
    ("email.rfc822", HIDDEN_MIME, None),
    ("page.html", b"<html>no mime here</html>", None),
    ("empty.html", b"", None),
])
def test_hidden_mime_skipped(root_analysis, tmp_path, name, content, directive):
    path = tmp_path / name
    path.write_bytes(content)

    assert not _analyze(root_analysis, path, "hidden_mime", directive=directive).get_and_load_analysis(HiddenMIMEAnalysis)


@pytest.mark.integration
def test_active_mime(root_analysis, tmp_path):
    path = tmp_path / "editdata.mso"
    path.write_bytes(_build_active_mime(SYNTHETIC_PAYLOAD))

    target = _analyze(root_analysis, path, "active_mime")

    analysis = target.get_and_load_analysis(ActiveMimeAnalysis)
    [extracted] = [o for o in analysis.observables if o.type == F_FILE]
    assert extracted.file_name == "editdata.mso.activemime"
    assert extracted.has_tag("activemime")
    assert extracted.get_relationship_by_type(R_EXTRACTED_FROM).target.uuid == target.uuid
    assert _contents(extracted) == SYNTHETIC_PAYLOAD
    assert analysis.summary == f"Active MIME Analysis: extracted {analysis.extracted_file}"


@pytest.mark.integration
@pytest.mark.parametrize("content", [b"not active mime", b""])
def test_active_mime_skipped(root_analysis, tmp_path, content):
    path = tmp_path / "editdata.mso"
    path.write_bytes(content)

    assert not _analyze(root_analysis, path, "active_mime").get_and_load_analysis(ActiveMimeAnalysis)
