import base64
import os

import pytest

from saq.analysis.root import load_root
from saq.constants import F_FILE
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.file_analysis.xml import XMLBinaryDataAnalysis
from saq.util.uuid import get_storage_dir


def _flat_opc(parts: list[tuple[str, bytes]]) -> str:
    """A Word document saved as a single XML file, with the given parts as base64 binary data."""
    package_parts = "".join(
        f'<pkg:part pkg:name="{name}"><pkg:binaryData>{base64.b64encode(content).decode()}</pkg:binaryData></pkg:part>'
        for name, content in parts)
    return ('<?xml version="1.0" standalone="yes"?>\n'
            '<?mso-application progid="Word.Document"?>\n'
            f'<pkg:package xmlns:pkg="http://schemas.microsoft.com/office/2006/xmlPackage">{package_parts}</pkg:package>')


@pytest.mark.integration
def test_xml_binary_data_part_names_stay_inside_the_output_dir(root_analysis, tmp_path):
    """The part names come from the document, so an absolute one is extracted under the document's
    output directory like any other."""
    escaped = tmp_path / "escaped.bin"
    root_analysis.analysis_mode = "test_groups"
    target_path = root_analysis.create_file_path("document.xml")
    with open(target_path, "w") as fp:
        # the extra leading / makes the part name an absolute path outside the package
        fp.write(_flat_opc([("/word/media/image1.png", b"image"), (f"/{escaped}", b"escaped")]))

    _file = root_analysis.add_file_observable(target_path)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("xml_binary_analyzer", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    assert not escaped.exists()

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    analysis = root_analysis.get_observable(_file.uuid).get_and_load_analysis(XMLBinaryDataAnalysis)
    extracted = {o.file_path: o for o in analysis.get_observables_by_type(F_FILE)}
    image_path = os.path.join("document.xml.xml", "word", "media", "image1.png")
    (escaped_path,) = set(extracted) - {image_path}
    assert image_path in extracted
    assert escaped_path == os.path.join("document.xml.xml", str(escaped).lstrip("/"))
    with open(extracted[escaped_path].full_path, "rb") as fp:
        assert fp.read() == b"escaped"


@pytest.mark.integration
def test_xml_binary_data_parts_with_the_same_name_are_kept_apart(root_analysis):
    """A document can name two parts the same, and the second must not overwrite the first."""
    root_analysis.analysis_mode = "test_groups"
    target_path = root_analysis.create_file_path("document.xml")
    with open(target_path, "w") as fp:
        fp.write(_flat_opc([("/word/media/image1.png", b"first"), ("/word/media/image1.png", b"second")]))

    _file = root_analysis.add_file_observable(target_path)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("xml_binary_analyzer", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    analysis = root_analysis.get_observable(_file.uuid).get_and_load_analysis(XMLBinaryDataAnalysis)
    contents = {}
    for o in analysis.get_observables_by_type(F_FILE):
        with open(o.full_path, "rb") as fp:
            contents[o.file_path] = fp.read()

    media = os.path.join("document.xml.xml", "word", "media")
    assert contents == {os.path.join(media, "image1.png"): b"first", os.path.join(media, "image1_000.png"): b"second"}


@pytest.mark.integration
def test_xml_binary_data_part_named_the_package_root(root_analysis):
    """A part named / must not take the output directory's name and keep the later parts out of it."""
    root_analysis.analysis_mode = "test_groups"
    target_path = root_analysis.create_file_path("document.xml")
    with open(target_path, "w") as fp:
        fp.write(_flat_opc([("/", b"root"), ("/word/vbaProject.bin", b"macros")]))

    _file = root_analysis.add_file_observable(target_path)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("xml_binary_analyzer", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    analysis = root_analysis.get_observable(_file.uuid).get_and_load_analysis(XMLBinaryDataAnalysis)
    contents = {}
    for o in analysis.get_observables_by_type(F_FILE):
        with open(o.full_path, "rb") as fp:
            contents[o.file_path] = fp.read()

    assert contents == {
        os.path.join("document.xml.xml", "_"): b"root",
        os.path.join("document.xml.xml", "word", "vbaProject.bin"): b"macros",
    }
