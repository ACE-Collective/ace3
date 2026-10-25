import hashlib
import logging
import os
from unittest.mock import Mock

import pytest
from PIL import Image

from saq.configuration.config import get_config
from saq.constants import DIRECTIVE_YARA_META_PREFIX, F_FILE_LOCATION, F_SHA256
from saq.observables.file import parse_yara_meta_directive, YARA_META_NAME_PATTERN


class TestParseYaraMetaDirective:
    @pytest.mark.unit
    def test_valid_directive(self):
        result = parse_yara_meta_directive("yara_meta:content_type=email_body")
        assert result == ("content_type", "email_body")

    @pytest.mark.unit
    def test_valid_directive_with_hyphens(self):
        result = parse_yara_meta_directive("yara_meta:file-type=html-body")
        assert result == ("file-type", "html-body")

    @pytest.mark.unit
    def test_valid_directive_value_with_equals(self):
        result = parse_yara_meta_directive("yara_meta:key=val=ue")
        assert result == ("key", "val=ue")

    @pytest.mark.unit
    def test_valid_directive_empty_value(self):
        result = parse_yara_meta_directive("yara_meta:key=")
        assert result == ("key", "")

    @pytest.mark.unit
    def test_non_yara_meta_directive(self):
        result = parse_yara_meta_directive("sandbox")
        assert result is None

    @pytest.mark.unit
    def test_missing_equals(self):
        result = parse_yara_meta_directive("yara_meta:noequals")
        assert result is None

    @pytest.mark.unit
    def test_invalid_name_with_spaces(self):
        result = parse_yara_meta_directive("yara_meta:bad name=value")
        assert result is None

    @pytest.mark.unit
    def test_invalid_name_with_special_chars(self):
        result = parse_yara_meta_directive("yara_meta:bad!name=value")
        assert result is None


class TestFileObservableYaraMeta:
    @pytest.mark.unit
    def test_add_yara_meta(self, root_analysis):
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"test content")

        observable = root_analysis.add_file_observable(file_path)
        observable.add_yara_meta("content_type", "email_body")

        expected = f"{DIRECTIVE_YARA_META_PREFIX}content_type=email_body"
        assert expected in observable.directives

    @pytest.mark.unit
    def test_add_yara_meta_invalid_name(self, root_analysis):
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"test content")

        observable = root_analysis.add_file_observable(file_path)
        with pytest.raises(ValueError):
            observable.add_yara_meta("bad name", "value")

    @pytest.mark.unit
    def test_has_yara_meta(self, root_analysis):
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"test content")

        observable = root_analysis.add_file_observable(file_path)
        observable.add_yara_meta("type", "script.javascript")

        assert observable.has_yara_meta("type", "script.javascript")

    @pytest.mark.unit
    def test_has_yara_meta_missing(self, root_analysis):
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"test content")

        observable = root_analysis.add_file_observable(file_path)
        observable.add_yara_meta("type", "script.javascript")
        observable.add_directive("sandbox")

        # wrong value for an existing name
        assert not observable.has_yara_meta("type", "script.vbscript")
        # name that was never added
        assert not observable.has_yara_meta("source", "imap")
        # a plain directive is not a yara meta tag
        assert not observable.has_yara_meta("sandbox", "")

    @pytest.mark.unit
    def test_yara_meta_tags_property(self, root_analysis):
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"test content")

        observable = root_analysis.add_file_observable(file_path)
        observable.add_yara_meta("content_type", "email_body")
        observable.add_yara_meta("source", "imap")

        tags = observable.yara_meta_tags
        assert "content_type=email_body" in tags
        assert "source=imap" in tags
        assert len(tags) == 2

    @pytest.mark.unit
    def test_yara_meta_tags_empty(self, root_analysis):
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"test content")

        observable = root_analysis.add_file_observable(file_path)
        assert observable.yara_meta_tags == []

    @pytest.mark.unit
    def test_yara_meta_tags_with_mixed_directives(self, root_analysis):
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"test content")

        observable = root_analysis.add_file_observable(file_path)
        observable.add_directive("sandbox")
        observable.add_yara_meta("content_type", "email_body")
        observable.add_directive("no_scan")

        tags = observable.yara_meta_tags
        assert tags == ["content_type=email_body"]


def _write_file(root_analysis, name: str, content: bytes) -> str:
    file_path = root_analysis.create_file_path(name)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as fp:
        fp.write(content)

    return file_path


class TestFileObservableExt:
    @pytest.mark.unit
    def test_ext_is_lowercase(self, root_analysis):
        observable = root_analysis.add_file_observable(_write_file(root_analysis, "Report.PDF", b"test"))
        assert observable.ext == "pdf"

    @pytest.mark.unit
    def test_dot_file(self, root_analysis):
        # archive.py relies on this to find the .rels parts of an extracted xps
        observable = root_analysis.add_file_observable(_write_file(root_analysis, "_rels/.rels", b"test"))
        assert observable.ext == "rels"

    @pytest.mark.unit
    def test_no_ext_in_dotted_directory(self, root_analysis):
        # the files directory of every root and the directories archives extract into
        # (sample.zip.extracted/) can carry dots that are not the file's
        observable = root_analysis.add_file_observable(
            _write_file(root_analysis, "sample.zip.extracted/xml", b"test"))
        assert observable.ext is None


class TestFileObservableMimeType:
    @pytest.mark.unit
    def test_mime_type_of_file(self, root_analysis):
        observable = root_analysis.add_file_observable(_write_file(root_analysis, "test.txt", b"test content"))
        assert observable.mime_type == "text/plain"

    @pytest.mark.unit
    def test_missing_file_has_no_mime_type(self, root_analysis):
        file_path = _write_file(root_analysis, "test.txt", b"test content")
        observable = root_analysis.add_file_observable(file_path)
        os.remove(file_path)

        assert observable.mime_type is None
        assert not observable.is_image
        # nothing was cached: the file comes back with its type
        _write_file(root_analysis, "test.txt", b"test content")
        assert observable.mime_type == "text/plain"

    @pytest.mark.unit
    def test_unloadable_file_type_analysis_falls_back_to_file(self, root_analysis, monkeypatch):
        observable = root_analysis.add_file_observable(_write_file(root_analysis, "test.txt", b"test content"))
        monkeypatch.setattr(observable, "get_and_load_analysis", Mock(side_effect=OSError("details gone")))

        assert observable.mime_type == "text/plain"


class TestFileObservableSize:
    @pytest.mark.unit
    @pytest.mark.parametrize("size,expected", [
        (0, "0 B"),
        (100, "100 B"),
        (1536, "1.5 KB"),
        (5 * 1024 * 1024, "5 MB"),
    ])
    def test_human_readable_size(self, root_analysis, size, expected):
        observable = root_analysis.add_file_observable(_write_file(root_analysis, "test.bin", b"\x01" * size))
        assert observable.human_readable_size == expected

    @pytest.mark.unit
    def test_human_readable_size_petabytes(self, root_analysis):
        # the order of magnitude after terabytes was labeled exabytes
        observable = root_analysis.add_file_observable(_write_file(root_analysis, "test.bin", b"test"))
        observable._size = 3 * 2 ** 50
        assert observable.human_readable_size == "3 PB"

    @pytest.mark.unit
    def test_missing_file_size(self, root_analysis, caplog):
        file_path = _write_file(root_analysis, "test.bin", b"test")
        observable = root_analysis.add_file_observable(file_path)
        os.remove(file_path)

        with caplog.at_level(logging.WARNING):
            assert observable.size is None
            assert observable.human_readable_size == ""

        assert any("unable to determine size of" in r.getMessage() for r in caplog.records)
        assert not observable.exists


class TestFileObservablePreview:
    @pytest.mark.unit
    def test_display_preview_is_capped(self, root_analysis):
        content = b"A" * (get_config().gui.file_preview_bytes + 100)
        observable = root_analysis.add_file_observable(_write_file(root_analysis, "test.txt", content))
        assert observable.display_preview == "A" * get_config().gui.file_preview_bytes

    @pytest.mark.unit
    def test_display_preview_replaces_undecodable_bytes(self, root_analysis):
        observable = root_analysis.add_file_observable(_write_file(root_analysis, "test.bin", b"ab\xffcd"))
        assert observable.display_preview == "ab\ufffdcd"

    @pytest.mark.unit
    def test_display_preview_missing_file(self, root_analysis, caplog):
        file_path = _write_file(root_analysis, "test.txt", b"test")
        observable = root_analysis.add_file_observable(file_path)
        os.remove(file_path)

        with caplog.at_level(logging.WARNING):
            assert observable.display_preview is None

        assert any("file does not exist for display_preview" in r.getMessage() for r in caplog.records)


def _write_image(root_analysis, name: str, width: int, height: int) -> str:
    file_path = root_analysis.create_file_path(name)
    Image.new("RGB", (width, height)).save(file_path, format="PNG")
    return file_path


class TestFileObservableScaledDimensions:
    @pytest.mark.unit
    def test_small_image_is_not_scaled(self, root_analysis):
        observable = root_analysis.add_file_observable(_write_image(root_analysis, "small.png", 100, 50))
        assert observable.is_image
        assert (observable.scaled_width, observable.scaled_height) == (100, 50)

    @pytest.mark.unit
    def test_large_image_is_scaled(self, root_analysis):
        observable = root_analysis.add_file_observable(_write_image(root_analysis, "large.png", 640, 480))
        assert (observable.scaled_width, observable.scaled_height) == (320, 240)

    @pytest.mark.unit
    def test_dimensions_are_computed_once(self, root_analysis, monkeypatch):
        observable = root_analysis.add_file_observable(_write_image(root_analysis, "large.png", 640, 480))
        assert observable.scaled_width == 320

        # read from the serialized values from now on, not from the file
        monkeypatch.setattr("PIL.Image.open", Mock(side_effect=AssertionError("image reopened")))
        observable.compute_scaled_dimensions()
        assert (observable.scaled_width, observable.scaled_height) == (320, 240)

    @pytest.mark.unit
    def test_not_an_image(self, root_analysis):
        observable = root_analysis.add_file_observable(_write_file(root_analysis, "test.txt", b"test"))
        assert not observable.is_image
        assert observable.scaled_width is None
        assert observable.scaled_height is None

    @pytest.mark.unit
    def test_unparseable_image(self, root_analysis, caplog):
        observable = root_analysis.add_file_observable(_write_file(root_analysis, "broken.png", b"not a png"))
        observable.mime_type = "image/png"

        with caplog.at_level(logging.WARNING):
            assert observable.scaled_width is None
            assert observable.scaled_height is None

        assert any("unable to parse image" in r.getMessage() for r in caplog.records)


class TestFileObservableTagMapping:
    @pytest.mark.unit
    def test_tags_map_to_the_sha256(self, root_analysis):
        observable = root_analysis.add_file_observable(_write_file(root_analysis, "test.txt", b"test"))
        sha256 = hashlib.sha256(b"test").hexdigest()

        assert observable.tag_mapping_type == F_SHA256
        assert observable.tag_mapping_value == sha256
        assert observable.tag_mapping_md5_hex == hashlib.md5(sha256.encode()).hexdigest()


class TestFileLocationObservable:
    @pytest.mark.unit
    def test_hostname_and_path(self, root_analysis):
        observable = root_analysis.add_observable_by_spec(F_FILE_LOCATION, r"workstation@C:\Users\test\evil.exe")
        assert observable.hostname == "workstation"
        assert observable.full_path == r"C:\Users\test\evil.exe"
