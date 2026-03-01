import pytest

from saq.constants import DIRECTIVE_YARA_META_PREFIX
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
