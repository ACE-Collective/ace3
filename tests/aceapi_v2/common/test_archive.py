import pytest

from aceapi_v2.common.archive import safe_file_name


@pytest.mark.unit
@pytest.mark.parametrize("file_name, expected", [
    ("invoice.doc", "invoice.doc"),
    ("../../etc/passwd", "passwd"),
    ("dir/sub/..hidden", "hidden"),
    ("with spaces & $(stuff).exe", "with_spaces_stuff_.exe"),
    ("", "file"),
    ("...", "file"),
    ("manifest.json", "file_manifest.json"),
    ("match.json", "match.json"),
    ("x" * 300, "x" * 128),
])
def test_safe_file_name(file_name, expected):
    assert safe_file_name(file_name) == expected


@pytest.mark.unit
def test_safe_file_name_avoids_the_archive_s_own_names():
    reserved = {"manifest.json", "match.json"}
    assert safe_file_name("match.json", reserved) == "file_match.json"
    assert safe_file_name("../manifest.json", reserved) == "file_manifest.json"
    assert safe_file_name("other.json", reserved) == "other.json"
