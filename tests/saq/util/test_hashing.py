import pytest

from saq.util.hashing import get_md5_hash_of_file, get_md5_hash_of_string

@pytest.mark.unit
def test_get_md5_hash_of_file(tmpdir):
    file_path = tmpdir / "test"
    file_path.write_binary(b'')
    assert get_md5_hash_of_file(str(file_path)) == "d41d8cd98f00b204e9800998ecf8427e"

    file_path.write_binary(b'test')
    assert get_md5_hash_of_file(str(file_path)) == "098f6bcd4621d373cade4e832627b4f6"


@pytest.mark.parametrize("source, expected_value", [
    ("test", "098f6bcd4621d373cade4e832627b4f6"),
])
@pytest.mark.unit
def test_get_md5_hash_of_string(source, expected_value):
    assert get_md5_hash_of_string(source) == expected_value