import os

import pytest

from saq.util.filesystem import NAME_MAX_BYTES, is_path_under, shorten_basename_for_suffix


class TestShortenBasenameForSuffix:

    @pytest.mark.unit
    def test_exactly_at_limit_passes_through_unchanged(self):
        suffix = ".headers"
        basename = "x" * (NAME_MAX_BYTES - len(suffix))
        result = shorten_basename_for_suffix(basename, suffix)
        assert result == basename + suffix
        assert len(result.encode("utf-8")) == NAME_MAX_BYTES

    @pytest.mark.unit
    def test_one_byte_over_limit_truncates(self):
        suffix = ".headers"
        basename = "x" * (NAME_MAX_BYTES - len(suffix) + 1)
        result = shorten_basename_for_suffix(basename, suffix)
        assert len(result.encode("utf-8")) <= NAME_MAX_BYTES
        assert result.endswith(suffix)
        # ".XXXXXXXX.headers" hash signature should appear right before the suffix
        assert result[-(len(suffix) + 9)] == "."

    @pytest.mark.unit
    def test_determinism(self):
        """A retried analysis, in another process or on another node, gets the same path: the
        digest is the first 8 hex characters of the sha1 of the whole basename."""
        # hashlib.sha1(("a" * 300).encode()).hexdigest()[:8] == "003ef1ba"
        assert shorten_basename_for_suffix("a" * 300, ".headers") == "a" * 238 + ".003ef1ba.headers"

    @pytest.mark.unit
    def test_distinct_inputs_share_truncated_prefix_do_not_collide(self):
        # Same first 300 chars, different at char 301.
        common_prefix = "a" * 300
        a = common_prefix + "X" * 50
        b = common_prefix + "Y" * 50
        assert shorten_basename_for_suffix(a, ".headers") != shorten_basename_for_suffix(b, ".headers")

    @pytest.mark.unit
    def test_multibyte_utf8_not_split_mid_codepoint(self):
        # 3-byte UTF-8 characters; truncating naively at a byte boundary would land mid-codepoint.
        # The helper must decode with errors="ignore" and the result must be valid UTF-8.
        basename = "中" * 100 + ".eml"  # 100 × 3 bytes + 4 = 304 bytes
        result = shorten_basename_for_suffix(basename, ".headers")
        assert len(result.encode("utf-8")) <= NAME_MAX_BYTES
        # Round-trip — confirms no broken codepoint snuck through.
        result.encode("utf-8").decode("utf-8")
        assert result.endswith(".headers")


class TestIsPathUnder:

    @pytest.mark.unit
    def test_inside_and_the_root_itself(self, tmp_path):
        assert is_path_under(str(tmp_path / "a" / "b.txt"), str(tmp_path))
        assert is_path_under(str(tmp_path), str(tmp_path))
        assert is_path_under(str(tmp_path / "a" / ".." / "b.txt"), str(tmp_path))

    @pytest.mark.unit
    def test_outside(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        assert not is_path_under(str(root / ".." / "b.txt"), str(root))
        assert not is_path_under(str(tmp_path / "rootx"), str(root))
        assert not is_path_under("/etc/passwd", str(root))

    @pytest.mark.unit
    def test_a_symlink_out_is_followed(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        os.symlink(tmp_path, root / "link")
        assert not is_path_under(str(root / "link" / "b.txt"), str(root))
        # and a symlinked root still contains what is inside it
        os.symlink(root, tmp_path / "root_link")
        assert is_path_under(str(root / "b.txt"), str(tmp_path / "root_link"))
