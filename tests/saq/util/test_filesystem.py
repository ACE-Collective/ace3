import os

import pytest

from saq.util.filesystem import NAME_MAX_BYTES, is_path_under, shorten_basename_for_suffix, unique_file_path


class TestShortenBasenameForSuffix:

    @pytest.mark.unit
    def test_short_basename_passes_through_unchanged(self):
        assert shorten_basename_for_suffix("hello.eml", ".headers") == "hello.eml.headers"

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
    def test_production_payload_fits(self):
        # Matches the production traceback: 247-byte basename + .headers = 255 → would have hit 256+ on .combined.
        basename = (
            "_Share-d37b5d9a-8ba2-41f8-aa8a-47304bdbac75;rcid_f42515a2-50c3-d000-114c-7f4917c156a9;"
            "wiid_f95a6d38-13fc-4ae5-b60b-28d6590de67b-ioe_1-tid_7a53b4fc-e87d-4c46-9972-0570ac271b27-"
            "rh_cac_notifyp-aid_928ab984-e2fc-480a-9b28-91d1c5dfa667@odspnotify__glw5mcs4.eml"
        )
        for suffix in (".headers", ".combined"):
            result = shorten_basename_for_suffix(basename, suffix)
            assert len(result.encode("utf-8")) <= NAME_MAX_BYTES
            assert result.endswith(suffix)

    @pytest.mark.unit
    def test_determinism(self):
        basename = "a" * 300
        suffix = ".headers"
        assert shorten_basename_for_suffix(basename, suffix) == shorten_basename_for_suffix(basename, suffix)

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


class TestUniqueFilePath:

    @pytest.mark.unit
    def test_a_free_path_is_unchanged(self, tmp_path):
        assert unique_file_path(str(tmp_path / "a.txt")) == str(tmp_path / "a.txt")

    @pytest.mark.unit
    def test_a_taken_path_gets_the_next_free_index(self, tmp_path):
        (tmp_path / "a.txt").write_text("a")
        assert unique_file_path(str(tmp_path / "a.txt")) == str(tmp_path / "a_000.txt")

        (tmp_path / "a_000.txt").write_text("a")
        assert unique_file_path(str(tmp_path / "a.txt")) == str(tmp_path / "a_001.txt")

    @pytest.mark.unit
    def test_no_extension_and_a_dangling_symlink(self, tmp_path):
        os.symlink(tmp_path / "missing", tmp_path / "upload")
        assert unique_file_path(str(tmp_path / "upload")) == str(tmp_path / "upload_000")
