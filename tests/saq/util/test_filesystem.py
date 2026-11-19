import hashlib
import json
import os

import pytest

from saq.util.filesystem import NAME_MAX_BYTES, is_path_under, shorten_basename_for_suffix, store_storage_paths_relative


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

    @pytest.mark.unit
    def test_undecodable_basename_is_measured_in_filesystem_bytes(self):
        """A name read from the filesystem that is not UTF-8 (each undecodable byte a lone surrogate)
        is kept and shortened by the bytes the filesystem stores."""
        short = b"\xe9\xe9.eml".decode("utf-8", "surrogateescape")
        assert shorten_basename_for_suffix(short, ".headers") == short + ".headers"

        long = (b"\xe9" * 300).decode("utf-8", "surrogateescape")
        result = shorten_basename_for_suffix(long, ".headers")
        digest = hashlib.sha1(b"\xe9" * 300).hexdigest()[:8]
        assert result == long[:238] + f".{digest}.headers"
        assert len(os.fsencode(result)) == NAME_MAX_BYTES


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


class TestStoreStoragePathsRelative:
    def _store(self, value, storage_dir, stored_storage_dir):
        return json.loads(store_storage_paths_relative(json.dumps(value), storage_dir, stored_storage_dir))

    @pytest.mark.unit
    def test_data_inside_saq_home(self):
        storage_dir, stored = "/opt/ace/data/node/abc/abc-uuid", "data/node/abc/abc-uuid"
        value = {"summary": f"extracted {storage_dir}/files/a.txt", "files": [f"{storage_dir}/files/b.txt"],
                 "other": "/opt/ace/data/node/def/def-uuid/files/c.txt", "stored": f"{stored}/files/d.txt"}
        assert self._store(value, storage_dir, stored) == {
            "summary": f"extracted {stored}/files/a.txt", "files": [f"{stored}/files/b.txt"],
            # another root's storage directory is not this root's to rewrite
            "other": "/opt/ace/data/node/def/def-uuid/files/c.txt",
            "stored": f"{stored}/files/d.txt"}

    @pytest.mark.unit
    def test_data_outside_saq_home(self):
        """The relative path ends with the absolute one; one already stored is not rewritten again."""
        storage_dir, stored = "/var/data/node/abc/abc-uuid", "../../var/data/node/abc/abc-uuid"
        value = {"new": f"{storage_dir}/files/a.txt", "stored": f"{stored}/files/b.txt"}
        assert self._store(value, storage_dir, stored) == {"new": f"{stored}/files/a.txt", "stored": f"{stored}/files/b.txt"}

    @pytest.mark.unit
    def test_an_absolute_storage_dir_is_stored_as_it_is(self):
        storage_dir = "/var/work/abc-uuid"
        assert self._store({"path": f"{storage_dir}/files/a.txt"}, storage_dir, storage_dir) == {"path": f"{storage_dir}/files/a.txt"}
