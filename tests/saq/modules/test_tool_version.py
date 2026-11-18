"""Unit tests for probe_binary_version (cache-key tool fingerprinting)."""
import hashlib
import os
import pathlib
import shutil
import stat
import tempfile

import pytest

from saq.modules.tool_version import (
    _reset_probe_cache_for_tests,
    file_content_version,
    probe_binary_version,
)


@pytest.fixture(autouse=True)
def reset_probe_cache():
    _reset_probe_cache_for_tests()
    yield
    _reset_probe_cache_for_tests()


@pytest.fixture
def fake_tool_dir(monkeypatch):
    # NOT tmp_path: /tmp is mounted noexec in the dev container, so fake
    # executables there are invisible to shutil.which. /var/tmp allows exec.
    tool_dir = pathlib.Path(tempfile.mkdtemp(prefix="tool_version_test_", dir="/var/tmp"))
    monkeypatch.setenv("PATH", f"{tool_dir}{os.pathsep}{os.environ['PATH']}")
    yield tool_dir
    shutil.rmtree(tool_dir, ignore_errors=True)


def _make_tool(directory, name, script_body):
    path = directory / name
    path.write_text(f"#!/bin/sh\n{script_body}\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


class TestProbeBinaryVersion:

    @pytest.mark.unit
    def test_returns_first_nonempty_stdout_line(self, fake_tool_dir):
        _make_tool(fake_tool_dir, "fake_tool", 'echo "fake_tool 1.2.3"\necho "extra line"')
        assert probe_binary_version("fake_tool") == "fake_tool 1.2.3"

    @pytest.mark.unit
    def test_falls_back_to_stderr(self, fake_tool_dir):
        # pdfinfo-style: version goes to stderr
        _make_tool(fake_tool_dir, "fake_tool", 'echo "fake_tool 4.5.6" >&2')
        assert probe_binary_version("fake_tool") == "fake_tool 4.5.6"

    @pytest.mark.unit
    def test_custom_args(self, fake_tool_dir):
        _make_tool(fake_tool_dir, "fake_tool", 'echo "args: $@"')
        assert probe_binary_version("fake_tool", args=["-v"]) == "args: -v"

    @pytest.mark.unit
    def test_missing_tool_returns_none(self, fake_tool_dir):
        assert probe_binary_version("definitely_not_a_real_tool_xyz") is None

    @pytest.mark.unit
    def test_failing_tool_returns_none_and_caches_negative(self, fake_tool_dir):
        counter = fake_tool_dir / "count"
        # produces no stdout/stderr output at all → probe returns None
        _make_tool(fake_tool_dir, "fake_tool", f'echo x >> "{counter}"\nexit 1')
        assert probe_binary_version("fake_tool") is None
        assert probe_binary_version("fake_tool") is None
        # negative result cached: the script ran exactly once
        assert counter.read_text().count("x") == 1

    @pytest.mark.unit
    def test_result_cached_per_binary_identity(self, fake_tool_dir):
        counter = fake_tool_dir / "count"
        _make_tool(fake_tool_dir, "fake_tool", f'echo x >> "{counter}"\necho "v1"')
        assert probe_binary_version("fake_tool") == "v1"
        assert probe_binary_version("fake_tool") == "v1"
        assert counter.read_text().count("x") == 1

    @pytest.mark.unit
    def test_mtime_change_reprobes(self, fake_tool_dir):
        tool = _make_tool(fake_tool_dir, "fake_tool", 'echo "v1"')
        assert probe_binary_version("fake_tool") == "v1"
        # simulate an upgrade that keeps the size: replace content, move mtime forward
        size = tool.stat().st_size
        _make_tool(fake_tool_dir, "fake_tool", 'echo "v2"')
        st = tool.stat()
        assert st.st_size == size
        os.utime(tool, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
        assert probe_binary_version("fake_tool") == "v2"


class TestFileContentVersion:

    @pytest.mark.unit
    def test_returns_content_sha256(self, tmp_path):
        f = tmp_path / "rules.filter"
        f.write_bytes(b"example\\.com\n")
        assert file_content_version(str(f)) == hashlib.sha256(b"example\\.com\n").hexdigest()

    @pytest.mark.unit
    def test_missing_file_returns_none(self, tmp_path):
        assert file_content_version(str(tmp_path / "nope")) is None
