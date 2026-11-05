import logging
import os
import subprocess
import threading
import pytest
import tempfile

from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_ZIP_ENCRYPTION_ANALYZER
from saq.cracking import generate_wordlist, crack_password
from saq.modules.email.encryption.zip import ZipEncryptionAnalyzer
from saq.sandbox.runner import SandboxResult
from tests.saq.test_util import create_test_context


@pytest.mark.unit
def test_generate_wordlist_byte_limit():
    """Only the first byte_limit characters of the content are read."""
    assert generate_wordlist(text_content="abcdWXYZ", byte_limit=4, range_low=4, range_high=4) == ["abcd"]


@pytest.mark.unit
def test_generate_wordlist_list_limit():
    """Test generate_wordlist with list_limit parameter."""
    text_content = "abcdefghijklmnopqrstuvwxyz" * 10  # Create diverse content
    
    wordlist = generate_wordlist(text_content=text_content, range_low=4, range_high=6, list_limit=50)
    
    # Should not exceed list_limit
    assert len(wordlist) <= 50


@pytest.mark.unit
def test_generate_wordlist_whitespace_filtering():
    """Every substring from range_low to range_high characters long, except those with whitespace in them."""
    wordlist = generate_wordlist(text_content="abc d\tef\rgh\nijk", range_low=2, range_high=3)

    assert sorted(wordlist) == ["ab", "abc", "bc", "ef", "gh", "ij", "ijk", "jk"]


@pytest.mark.unit
def test_generate_wordlist_empty_content():
    """Test generate_wordlist with empty content."""
    wordlist = generate_wordlist(text_content="", range_low=4, range_high=8)
    
    assert isinstance(wordlist, list)
    assert len(wordlist) == 0


def _module():
    """The module john runs in the sandbox of."""
    return ZipEncryptionAnalyzer(context=create_test_context(),
                                 config=get_analysis_module_config(ANALYSIS_MODULE_ZIP_ENCRYPTION_ANALYZER))


def _john_available():
    """Check if john the ripper is available in common locations."""
    path = "/opt/tools/john-1.9.0-jumbo-1/run"
    if os.path.exists(os.path.join(path, 'john')):
        return path

    return None


@pytest.mark.integration
def test_crack_password_nonexistent_john():
    """Test crack_password with non-existent john binary path."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as hash_file:
        hash_file.write("test:hash\n")
        hash_file_path = hash_file.name
    
    try:
        # This should raise an exception or handle the error gracefully
        with pytest.raises((FileNotFoundError, OSError)):
            crack_password(_module(), "/nonexistent/path", hash_file_path, "testfile", "--test=0")
    finally:
        os.unlink(hash_file_path)


@pytest.mark.integration
def test_crack_password_nonexistent_hash_file():
    """Test crack_password with non-existent hash file."""
    john_path = _john_available()
    if not john_path:
        pytest.skip("John the Ripper not found in common locations")
    
    # This should raise an exception or handle the error gracefully
    with pytest.raises((FileNotFoundError, OSError)):
        crack_password(_module(), john_path, "/nonexistent/hash/file.txt", "testfile", "--test=0")


def _encrypted_zip_hash(directory, name: str, password: str) -> str:
    """Returns the path of the zip2john hash of a new zip encrypted with password."""
    payload = os.path.join(directory, f"{name}.txt")
    with open(payload, "w") as fp:
        # zip2john skips entries that are too short
        fp.write("payload line\n" * 50)
    archive = os.path.join(directory, f"{name}.zip")
    subprocess.run(["7z", "a", "-tzip", f"-p{password}", archive, payload], check=True, capture_output=True)
    hash_file = f"{archive}.hash"
    with open(hash_file, "wb") as fp:
        fp.write(subprocess.run([os.path.join(_john_available(), "zip2john"), archive], check=True, capture_output=True).stdout)
    return hash_file


@pytest.mark.integration
def test_crack_password_concurrently(tmp_path):
    """Engine workers crack attachments at the same time; every run must get its own john session."""
    john_path = _john_available()
    if not john_path:
        pytest.skip("John the Ripper not found in common locations")

    count = 8
    hash_files = [_encrypted_zip_hash(str(tmp_path), f"archive{i}", f"Concurrent{i}") for i in range(count)]
    wordlist = tmp_path / "wordlist"
    wordlist.write_text("".join(f"Concurrent{i}\n" for i in range(count)))

    barrier = threading.Barrier(count)
    results = [None] * count

    def _crack(index: int):
        barrier.wait()
        results[index] = crack_password(_module(), john_path, hash_files[index], f"archive{index}.zip", f"--wordlist={wordlist}",
                                        read_files=[str(wordlist)])

    threads = [threading.Thread(target=_crack, args=(i,)) for i in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)

    assert results == [f"Concurrent{i}" for i in range(count)]


@pytest.mark.integration
def test_crack_password_logs_john_failure(tmp_path, caplog):
    john_path = _john_available()
    if not john_path:
        pytest.skip("John the Ripper not found in common locations")

    hash_file = _encrypted_zip_hash(str(tmp_path), "archive", "secret")

    assert crack_password(_module(), john_path, hash_file, "archive.zip", "--incremental=NoSuchMode") is None
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING and "--incremental=NoSuchMode" in r.getMessage()]
    assert len(warnings) == 1
    assert "Unknown incremental mode: NoSuchMode" in warnings[0].getMessage()


@pytest.mark.unit
def test_crack_password_when_john_is_stopped(tmp_path, monkeypatch):
    """A john run that was stopped (a timeout, a cancelled analysis) cracked nothing."""
    john_path = _john_available()
    if not john_path:
        pytest.skip("John the Ripper not found in common locations")

    hash_file = tmp_path / "archive.zip.hash"
    hash_file.write_text("archive.zip:$pkzip$hash\n")
    module = _module()
    runs = []
    monkeypatch.setattr(module, "run_sandboxed_tool", lambda args, target, **kwargs: runs.append(args))

    assert crack_password(module, john_path, str(hash_file), "archive.zip", "--wordlist=words") is None
    # nothing to --show without the first run's pot
    assert len(runs) == 1


@pytest.mark.unit
def test_crack_password_when_john_show_is_stopped(tmp_path, monkeypatch):
    """The first run cracked the hash, and the --show that reads its pot was stopped."""
    john_path = _john_available()
    if not john_path:
        pytest.skip("John the Ripper not found in common locations")

    hash_file = tmp_path / "archive.zip.hash"
    hash_file.write_text("archive.zip:$pkzip$hash\n")
    module = _module()
    runs = []

    def _run(args, target, outputs=None, **kwargs):
        runs.append(args)
        if outputs:
            for destination in outputs.values():
                with open(destination, "w") as fp:
                    fp.write("$pkzip$hash:secret\n")
            return SandboxResult(0, "", "")
        return None

    monkeypatch.setattr(module, "run_sandboxed_tool", _run)

    assert crack_password(module, john_path, str(hash_file), "archive.zip", "--wordlist=words") is None
    assert "--show" in runs[-1] and len(runs) == 2
