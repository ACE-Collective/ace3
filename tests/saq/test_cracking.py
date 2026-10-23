import logging
import os
import subprocess
import threading
import pytest
import tempfile

from saq.cracking import generate_wordlist, crack_password


@pytest.mark.unit
def test_generate_wordlist_with_text_content():
    """Test generate_wordlist with text_content parameter."""
    text_content = "hello world password123 test_pass admin1234"
    
    wordlist = generate_wordlist(text_content=text_content, range_low=4, range_high=8)
    
    assert isinstance(wordlist, list)
    assert len(wordlist) > 0
    # Should contain substrings within the range
    assert any(4 <= len(word) <= 8 for word in wordlist)
    # Should not contain words with whitespace
    assert all(' ' not in word for word in wordlist)
    assert all('\t' not in word for word in wordlist)
    assert all('\n' not in word for word in wordlist)


@pytest.mark.unit
def test_generate_wordlist_with_text_file(tmpdir):
    """Test generate_wordlist with text_file parameter."""
    test_content = "testpass secure123 mypassword admin"
    test_file = tmpdir.join("test.txt")
    test_file.write(test_content)
    
    wordlist = generate_wordlist(text_file=str(test_file), range_low=4, range_high=10)
    
    assert isinstance(wordlist, list)
    assert len(wordlist) > 0
    # Should extract substrings from file content
    assert any('test' in word for word in wordlist)
    assert any('pass' in word for word in wordlist)


@pytest.mark.unit
def test_generate_wordlist_range_parameters():
    """Test generate_wordlist with different range parameters."""
    text_content = "password123testing"
    
    # Test with small range
    wordlist_small = generate_wordlist(text_content=text_content, range_low=4, range_high=6)
    assert all(4 <= len(word) <= 6 for word in wordlist_small)
    
    # Test with larger range
    wordlist_large = generate_wordlist(text_content=text_content, range_low=8, range_high=12)
    assert all(8 <= len(word) <= 12 for word in wordlist_large)


@pytest.mark.unit
def test_generate_wordlist_byte_limit():
    """Test generate_wordlist with byte_limit parameter."""
    text_content = "a" * 2000  # Long string
    
    wordlist = generate_wordlist(text_content=text_content, byte_limit=100, range_low=4, range_high=8)
    
    # Should only process first 100 bytes
    assert isinstance(wordlist, list)
    # All generated words should be within the specified range
    assert all(4 <= len(word) <= 8 for word in wordlist)


@pytest.mark.unit
def test_generate_wordlist_list_limit():
    """Test generate_wordlist with list_limit parameter."""
    text_content = "abcdefghijklmnopqrstuvwxyz" * 10  # Create diverse content
    
    wordlist = generate_wordlist(text_content=text_content, range_low=4, range_high=6, list_limit=50)
    
    # Should not exceed list_limit
    assert len(wordlist) <= 50


@pytest.mark.unit
def test_generate_wordlist_whitespace_filtering():
    """Test that generate_wordlist filters out passwords containing whitespace."""
    text_content = "pass word\ttest\nline password123"
    
    wordlist = generate_wordlist(text_content=text_content, range_low=4, range_high=15)
    
    # No word should contain whitespace characters
    for word in wordlist:
        assert ' ' not in word
        assert '\t' not in word
        assert '\n' not in word
        assert '\r' not in word


@pytest.mark.unit
def test_generate_wordlist_empty_content():
    """Test generate_wordlist with empty content."""
    wordlist = generate_wordlist(text_content="", range_low=4, range_high=8)
    
    assert isinstance(wordlist, list)
    assert len(wordlist) == 0


@pytest.mark.unit
def test_generate_wordlist_short_content():
    """Test generate_wordlist with content shorter than range_low."""
    text_content = "ab"
    
    wordlist = generate_wordlist(text_content=text_content, range_low=4, range_high=8)
    
    assert isinstance(wordlist, list)
    assert len(wordlist) == 0


@pytest.mark.unit
def test_generate_wordlist_file_read_error():
    """Test generate_wordlist with non-existent file."""
    with pytest.raises(FileNotFoundError):
        generate_wordlist(text_file="/non/existent/file.txt")


@pytest.mark.unit
def test_generate_wordlist_binary_file_handling(tmpdir):
    """Test generate_wordlist with binary content (should decode with errors='ignore')."""
    # Create a file with binary content including invalid UTF-8
    test_file = tmpdir.join("binary_test.txt")
    binary_content = b"test\xff\xfepassword\x80\x90admin"
    test_file.write_binary(binary_content)
    
    wordlist = generate_wordlist(text_file=str(test_file), range_low=4, range_high=10)
    
    assert isinstance(wordlist, list)
    # Should handle binary content gracefully
    assert any('test' in word for word in wordlist)
    assert any('pass' in word for word in wordlist)


def _john_available():
    """Check if john the ripper is available in common locations."""
    path = "/opt/tools/john-1.9.0-jumbo-1/run"
    if os.path.exists(os.path.join(path, 'john')):
        return path

    return None


@pytest.mark.integration
def test_crack_password_with_john():
    """Test crack_password integration with actual john binary if available."""
    john_path = _john_available()
    if not john_path:
        pytest.skip("John the Ripper not found in common locations")
    
    # Create a temporary hash file with a simple hash
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as hash_file:
        # Simple hash for testing - this would normally be generated by john
        hash_file.write("testfile:$zip$*0*1*0*08*test*$/zip$\n")
        hash_file_path = hash_file.name
    
    try:
        # Test with invalid mode to ensure function handles failures gracefully
        result = crack_password(john_path, hash_file_path, "testfile", "--test=0")
        
        # Function should return None or a password string, never crash
        assert result is None or isinstance(result, str)
        
    finally:
        # Clean up temporary file
        os.unlink(hash_file_path)


@pytest.mark.integration
def test_crack_password_nonexistent_john():
    """Test crack_password with non-existent john binary path."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as hash_file:
        hash_file.write("test:hash\n")
        hash_file_path = hash_file.name
    
    try:
        # This should raise an exception or handle the error gracefully
        with pytest.raises((FileNotFoundError, OSError)):
            crack_password("/nonexistent/path", hash_file_path, "testfile", "--test=0")
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
        crack_password(john_path, "/nonexistent/hash/file.txt", "testfile", "--test=0")


@pytest.mark.integration
def test_crack_password_empty_hash_file():
    """Test crack_password with empty hash file."""
    john_path = _john_available()
    if not john_path:
        pytest.skip("John the Ripper not found in common locations")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as hash_file:
        # Write empty content
        pass
        hash_file_path = hash_file.name
    
    try:
        result = crack_password(john_path, hash_file_path, "testfile", "--test=0")
        # Should handle empty file gracefully
        assert result is None or isinstance(result, str)
    finally:
        os.unlink(hash_file_path)


@pytest.mark.integration
def test_crack_password_invalid_mode():
    """Test crack_password with invalid john mode."""
    john_path = _john_available()
    if not john_path:
        pytest.skip("John the Ripper not found in common locations")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as hash_file:
        hash_file.write("testfile:somehash\n")
        hash_file_path = hash_file.name
    
    try:
        # Test with invalid mode - should handle gracefully
        result = crack_password(john_path, hash_file_path, "testfile", "--invalid-mode-xyz")
        # Function should not crash, may return None
        assert result is None or isinstance(result, str)
    finally:
        os.unlink(hash_file_path)

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
        results[index] = crack_password(john_path, hash_files[index], f"archive{index}.zip", f"--wordlist={wordlist}")

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

    assert crack_password(john_path, hash_file, "archive.zip", "--incremental=NoSuchMode") is None
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING and "--incremental=NoSuchMode" in r.getMessage()]
    assert len(warnings) == 1
    assert "Unknown incremental mode: NoSuchMode" in warnings[0].getMessage()
