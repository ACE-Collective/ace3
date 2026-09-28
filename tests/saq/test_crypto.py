import pytest

from saq.crypto import InvalidPasswordError, PasswordNotSetError, decrypt_chunk, encrypt_chunk, encryption_key_set, get_aes_key, set_encryption_password

@pytest.mark.integration
def test_set_password():
    assert encryption_key_set()
    # verify the password
    aes_key = get_aes_key('test')
    assert isinstance(aes_key, bytes)
    assert len(aes_key) == 32

    # encrypt and decrypt something with this password
    encrypted_chunk = encrypt_chunk('Hello, World!'.encode(), password=aes_key)
    assert decrypt_chunk(encrypted_chunk, password=get_aes_key('test')) == 'Hello, World!'.encode()

@pytest.mark.integration
def test_change_password():
    assert encryption_key_set()
    # verify the password
    aes_key = get_aes_key('test')
    # now change the password to something else
    set_encryption_password('new password', old_password='test')
    # aes key should still be the same
    assert aes_key == get_aes_key('new password')

@pytest.mark.integration
def test_invalid_password():
    assert encryption_key_set()
    with pytest.raises(InvalidPasswordError):
        aes_key = get_aes_key('invalid_password')

@pytest.mark.integration
def test_encrypt_chunk():
    chunk = b'1234567890'
    encrypted_chunk = encrypt_chunk(chunk)
    assert chunk != encrypted_chunk
    decrypted_chunk = decrypt_chunk(encrypted_chunk)
    assert chunk == decrypted_chunk

@pytest.mark.integration
def test_encrypt_empty_chunk():
    chunk = b''
    encrypted_chunk = encrypt_chunk(chunk)
    assert chunk != encrypted_chunk
    decrypted_chunk = decrypt_chunk(encrypted_chunk)
    assert chunk == decrypted_chunk

#
# file formats (v0 and v1) and the stream API
#

import io
import os
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from saq.crypto import (
    CHUNK_SIZE,
    FORMAT_V0,
    FORMAT_V1,
    MAGIC,
    V1_HEADER_SIZE,
    IntegrityError,
    KeyMismatchError,
    UnsupportedFormatError,
    _get_password,
    decrypt,
    decrypt_stream,
    encrypt,
    encrypt_stream,
    get_key_id,
)


def _frozen_v0_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """A copy of what encrypt() did before the v1 format existed. Kept frozen here so that the test
    proves the new code reads files the OLD code wrote, not files the new code says are v0."""
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)
    encryptor.finalize()
    return struct.pack('<Q', len(plaintext)) + nonce + ciphertext + encryptor.tag


def _frozen_v0_decrypt(data: bytes, key: bytes) -> bytes:
    """A copy of what decrypt() did before the v1 format existed (without the file plumbing)."""
    original_size = struct.unpack('<Q', data[:8])[0]
    nonce = data[8:20]
    tag = data[-16:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    return (decryptor.update(data[20:-16]) + decryptor.finalize())[:original_size]


class _NonSeekable(io.RawIOBase):
    """A read-only stream that refuses to seek, like a pipe."""
    def __init__(self, data: bytes):
        self._buffer = io.BytesIO(data)

    def readable(self):
        return True

    def seekable(self):
        return False

    def readinto(self, b):
        chunk = self._buffer.read(len(b))
        b[:len(chunk)] = chunk
        return len(chunk)


@pytest.mark.unit
@pytest.mark.parametrize("size", [0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 3 * CHUNK_SIZE + 17])
def test_v0_files_written_by_old_code_still_decrypt(tmp_path, size):
    plaintext = os.urandom(size)
    source = tmp_path / "old.e"
    source.write_bytes(_frozen_v0_encrypt(plaintext, _get_password()))

    target = tmp_path / "out"
    result = decrypt(str(source), str(target))
    assert target.read_bytes() == plaintext
    assert result.format_version == FORMAT_V0
    assert result.key_id is None
    assert result.size == size


@pytest.mark.unit
def test_encrypt_still_writes_v0_for_existing_callers(tmp_path):
    plaintext = os.urandom(CHUNK_SIZE + 5)
    source = tmp_path / "plain"
    source.write_bytes(plaintext)
    target = tmp_path / "plain.e"

    result = encrypt(str(source), str(target))
    data = target.read_bytes()
    assert result.format_version == FORMAT_V0
    assert result.stored_size == len(data) == 8 + 12 + len(plaintext) + 16
    # the first 8 bytes are the little-endian size, so byte 7 is zero
    assert struct.unpack('<Q', data[:8])[0] == len(plaintext)
    assert data[7] == 0
    assert not data.startswith(MAGIC)
    # and the OLD decoder reads it
    assert _frozen_v0_decrypt(data, _get_password()) == plaintext


@pytest.mark.unit
def test_v1_round_trip_and_header_layout(tmp_path):
    plaintext = os.urandom(2 * CHUNK_SIZE + 3)
    encrypted = io.BytesIO()
    result = encrypt_stream(io.BytesIO(plaintext), encrypted, size=len(plaintext))
    data = encrypted.getvalue()

    assert result.format_version == FORMAT_V1
    assert result.key_id == get_key_id()
    assert len(result.key_id) == 16
    assert result.size == len(plaintext)
    assert result.stored_size == len(data) == V1_HEADER_SIZE + len(plaintext) + 16

    assert data[:7] == MAGIC
    assert data[7] == FORMAT_V1
    assert data[8:16].hex() == get_key_id()
    assert struct.unpack('<Q', data[16:24])[0] == len(plaintext)

    decrypted = io.BytesIO()
    result = decrypt_stream(io.BytesIO(data), decrypted)
    assert decrypted.getvalue() == plaintext
    assert result.format_version == FORMAT_V1
    assert result.key_id == get_key_id()
    assert result.size == len(plaintext)


@pytest.mark.unit
def test_encrypt_stream_defaults_to_v1_and_infers_size_from_seekable_source():
    plaintext = b"hello"
    encrypted = io.BytesIO()
    result = encrypt_stream(io.BytesIO(plaintext), encrypted)
    assert result.format_version == FORMAT_V1
    assert encrypted.getvalue().startswith(MAGIC)


@pytest.mark.unit
def test_encrypt_stream_requires_size_for_non_seekable_source():
    with pytest.raises(ValueError):
        encrypt_stream(_NonSeekable(b"hello"), io.BytesIO())


@pytest.mark.unit
def test_encrypt_stream_rejects_wrong_size():
    with pytest.raises(ValueError):
        encrypt_stream(io.BytesIO(b"hello"), io.BytesIO(), size=4)


@pytest.mark.unit
def test_decrypt_stream_reads_non_seekable_source():
    plaintext = os.urandom(CHUNK_SIZE + 1)
    encrypted = io.BytesIO()
    encrypt_stream(io.BytesIO(plaintext), encrypted, size=len(plaintext))
    decrypted = io.BytesIO()
    decrypt_stream(_NonSeekable(encrypted.getvalue()), decrypted)
    assert decrypted.getvalue() == plaintext


@pytest.mark.unit
@pytest.mark.parametrize("offset,error", [
    (7, UnsupportedFormatError),   # version byte
    (8, KeyMismatchError),         # key id
    (16, IntegrityError),          # size (authenticated)
    (24, IntegrityError),          # nonce (authenticated)
    (V1_HEADER_SIZE + 10, IntegrityError),  # ciphertext
    (-1, IntegrityError),          # tag
])
def test_v1_tampering_is_detected(tmp_path, offset, error):
    plaintext = os.urandom(CHUNK_SIZE + 100)
    encrypted = io.BytesIO()
    encrypt_stream(io.BytesIO(plaintext), encrypted, size=len(plaintext))
    data = bytearray(encrypted.getvalue())
    # 0x02 rather than 0x01: clearing the low bit of the version byte would make a valid v0 prefix
    data[offset] ^= 0x02
    source = tmp_path / "tampered.e"
    source.write_bytes(bytes(data))
    target = tmp_path / "out"

    with pytest.raises(error):
        decrypt(str(source), str(target))

    # nothing was released and nothing was left behind
    assert not target.exists()
    assert [p.name for p in tmp_path.iterdir()] == ["tampered.e"]


@pytest.mark.unit
def test_v0_tampering_is_detected_and_releases_nothing(tmp_path):
    plaintext = os.urandom(CHUNK_SIZE + 100)
    data = bytearray(_frozen_v0_encrypt(plaintext, _get_password()))
    data[20 + 50] ^= 0x01
    source = tmp_path / "tampered.e"
    source.write_bytes(bytes(data))
    target = tmp_path / "out"

    with pytest.raises(IntegrityError):
        decrypt(str(source), str(target))

    assert not target.exists()
    assert [p.name for p in tmp_path.iterdir()] == ["tampered.e"]


@pytest.mark.unit
def test_truncated_data_is_an_integrity_error():
    plaintext = os.urandom(100)
    encrypted = io.BytesIO()
    encrypt_stream(io.BytesIO(plaintext), encrypted, size=len(plaintext))
    data = encrypted.getvalue()
    for cut in (4, V1_HEADER_SIZE - 1, V1_HEADER_SIZE + 5, len(data) - 1):
        with pytest.raises(IntegrityError):
            decrypt_stream(io.BytesIO(data[:cut]), io.BytesIO())


@pytest.mark.unit
def test_decrypt_in_place(tmp_path):
    plaintext = os.urandom(1000)
    path = tmp_path / "file"
    path.write_bytes(plaintext)
    encrypt(str(path), str(tmp_path / "file.e"), format_version=FORMAT_V1)
    os.replace(tmp_path / "file.e", path)
    assert path.read_bytes() != plaintext

    decrypt(str(path))
    assert path.read_bytes() == plaintext
    assert [p.name for p in tmp_path.iterdir()] == ["file"]


@pytest.mark.unit
def test_encrypt_with_explicit_password_uses_that_key():
    plaintext = b"secret"
    encrypted = io.BytesIO()
    result = encrypt_stream(io.BytesIO(plaintext), encrypted, size=len(plaintext), password="other")
    assert result.key_id == get_key_id("other")
    assert result.key_id != get_key_id()

    # the system key does not decrypt it, and says so by key id before touching the ciphertext
    with pytest.raises(KeyMismatchError) as e:
        decrypt_stream(io.BytesIO(encrypted.getvalue()), io.BytesIO())
    assert e.value.header_key_id == get_key_id("other")
    assert e.value.current_key_id == get_key_id()

    decrypted = io.BytesIO()
    decrypt_stream(io.BytesIO(encrypted.getvalue()), decrypted, password="other")
    assert decrypted.getvalue() == plaintext


@pytest.mark.unit
def test_key_id_is_stable_and_key_specific():
    assert get_key_id() == get_key_id()
    assert get_key_id("a") == get_key_id("a")
    assert get_key_id("a") != get_key_id("b")
    assert len(get_key_id()) == 16
    int(get_key_id(), 16)
