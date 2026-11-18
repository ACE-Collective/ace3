import pytest

from saq.crypto import (
    CONFIG_KEY_ENCRYPTION_KEY,
    PasswordNotSetError,
    decrypt_chunk,
    encrypt_chunk,
    get_aes_key,
    set_encryption_password,
)

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


def _frozen_v1_decrypt(data: bytes, key: bytes) -> bytes:
    """The v1 layout as the module docstring of saq/crypto.py specifies it, written out here so that a
    change to the layout fails a test instead of changing the encoder and the decoder together."""
    header = data[:36]
    assert header[:7] == b"ACE-GCM"
    nonce = header[24:36]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, data[-16:]))
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(header)
    return decryptor.update(data[36:-16]) + decryptor.finalize()


# a raw 32-byte key and its key id, sha256(b"ace-key-id:" + key)[:8] computed outside ACE. Key ids
# are stored (cas_objects.key_id) and every node computes its own, so they are pinned as literals.
FIXED_KEY = bytes(range(32))
FIXED_KEY_ID = "a6caee7affc8dd1d"


@pytest.mark.integration
@pytest.mark.parametrize("chunk", [b"", b"1234567890"])
def test_encrypt_chunk_uses_the_v0_layout(chunk):
    # the wrapped data key in `config` and every row of encrypted_passwords are stored in it
    key = _get_password()
    encrypted = encrypt_chunk(chunk)
    assert len(encrypted) == 8 + 12 + len(chunk) + 16
    assert _frozen_v0_decrypt(encrypted, key) == chunk
    assert decrypt_chunk(_frozen_v0_encrypt(chunk, key)) == chunk
    assert decrypt_chunk(encrypted) == chunk


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
def test_v1_round_trip_and_header_layout():
    plaintext = os.urandom(2 * CHUNK_SIZE + 3)
    encrypted = io.BytesIO()
    result = encrypt_stream(io.BytesIO(plaintext), encrypted, size=len(plaintext), password=FIXED_KEY)
    data = encrypted.getvalue()

    assert result.format_version == 1
    assert result.key_id == FIXED_KEY_ID
    assert result.size == len(plaintext)
    assert result.stored_size == len(data) == 36 + len(plaintext) + 16

    assert data[:7] == b"ACE-GCM"
    assert data[7] == 1
    assert data[8:16].hex() == FIXED_KEY_ID
    assert struct.unpack('<Q', data[16:24])[0] == len(plaintext)
    assert _frozen_v1_decrypt(data, FIXED_KEY) == plaintext

    decrypted = io.BytesIO()
    result = decrypt_stream(io.BytesIO(data), decrypted, password=FIXED_KEY)
    assert decrypted.getvalue() == plaintext
    assert result.format_version == 1
    assert result.key_id == FIXED_KEY_ID
    assert result.size == len(plaintext)


@pytest.mark.unit
def test_encrypt_stream_defaults_to_v1_and_infers_size_from_seekable_source():
    # the size is what is left from the current position, not the whole stream
    source = io.BytesIO(b"skip:hello")
    source.seek(5)
    encrypted = io.BytesIO()
    result = encrypt_stream(source, encrypted)
    assert result.format_version == FORMAT_V1
    assert result.size == 5
    assert encrypted.getvalue().startswith(b"ACE-GCM")

    decrypted = io.BytesIO()
    decrypt_stream(io.BytesIO(encrypted.getvalue()), decrypted)
    assert decrypted.getvalue() == b"hello"


@pytest.mark.unit
def test_encrypt_stream_requires_size_for_non_seekable_source():
    # match: tell() on a stream that cannot seek raises io.UnsupportedOperation, a ValueError too
    with pytest.raises(ValueError, match="size is required"):
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
def test_encrypt_without_the_key_leaves_nothing_at_the_target(tmp_path, monkeypatch):
    # the email archive takes an existing target to mean the email is already archived
    source = tmp_path / "plain"
    source.write_bytes(b"plaintext")
    target = tmp_path / "plain.e"
    monkeypatch.setattr(get_global_runtime_settings(), "encryption_key", None)

    with pytest.raises(PasswordNotSetError):
        encrypt(str(source), str(target))

    assert not target.exists()
    assert [p.name for p in tmp_path.iterdir()] == ["plain"]


@pytest.mark.unit
def test_encrypt_that_fails_partway_leaves_the_old_target_alone(tmp_path, monkeypatch):
    source = tmp_path / "plain"
    source.write_bytes(os.urandom(CHUNK_SIZE * 3))
    target = tmp_path / "plain.e"
    target.write_bytes(b"what was there before")

    def _fail_partway(fp_in, fp_out, **kwargs):
        fp_out.write(b"part of the ciphertext")
        raise OSError("No space left on device")

    monkeypatch.setattr(saq.crypto, "encrypt_stream", _fail_partway)

    with pytest.raises(OSError):
        encrypt(str(source), str(target))

    assert target.read_bytes() == b"what was there before"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["plain", "plain.e"]


@pytest.mark.unit
@pytest.mark.parametrize("function", [encrypt, decrypt])
def test_a_missing_source_leaves_no_temp_file_or_open_descriptor(tmp_path, function):
    open_before = len(os.listdir("/proc/self/fd"))

    with pytest.raises(FileNotFoundError):
        function(str(tmp_path / "missing"), str(tmp_path / "out"))

    assert list(tmp_path.iterdir()) == []
    assert len(os.listdir("/proc/self/fd")) == open_before


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
def test_key_id_is_a_fixed_fingerprint_of_the_key():
    assert get_key_id(FIXED_KEY) == FIXED_KEY_ID
    # a string password is hashed into the key first; computed outside ACE the same way
    assert get_key_id("a") == "6e9b87c7735c3bf5"
    assert get_key_id("b") == "cd471495427846b0"


#
# initialize_encryption: how a process gets the system key at startup
#

import logging

import saq.crypto
from saq.configuration.database import delete_database_config_value
from saq.constants import INSTANCE_TYPE_DEV
from saq.crypto import get_decryption_key, initialize_encryption
from saq.environment import get_global_runtime_settings


@pytest.fixture
def unloaded_key(monkeypatch):
    """The system key as a process has it before initialize_encryption runs."""
    expected = get_aes_key("test")
    monkeypatch.setattr(get_global_runtime_settings(), "encryption_key", None)
    monkeypatch.setattr(get_global_runtime_settings(), "encryption_initialized", False)
    monkeypatch.delenv("SAQ_ENC", raising=False)
    return expected


@pytest.mark.integration
def test_initialize_encryption_with_the_password(unloaded_key):
    initialize_encryption(encryption_password_plaintext="test")

    assert get_global_runtime_settings().encryption_key == unloaded_key
    assert get_global_runtime_settings().encryption_initialized


@pytest.mark.integration
def test_initialize_encryption_prompts_until_the_password_is_right(unloaded_key, monkeypatch, caplog):
    answers = iter(["wrong", "test"])
    monkeypatch.setattr(saq.crypto, "getpass", lambda prompt: next(answers))

    with caplog.at_level(logging.ERROR):
        initialize_encryption(prompt_for_missing_password=True)

    assert get_global_runtime_settings().encryption_key == unloaded_key
    assert [r.getMessage() for r in caplog.records] == ["invalid encryption password"]


@pytest.mark.integration
def test_initialize_encryption_reads_and_removes_saq_enc(unloaded_key, monkeypatch):
    monkeypatch.setenv("SAQ_ENC", "test")

    initialize_encryption()

    assert get_global_runtime_settings().encryption_key == unloaded_key
    # nothing the process starts later inherits the password
    assert "SAQ_ENC" not in os.environ


@pytest.mark.integration
def test_initialize_encryption_keeps_saq_enc_in_the_dev_container(unloaded_key, monkeypatch):
    monkeypatch.setenv("SAQ_ENC", "test")
    monkeypatch.setattr(get_global_runtime_settings(), "instance_type", INSTANCE_TYPE_DEV)

    initialize_encryption()

    assert get_global_runtime_settings().encryption_key == unloaded_key
    assert os.environ["SAQ_ENC"] == "test"


@pytest.mark.integration
def test_initialize_encryption_with_a_wrong_saq_enc_leaves_the_key_unloaded(unloaded_key, monkeypatch, caplog):
    monkeypatch.setenv("SAQ_ENC", "wrong")

    with caplog.at_level(logging.ERROR):
        initialize_encryption()

    assert get_global_runtime_settings().encryption_key is None
    assert get_global_runtime_settings().encryption_initialized
    assert [r.getMessage() for r in caplog.records] == ["encryption password is wrong"]


@pytest.mark.integration
def test_initialize_encryption_without_a_password_leaves_the_key_unloaded(unloaded_key):
    initialize_encryption()

    assert get_global_runtime_settings().encryption_key is None
    assert get_global_runtime_settings().encryption_initialized


@pytest.mark.integration
def test_initialize_encryption_raises_what_it_cannot_handle(unloaded_key, monkeypatch, caplog):
    def _get_aes_key(password):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(saq.crypto, "get_aes_key", _get_aes_key)

    with caplog.at_level(logging.ERROR), pytest.raises(RuntimeError):
        initialize_encryption(encryption_password_plaintext="test")

    assert "unable to get encryption key: database unavailable" in caplog.text
    assert not get_global_runtime_settings().encryption_initialized


@pytest.mark.integration
def test_the_decryption_key_needs_a_password_set():
    delete_database_config_value(CONFIG_KEY_ENCRYPTION_KEY)

    with pytest.raises(PasswordNotSetError):
        get_decryption_key("test")


@pytest.mark.integration
def test_set_encryption_password_with_a_given_key(monkeypatch):
    key = os.urandom(32)
    monkeypatch.setattr(get_global_runtime_settings(), "encryption_key", None)

    set_encryption_password("other password", key=key)

    assert get_aes_key("other password") == key
