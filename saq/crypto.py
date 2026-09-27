# vim: sw=4:ts=4:et:cc=120
#
# cryptography functions used by ACE
#
# Two on-disk formats exist for files. Both are AES-256-GCM with a random 12-byte nonce and the
# 16-byte tag at the tail, and both are produced by the same code path (encrypt_stream):
#
#   v0  <Q original_size> || nonce(12) || ciphertext || tag(16)
#       No magic, no key id, header not authenticated. This is what every file written before the
#       v1 format existed looks like (email archive .gz.e, stream archives, msoffice .e archives),
#       and it is STILL what encrypt() writes by default: a lot of that data is read across nodes,
#       and a node running older code cannot read v1, so switching the default is a deliberate
#       later step once every node runs code that understands v1.
#
#   v1  b"ACE-GCM" || version(1) || key_id(8) || <Q original_size> || nonce(12) || ciphertext || tag(16)
#       The whole 36-byte header is bound as authenticated data. The key id is a fingerprint of the
#       data key, which is what makes rotating that key possible later without re-encrypting
#       everything at once. Opt-in through format_version; the CAS (saq/cas) writes v1.
#
# Detection is unambiguous: a v0 file starts with a little-endian size, so its byte 7 is 0x00 for
# any file smaller than 2**56 bytes; a v1 file has the magic there and a nonzero version byte.
#
# decrypt() never releases plaintext before the tag verifies: it decrypts into a temp file next to
# the target and renames only after finalize() succeeds. decrypt_stream() has the same contract in
# stream form -- it raises before returning on a bad tag, so the caller must write into something
# private and publish it only after a normal return.
#
# encrypt_chunk / decrypt_chunk use the v0 layout in memory. That layout is persisted in the
# database (the wrapped data key in `config`, every row of `encrypted_passwords`) and must not change.
#

from dataclasses import dataclass
from getpass import getpass
import hashlib
import io
import logging
import os
import os.path
import struct
import tempfile

from typing import BinaryIO, Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hmac

from saq.configuration.config import get_config
from saq.constants import INSTANCE_TYPE_DEV
from saq.environment import get_global_runtime_settings

CHUNK_SIZE = 64 * 1024

CONFIG_KEY_ENCRYPTION_KEY = 'encryption-key'
CONFIG_KEY_ENCRYPTION_SALT = 'encryption-salt'
CONFIG_KEY_ENCRYPTION_VERIFICATION = 'encryption-verification'
CONFIG_KEY_ENCRYPTION_ITERATIONS = 'encryption-iterations'

# file format constants (see the module docstring)
FORMAT_V0 = 0
FORMAT_V1 = 1
MAGIC = b"ACE-GCM"
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_ID_SIZE = 8              # raw bytes in the v1 header; the string form is its hex (16 chars)
_SIZE_FIELD = struct.Struct('<Q')
V0_HEADER_SIZE = _SIZE_FIELD.size + NONCE_SIZE                                   # 20
V1_HEADER_SIZE = len(MAGIC) + 1 + KEY_ID_SIZE + _SIZE_FIELD.size + NONCE_SIZE    # 36
_DETECT_SIZE = len(MAGIC) + 1                                                    # 8: enough to tell v0 from v1
_KEY_ID_DOMAIN = b"ace-key-id:"

class PasswordNotSetError(Exception):
    """Thrown when an attempt is made to load the encryption key but it has not been set."""
    pass

class InvalidPasswordError(Exception):
    """Thrown when an invalid password is provided."""
    pass

class CryptoError(Exception):
    """Base class for errors while reading or writing encrypted data."""
    pass

class IntegrityError(CryptoError):
    """The data failed authentication (bad tag, truncated, or a size that does not match the header)."""
    pass

class UnsupportedFormatError(CryptoError):
    """The data carries the v1 magic but a version this code does not understand."""
    pass

class KeyMismatchError(CryptoError):
    """The data was encrypted with a different key than the one available (by key id)."""
    def __init__(self, header_key_id: str, current_key_id: str):
        super().__init__(f"data was encrypted with key {header_key_id} but the loaded key is {current_key_id}")
        self.header_key_id = header_key_id
        self.current_key_id = current_key_id

@dataclass(frozen=True)
class EncryptResult:
    key_id: str            # fingerprint of the key the data was encrypted with (also for v0, where it is not stored)
    size: int              # plaintext bytes
    stored_size: int       # bytes written: header + ciphertext + tag
    format_version: int

@dataclass(frozen=True)
class DecryptResult:
    key_id: Optional[str]  # None for v0, which carries no key id
    size: int              # plaintext bytes written
    format_version: int

def is_encryption_initialized() -> bool:
    """Returns True if encryption has been initialized."""
    return get_global_runtime_settings().encryption_initialized

def encryption_key_set():
    """Returns True if the encryption key has been set, False otherwise."""
    from saq.configuration.database import get_database_config_value
    for key in [ 
        CONFIG_KEY_ENCRYPTION_KEY, 
        CONFIG_KEY_ENCRYPTION_SALT,
        CONFIG_KEY_ENCRYPTION_VERIFICATION,
        CONFIG_KEY_ENCRYPTION_ITERATIONS ]:
        if get_database_config_value(key) is None:
            return False

    return True

def get_decryption_key(password):
    """Returns the 32 byte key used to decrypt the encryption key.
       Raises InvalidPasswordError if the password is incorrect.
       Raises PasswordNotSetError if the password has not been set."""
    from saq.configuration.database import get_database_config_value

    if not encryption_key_set():
        raise PasswordNotSetError()

    # the salt and iterations used are stored when we set the password
    salt = get_database_config_value(CONFIG_KEY_ENCRYPTION_SALT, bytes)
    iterations = get_database_config_value(CONFIG_KEY_ENCRYPTION_ITERATIONS, int)
    target_verification = get_database_config_value(CONFIG_KEY_ENCRYPTION_VERIFICATION, bytes)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=iterations,
    )
    result = kdf.derive(password.encode() if isinstance(password, str) else password)
    if not hmac.compare_digest(target_verification, result[32:]):
        raise InvalidPasswordError()

    return result[:32]

def get_aes_key(password):
    """Returns the 32 byte system encryption key."""
    from saq.configuration.database import get_database_config_value
    decryption_key = get_decryption_key(password)
    encrypted_key = get_database_config_value(CONFIG_KEY_ENCRYPTION_KEY, bytes)
    return decrypt_chunk(encrypted_key, decryption_key)

def set_encryption_password(password, old_password=None, key=None):
    """Sets the encryption password for the system. If a password has already been set, then
       old_password can be provided to change the password. Otherwise, the old password is
       over-written by the new password.
       If the key parameter is None then the PRIMARY AES KEY is random. Otherwise, the given key is used.
       The default of a random key is fine."""

    from saq.configuration import set_database_config_value

    assert isinstance(password, str)
    assert old_password is None or isinstance(old_password, str)
    assert key is None or (isinstance(key, bytes) and len(key) == 32)

    # has the encryption password been set yet?
    if encryption_key_set():
        # did we provide a password for it?
        if old_password is not None:
            # get the existing encryption password
            get_global_runtime_settings().encryption_key = get_aes_key(old_password)

    if get_global_runtime_settings().encryption_key is None:
        # otherwise we just make a new one
        if key is None:
            get_global_runtime_settings().encryption_key = os.urandom(32)
        else:
            get_global_runtime_settings().encryption_key = key

    # now we compute the key to use to encrypt the encryption key using the user-supplied password
    salt = os.urandom(get_config().encryption.salt_size)
    iterations = get_config().encryption.iterations

    if iterations < 600000:
        logging.warning(f"encryption.iterations is less than 600000, this is not recommended for production use. iterations={iterations}")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=iterations,
    )
    result = kdf.derive(password.encode() if isinstance(password, str) else password)
    user_encryption_key = result[:32] # the first 32 bytes is the user encryption key
    verification_key = result[32:] # and the second 32 bytes is used for password verification
    set_database_config_value(CONFIG_KEY_ENCRYPTION_VERIFICATION, verification_key)
    encrypted_encryption_key = encrypt_chunk(get_global_runtime_settings().encryption_key, password=user_encryption_key)
    set_database_config_value(CONFIG_KEY_ENCRYPTION_KEY, encrypted_encryption_key)
    set_database_config_value(CONFIG_KEY_ENCRYPTION_SALT, salt)
    set_database_config_value(CONFIG_KEY_ENCRYPTION_ITERATIONS, iterations)

def _get_password(password: Optional[Union[bytes, str]]=None) -> bytes:
    if password is None:
        key = get_global_runtime_settings().encryption_key
        if key is None:
            raise PasswordNotSetError("the system encryption key is not loaded")

        return key

    if isinstance(password, str):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode())
        return digest.finalize()

    if not isinstance(password, bytes) or len(password) != 32:
        raise ValueError("password must be 32 bytes")

    return password

def _key_id_raw(key: bytes) -> bytes:
    # a domain-separated fingerprint of the key. 64 bits of sha256(prefix || key) does not help
    # recover a 256-bit random key, and it needs no stored state: every node that has the key
    # computes the same id.
    return hashlib.sha256(_KEY_ID_DOMAIN + key).digest()[:KEY_ID_SIZE]

def get_key_id(password: Optional[Union[bytes, str]]=None) -> str:
    """Returns the key id (16 hex chars) of the given key, or of the system key when password is None.
       This is what the v1 header carries and what cas_objects.key_id records."""
    return _key_id_raw(_get_password(password)).hex()

def encrypt_stream(src: BinaryIO, dst: BinaryIO, *, size: Optional[int]=None, password=None,
                   format_version: int=FORMAT_V1) -> EncryptResult:
    """Encrypts everything readable from src into dst. If password is None then the system key is used.

       size is the number of plaintext bytes and must be known before anything is written, because
       it is part of the (authenticated, for v1) header. If it is not given, src must be seekable.
       A source that yields a different number of bytes than size is an error, and dst is garbage.

       format_version selects the on-disk layout (see the module docstring). v1 is the default here;
       encrypt() defaults to v0 for the sake of existing consumers."""

    if format_version not in (FORMAT_V0, FORMAT_V1):
        raise ValueError(f"unknown format version {format_version}")

    key = _get_password(password)
    if size is None:
        if not src.seekable():
            raise ValueError("size is required when src is not seekable")

        position = src.tell()
        src.seek(0, io.SEEK_END)
        size = src.tell() - position
        src.seek(position)

    nonce = os.urandom(NONCE_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()

    if format_version == FORMAT_V1:
        header = MAGIC + bytes([FORMAT_V1]) + _key_id_raw(key) + _SIZE_FIELD.pack(size) + nonce
        encryptor.authenticate_additional_data(header)
    else:
        header = _SIZE_FIELD.pack(size) + nonce

    dst.write(header)
    written = 0
    while True:
        chunk = src.read(CHUNK_SIZE)
        if not chunk:
            break

        written += len(chunk)
        dst.write(encryptor.update(chunk))

    if written != size:
        raise ValueError(f"source yielded {written} bytes but size was given as {size}")

    encryptor.finalize()
    dst.write(encryptor.tag)
    return EncryptResult(
        key_id=_key_id_raw(key).hex(),
        size=size,
        stored_size=len(header) + size + TAG_SIZE,
        format_version=format_version)

def _read_exactly(src: BinaryIO, count: int) -> bytes:
    data = b''
    while len(data) < count:
        chunk = src.read(count - len(data))
        if not chunk:
            break

        data += chunk

    return data

def decrypt_stream(src: BinaryIO, dst: BinaryIO, *, password=None) -> DecryptResult:
    """Decrypts src (v0 or v1) into dst. If password is None then the system key is used.

       CONTRACT: dst receives plaintext as it is produced, and the tag is only checked at the end.
       This function raises IntegrityError before returning if the tag does not verify, so dst must
       be something private (a temp file, a hashing sink) that the caller only publishes after a
       normal return. decrypt() is the path-based wrapper that does exactly that.

       src does not need to be seekable: the tail tag is found with a 16-byte lookahead."""

    key = _get_password(password)
    prefix = _read_exactly(src, _DETECT_SIZE)
    if len(prefix) < _DETECT_SIZE:
        raise IntegrityError("encrypted data is truncated (shorter than a header)")

    if prefix[:len(MAGIC)] == MAGIC and prefix[len(MAGIC)] != 0:
        format_version = prefix[len(MAGIC)]
        if format_version != FORMAT_V1:
            raise UnsupportedFormatError(f"unsupported encrypted file format version {format_version}")

        rest = _read_exactly(src, V1_HEADER_SIZE - _DETECT_SIZE)
        if len(rest) < V1_HEADER_SIZE - _DETECT_SIZE:
            raise IntegrityError("encrypted data is truncated (shorter than a v1 header)")

        header = prefix + rest
        header_key_id = header[_DETECT_SIZE:_DETECT_SIZE + KEY_ID_SIZE]
        expected_key_id = _key_id_raw(key)
        if not hmac.compare_digest(header_key_id, expected_key_id):
            raise KeyMismatchError(header_key_id.hex(), expected_key_id.hex())

        offset = _DETECT_SIZE + KEY_ID_SIZE
        expected_size = _SIZE_FIELD.unpack_from(header, offset)[0]
        nonce = header[offset + _SIZE_FIELD.size:]
        key_id = header_key_id.hex()
    else:
        format_version = FORMAT_V0
        rest = _read_exactly(src, V0_HEADER_SIZE - _DETECT_SIZE)
        if len(rest) < V0_HEADER_SIZE - _DETECT_SIZE:
            raise IntegrityError("encrypted data is truncated (shorter than a v0 header)")

        header = prefix + rest
        # the v0 size field is not authenticated and GCM has no padding, so the ciphertext length
        # already is the plaintext length: the field is not used for anything
        expected_size = None
        nonce = header[_SIZE_FIELD.size:]
        key_id = None

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    decryptor = cipher.decryptor()
    if format_version == FORMAT_V1:
        decryptor.authenticate_additional_data(header)

    # everything after the header is ciphertext except the last TAG_SIZE bytes, which we only know
    # we have reached when the source runs dry, so keep TAG_SIZE bytes of lookahead
    pending = b''
    written = 0
    while True:
        chunk = src.read(CHUNK_SIZE)
        if not chunk:
            break

        pending += chunk
        if len(pending) > TAG_SIZE:
            ciphertext, pending = pending[:-TAG_SIZE], pending[-TAG_SIZE:]
            plaintext = decryptor.update(ciphertext)
            written += len(plaintext)
            dst.write(plaintext)

    if len(pending) < TAG_SIZE:
        raise IntegrityError("encrypted data is truncated (no authentication tag)")

    try:
        plaintext = decryptor.finalize_with_tag(pending)
    except InvalidTag as e:
        raise IntegrityError("authentication tag verification failed") from e

    if plaintext:
        written += len(plaintext)
        dst.write(plaintext)

    if expected_size is not None and written != expected_size:
        raise IntegrityError(f"decrypted {written} bytes but the header says {expected_size}")

    return DecryptResult(key_id=key_id, size=written, format_version=format_version)

def encrypt(source_path, target_path, password=None, *, format_version: int=FORMAT_V0) -> EncryptResult:
    """Encrypts the file at source_path with the given password and saves the result at target_path.
       Uses AES-GCM for authenticated encryption. If password is None then the system key is used.
       Writes the v0 layout unless format_version says otherwise (see the module docstring for why)."""

    with open(source_path, 'rb') as fp_in:
        with open(target_path, 'wb') as fp_out:
            return encrypt_stream(fp_in, fp_out, size=os.path.getsize(source_path), password=password,
                                  format_version=format_version)

def encrypt_chunk(chunk, password=None):
    """Encrypts the given chunk of data and returns the encrypted chunk.
       Uses AES-GCM for authenticated encryption. If password is None then the global encryption key is used.
       Returns: <Q original_size> || <12-byte nonce> || <ciphertext> || <16-byte tag>."""

    password = _get_password(password)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(password), modes.GCM(nonce))
    encryptor = cipher.encryptor()

    original_size = len(chunk)

    ciphertext = encryptor.update(chunk)
    encryptor.finalize()
    tag = encryptor.tag

    result = struct.pack('<Q', original_size) + nonce + ciphertext + tag
    return result

def decrypt(source_path, target_path=None, password=None) -> DecryptResult:
    """Decrypts the file at source_path (v0 or v1) and writes the plaintext to target_path, or over
       source_path itself when target_path is None. Nothing is visible at target_path until the
       authentication tag has verified: plaintext goes to a temp file in the same directory, which
       is renamed into place on success and removed on any failure."""

    if target_path is None:
        target_path = source_path

    target_dir = os.path.dirname(os.path.abspath(target_path))
    fd, temp_path = tempfile.mkstemp(dir=target_dir, prefix='.dec-')
    try:
        with open(source_path, 'rb') as fp_in:
            with os.fdopen(fd, 'wb') as fp_out:
                result = decrypt_stream(fp_in, fp_out, password=password)

        os.replace(temp_path, target_path)
        return result
    except BaseException:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass

        raise

def decrypt_chunk(chunk, password=None):
    """Decrypts an AES-GCM encrypted chunk produced by encrypt_chunk.
       Expects format: <Q original_size> || <12-byte nonce> || <ciphertext> || <16-byte tag>."""

    password = _get_password(password)
    _buffer = io.BytesIO(chunk)
    original_size = struct.unpack('<Q', _buffer.read(struct.calcsize('Q')))[0]
    nonce = _buffer.read(12)
    remaining = _buffer.read()

    if len(remaining) < 16:
        raise ValueError("encrypted chunk too short")

    ciphertext = remaining[:-16]
    tag = remaining[-16:]

    cipher = Cipher(algorithms.AES(password), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    result = decryptor.update(ciphertext) + decryptor.finalize()
    return result[:original_size]

def initialize_encryption(encryption_password_plaintext: Optional[str]=None, prompt_for_missing_password: Optional[bool]=False):
    try:
        # are we prompting for the decryption password?
        if encryption_password_plaintext:
            get_global_runtime_settings().encryption_key = get_aes_key(encryption_password_plaintext)
        elif prompt_for_missing_password:
            while True:
                encryption_password_plaintext = getpass("Enter the decryption password:")
                try:
                    get_global_runtime_settings().encryption_key = get_aes_key(encryption_password_plaintext)
                except InvalidPasswordError:
                    logging.error("invalid encryption password")
                    continue

                break

        elif encryption_key_set():
            # if we're not prompting for it then we can do one of two things
            # 1) pass it in via an environment variable SAQ_ENC
            # 2) run the encryption cache service 
            if "SAQ_ENC" in os.environ:
                logging.debug("reading encryption password from environment variable")
                encryption_password_plaintext = os.environ['SAQ_ENC']
                # Leave the SAQ_ENC variable in place if we are in the dev container environment.
                # This fixes the ability to load encrypted passwords when the container first starts up.
                if get_global_runtime_settings().instance_type != INSTANCE_TYPE_DEV:
                    del os.environ["SAQ_ENC"]

                #if encryption_password_plaintext == "test":
                    #logging.warning("Using default encryption key 'test'. This is not recommended for production use.")

            if encryption_password_plaintext is not None:
                try:
                    get_global_runtime_settings().encryption_key = get_aes_key(encryption_password_plaintext)
                except InvalidPasswordError:
                    logging.error("encryption password is wrong")
                finally:
                    encryption_password_plaintext = None

    except Exception as e:
        logging.error(f"unable to get encryption key: {e}")
        raise e

    get_global_runtime_settings().encryption_initialized = True
