# vim: sw=4:ts=4:et:cc=120
#
# cryptography functions used by ACE
#

from getpass import getpass
import io
import logging
import os.path
import struct

from typing import Optional, Union

import os
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

class PasswordNotSetError(Exception):
    """Thrown when an attempt is made to load the encryption key but it has not been set."""
    pass

class InvalidPasswordError(Exception):
    """Thrown when an invalid password is provided."""
    pass

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
        return get_global_runtime_settings().encryption_key

    if isinstance(password, str):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode())
        return digest.finalize()

    if not isinstance(password, bytes) or len(password) != 32:
        raise ValueError("password must be 32 bytes")

    return password

def encrypt(source_path, target_path, password=None):
    """Encrypts the given file at source_path with the given password and saves the results in target_path.
       Uses AES-GCM for authenticated encryption. If password is None then the global encryption key is used.
       The header format is: <Q original_size> || <12-byte nonce> || <ciphertext> || <16-byte tag>."""

    password = _get_password(password)
    nonce = os.urandom(12)  # Recommended nonce size for GCM
    cipher = Cipher(algorithms.AES(password), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    file_size = os.path.getsize(source_path)

    with open(source_path, 'rb') as fp_in:
        with open(target_path, 'wb') as fp_out:
            # Write header: original size and nonce
            fp_out.write(struct.pack('<Q', file_size))
            fp_out.write(nonce)

            # Stream encrypt the file contents
            while True:
                chunk = fp_in.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                fp_out.write(encryptor.update(chunk))

            # Finalize and write authentication tag
            encryptor.finalize()
            fp_out.write(encryptor.tag)

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

def decrypt(source_path, target_path=None, password=None):
    """Decrypts the given file at source_path and writes plaintext to target_path.
       Expects AES-GCM format: <Q original_size> || <12-byte nonce> || <ciphertext> || <16-byte tag>."""

    password = _get_password(password)
    with open(source_path, 'rb') as fp_in:
        total_size = os.path.getsize(source_path)
        original_size = struct.unpack('<Q', fp_in.read(struct.calcsize('Q')))[0]
        nonce = fp_in.read(12)

        # Read authentication tag from end of file
        fp_in.seek(total_size - 16)
        tag = fp_in.read(16)

        # Prepare to read ciphertext only (exclude header and tag)
        ciphertext_length = total_size - struct.calcsize('Q') - 12 - 16
        fp_in.seek(struct.calcsize('Q') + 12)

        cipher = Cipher(algorithms.AES(password), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()

        with open(target_path, 'wb') as fp_out:
            remaining = ciphertext_length
            while remaining > 0:
                to_read = CHUNK_SIZE if remaining > CHUNK_SIZE else remaining
                chunk = fp_in.read(to_read)
                if not chunk:
                    break
                remaining -= len(chunk)
                fp_out.write(decryptor.update(chunk))

            # Finalize and truncate to original size
            decryptor.finalize()
            fp_out.truncate(original_size)

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
