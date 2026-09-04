import hashlib
from io import DEFAULT_BUFFER_SIZE
import re

# the hashes of zero-length content
EMPTY_CONTENT_MD5 = hashlib.md5(b"").hexdigest()
EMPTY_CONTENT_SHA1 = hashlib.sha1(b"").hexdigest()
EMPTY_CONTENT_SHA256 = hashlib.sha256(b"").hexdigest()

def get_md5_hash_of_file(path:str) -> str:
    """Computes the MD5 hash of a file. Returns the string hex representation of the hash in lowercase."""
    assert isinstance(path, str)

    hasher = hashlib.md5()
    with open(path, "rb") as fp:
        while True:
            data = fp.read(DEFAULT_BUFFER_SIZE)
            if not data:
                break

            hasher.update(data)

    return hasher.hexdigest().lower()

def get_md5_hash_of_string(data:str) -> str:
    """Computes the MD5 hash of a string. Returns the string hex representation of the hash in lowercase."""
    assert isinstance(data, str)

    hasher = hashlib.md5()
    hasher.update(data.encode(errors="ignore"))
    return hasher.hexdigest().lower()

def sha256(path:str, chunk_size:int=32768) -> str:
    """ returns the sha256 of a file

    Args:
        path (str): the path to the file to hash
        chunk_size (int, optional): the number of bytes to read in at a time (default 32768)

    Returns:
        str: the sha256 hexdigest of the file
    """
    # hash the file in chunks to save memory
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            h.update(data)
    return h.hexdigest()

def sha256_file(path: str) -> str:
    return sha256(path)

def sha256_str(data: str) -> str:
    """Returns the sha256 of the given string."""
    hasher = hashlib.sha256()
    hasher.update(data.encode(errors="ignore"))
    return hasher.hexdigest()

def sha256_bytes(data: bytes) -> str:
    """Returns the sha256 of the given bytes."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()

RE_SHA256 = re.compile(r'^[a-f0-9]{64}$', re.I)
def is_sha256_hex(value: str) -> bool:
    """Returns True if the given string (can be) a sha256 hex string."""
    return RE_SHA256.match(value) is not None