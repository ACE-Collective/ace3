import fcntl
import hashlib
import logging
import os
import re
import shlex
import shutil
import tempfile

from saq.environment import get_base_dir, get_temp_dir

# Per-component byte limit on ext4/xfs and most Linux filesystems.
NAME_MAX_BYTES = 255

def delete_file(path: str) -> bool:
    try:
        os.unlink(path)
        return True
    except Exception as e:
        logging.error(f"unable to delete file {path}: {e}")
        return False

def create_directory(path):
    """Creates the given directory and returns the path."""
    if not os.path.isdir(path):
        os.makedirs(path)

    return path

def create_temporary_directory() -> str:
    """Creates a temporary directory and returns the path using mktempd with get_temp_dir() as the base directory."""
    return tempfile.mkdtemp(dir=get_temp_dir())

# XXX rename to remove_directory_and_ignore_errors
def remove_directory(path):
    """Executes shutil.rmtree in a try catch block."""
    try:
        shutil.rmtree(path)
    except Exception as e:
        logging.error(f"unable to delete directory {path}: {e}")

def abs_path(path):
    """Given a path, return SAQ_HOME/path if path is relative, or path if path is absolute."""
    if os.path.isabs(path):
        return path

    return os.path.join(get_base_dir(), path)

RE_NT_DRIVE_LETTER = re.compile(r'^[a-zA-Z]:.+$')
RE_NT_UNC_PATH = re.compile(r'^\\\\[^\\]+\\.+$')
INVALID_WINDOWS_CHARS = [ '<', '>', ':', '"', '/', '\\', '|', '?', '*' ]
RE_NT_INVALID_CHARS = re.compile('[<>:"/\\|?*]')

def is_nt_path(path):
    """Returns True if the given path is clearly an NT (Windows) path.
       Returns False if it could possibly not be."""

    drive_letter = RE_NT_DRIVE_LETTER.match(path)
    unc = RE_NT_UNC_PATH.match(path)

    if not drive_letter and not unc:
        return False

    target = path
    if drive_letter:
        target = path[2:]

    if RE_NT_INVALID_CHARS.search(target):
        return False

    return True

RE_ESCAPED_QUOTED_DRIVE_PATH = re.compile(r'\\"([a-zA-Z]:[^"]*?)\\"')
RE_ESCAPED_QUOTED_UNC_PATH = re.compile(r'\\"(\\\\[^\\]+\\[^"]*?)\\"')
RE_QUOTED_DRIVE_PATH = re.compile(r'(?<!\\)"([a-zA-Z]:[^"]*?)(?<!\\)"')
RE_QUOTED_UNC_PATH = re.compile(r'(?<!\\)"(\\\\[^\\]+\\[^"]*?)(?<!\\)"')

def find_nt_paths_in_text(text):
    """Find Windows file paths in arbitrary text using regex.

    This handles paths embedded in script bodies where shlex tokenization fails,
    such as PowerShell -Command arguments with escaped quotes (\\"...\\").
    """
    paths = []
    seen = set()

    for pattern in [RE_ESCAPED_QUOTED_DRIVE_PATH, RE_ESCAPED_QUOTED_UNC_PATH,
                    RE_QUOTED_DRIVE_PATH, RE_QUOTED_UNC_PATH]:
        for match in pattern.finditer(text):
            path = match.group(1)
            if path not in seen and is_nt_path(path):
                paths.append(path)
                seen.add(path)

    return paths


def is_path_under(path: str, root: str) -> bool:
    """True when path really resolves to root or somewhere inside it, symlinks followed."""
    real_root = os.path.realpath(root)
    return os.path.commonpath([real_root, os.path.realpath(path)]) == real_root

def unique_file_path(path: str) -> str:
    """Returns path, or when something already exists there, the first free <name>_NNN<ext> next to it."""
    if not os.path.lexists(path):
        return path

    stem, ext = os.path.splitext(path)
    index = 0
    while os.path.lexists(f"{stem}_{index:03}{ext}"):
        index += 1

    return f"{stem}_{index:03}{ext}"

def extract_windows_filepaths(command_line):
    """Given a command line, extract any file paths found inside of it and return a list of them."""
    result = []
    for token in shlex.split(command_line, posix=False):
        # remove surrounding quotes if they exist
        while token.startswith('"') and token.endswith('"'):
            token = token[1:-1]

        if not is_nt_path(token):
            continue

        result.append(token)

    return result

# class for opening files after securing a lock
class atomic_open:
    def __init__(self, path, *args, **kwargs):
        self.lock_file = open(f"{path}.lock", 'w')
        fcntl.lockf(self.lock_file, fcntl.LOCK_EX)
        self.file = open(path, *args, **kwargs)

    def __enter__(self, *args, **kwargs):
        return self.file

    def __exit__(self, exc_type=None, exc_value=None, traceback=None):        
        self.file.close()
        fcntl.lockf(self.lock_file, fcntl.LOCK_UN)
        self.lock_file.close()

RE_MIME_TYPE_COMMENT = re.compile(r"^\s*#")
def map_mimetype_to_file_ext(target_mime_type: str, default="bin") -> str:
    """Returns a file extension for the given mime type, or default if none is found.
    Uses the data provided to the public domain curl http://svn.apache.org/repos/asf/httpd/httpd/trunk/docs/conf/mime.types"""
    with open(os.path.join(get_base_dir(), "etc", "mime.types")) as fp:
        for line in fp:
            line = line.strip()
            if RE_MIME_TYPE_COMMENT.search(line):
                continue

            split_line = line.split()
            mime_type, file_extensions = (split_line[0], split_line[1:])
            if mime_type != target_mime_type:
                continue

            # if there is a match then just return the file extension
            return file_extensions[0]

    return default

def shorten_basename_for_suffix(basename: str, suffix: str, max_bytes: int = NAME_MAX_BYTES) -> str:
    """Return ``basename + suffix``, truncating ``basename`` so the result fits within
    ``max_bytes`` when UTF-8 encoded.

    When truncation is needed, an 8-char sha1 of the original basename is interpolated
    before the suffix so distinct inputs that share a truncated prefix do not collide.
    Output is deterministic — the same input always produces the same output, so callers
    that retry analysis hit the same path."""
    assert os.sep not in basename, "shorten_basename_for_suffix expects a bare basename"

    combined = basename + suffix
    if len(combined.encode("utf-8")) <= max_bytes:
        return combined

    digest = hashlib.sha1(basename.encode("utf-8")).hexdigest()[:8]
    tail = f".{digest}{suffix}"
    available = max_bytes - len(tail.encode("utf-8"))
    if available < 0:
        available = 0

    truncated_bytes = basename.encode("utf-8")[:available]
    truncated_stem = truncated_bytes.decode("utf-8", errors="ignore")
    return f"{truncated_stem}{tail}"

def get_local_file_path(root, _file):
    """Return the local (full) file path for a given F_FILE type indicator from the given analysis."""
    from saq.observables.file import FileObservable
    assert isinstance(_file, FileObservable)
    return _file.full_path