import fcntl
import logging
import os
import re
import shlex
import shutil
import tempfile

from saq.environment import get_base_dir, get_temp_dir

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

def safe_file_name(file_name):
    """Returns a file name with all path separator and directory traversal replaced with underscores."""
    return re.sub('_+', '_', file_name.replace('\\', '_').replace('../', '_').replace('/', '_').replace('~', '_'))

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

def safe_filename(s):

    def _safe_char(c):
        # we want . for file ext and / for dir path, but ...
        if c.isalnum() or c == '/' or c == '.':
            return c
        else:
            return "_"

    # make sure we don't allow parent dir
    return ("".join(_safe_char(c) for c in s).rstrip("_")).replace('..', '_') # turn parent dir into bemused face

def get_local_file_path(root, _file):
    """Return the local (full) file path for a given F_FILE type indicator from the given analysis."""
    from saq.observables.file import FileObservable
    assert isinstance(_file, FileObservable)
    return _file.full_path