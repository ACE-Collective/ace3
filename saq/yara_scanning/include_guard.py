"""Keeps a YARA rule's ``include`` inside the signature directory it is compiled from.

**Why.** ACE compiles rules with yara-python (``yara.compile``) driven by the ``yara_scanner``
library. yara-python resolves an ``include "path"`` by handing the name to a callback that joins it
to a directory and opens whatever is there. ``yara_scanner`` does exactly that
(``YaraScanner.compile_and_load_rules``): an absolute path replaces the directory, ``../`` walks out
of it, and a symbolic link is followed. The included file is read in full; when it is not valid
YARA, yara-python's compile error quotes the offending token, which reaches a reader (the yara
service log, the SVS validation report shown to analysts, a scan match's ``rule_source``). So a rule
author who can push to the signatures repository could make the process that compiles the rules read
a file of its own -- a secret, ``/proc/self/environ`` -- and learn whether it exists, its path, and,
for some contents, a piece of it.

**The rule.** A rule file, and every file it includes, must be a regular file inside the signature
directory being compiled, reached through no symbolic link. An include that names an absolute path,
leaves the signature directory, or passes through a symbolic link is refused before anything is
opened. The refusal is the same whatever the target is, so it says nothing about whether a file is
there, and it never carries a byte of a file outside the directory. An include of another file
inside the signature directory still works, as it did before (``../other/common.yar`` reaching a
sibling rule set of the same signature directory included).

**How.** ``yara_scanner`` opens every rule file and every include with the module-level name
``open``. :func:`guard_includes` binds that name, for the duration of a compile, to a wrapper that
checks the path the library is about to read and refuses it unless it is a regular file inside the
signature directory reached through no link. Enforcing it at the read -- where the library has
already applied the including file's directory to resolve a relative include -- is what lets a
relative include keep working while an escape is stopped before any byte is read. The check that a
path leaves the directory, or is absolute, is pure path arithmetic and touches no filesystem, so it
cannot say whether the target exists; the symlink and regular-file checks run only once the path is
known to be inside the directory.

The sandboxed SVS replay (:mod:`saq.svs.yara.child`) cannot import this module -- it runs with no
access to ``SAQ_HOME`` -- so it carries its own copy of this guard. A change here is mirrored there.
"""

import contextlib
import logging
import os

log = logging.getLogger(__name__)


def _is_within(path: str, root: str) -> bool:
    """True when ``path`` is ``root`` or sits inside it. Pure string arithmetic: it opens nothing,
    so it reveals nothing about whether ``path`` exists."""
    return path == root or path.startswith(root + os.sep)


def is_allowed_read(path: str, signature_dir: str) -> bool:
    """Whether a rule file or include at ``path`` may be read while compiling ``signature_dir``: it
    is a regular file inside ``signature_dir``, reached through no symbolic link.

    ``signature_dir`` is the directory the caller handed the scanner; the library builds the paths
    it reads from it, so a relative include resolves against the same spelling. The containment test
    is done against that spelling (so a non-canonical signature directory still matches its own
    files), and the symlink and regular-file tests walk the real directory from there."""
    given = os.path.abspath(signature_dir)
    # the candidate re-expressed under the given signature directory; an absolute path or a `../`
    # escape lands outside and is refused by arithmetic alone, without touching the filesystem
    rel = os.path.relpath(os.path.abspath(path), given)
    candidate = os.path.normpath(os.path.join(given, rel))
    if not _is_within(candidate, given):
        return False

    # from here the path is known to be inside the signature directory, so these filesystem checks
    # disclose nothing outside it: no component may be a symbolic link, and the target must be a
    # regular file
    root = os.path.realpath(given)
    current = root
    tail = os.path.relpath(os.path.normpath(os.path.join(root, rel)), root)
    parts = [] if tail == os.curdir else tail.split(os.sep)
    for part in parts:
        current = os.path.join(current, part)
        if os.path.islink(current):
            return False
    try:
        return os.path.isfile(current) and not os.path.islink(current)
    except OSError:
        return False


@contextlib.contextmanager
def guard_includes(signature_dir: str):
    """While this context is open, ``yara_scanner`` may read only regular files inside
    ``signature_dir``, reached through no symbolic link. A read of anything else raises
    :class:`PermissionError`, which the library records as the include's error and compiles in its
    place as empty, exactly as it already treats an include it cannot read.

    Wrap the ``load_rules`` / ``compile_and_load_rules`` call with it. It binds ``yara_scanner.open``
    for the duration and restores it afterwards, so it must not be entered from two threads of one
    process at once (the yara service compiles one generation at a time, in a process of its own)."""
    import yara_scanner

    real_open = open
    had_own = "open" in yara_scanner.__dict__
    previous = yara_scanner.__dict__.get("open")

    def guarded_open(file, mode="r", *args, **kwargs):
        # only reads name a rule file or an include; a write (the compiled-rules cache) is left alone
        if isinstance(file, (str, bytes, os.PathLike)) and "w" not in mode and "a" not in mode and "x" not in mode:
            path = os.fspath(file)
            if isinstance(path, bytes):
                path = os.fsdecode(path)
            if not is_allowed_read(path, signature_dir):
                log.warning("refused a yara file read outside the signature directory %s: %s",
                            signature_dir, path, extra={"signature_dir": signature_dir, "path": path})
                raise PermissionError("include is outside the signature directory or not a regular file")
        return real_open(file, mode, *args, **kwargs)

    yara_scanner.open = guarded_open
    try:
        yield
    finally:
        if had_own:
            yara_scanner.open = previous
        else:
            yara_scanner.__dict__.pop("open", None)
