"""Compiles one commit's YARA rules the way the yara service does and scans the replayed samples
with them. This file runs inside the Landlock sandbox (saq/sandbox/), as

    <venv>/bin/python3 -I child.py <workdir>

so it imports nothing from ACE (the sandbox cannot read SAQ_HOME): only the standard library, yara
and yara_scanner, whose import applies the same yara.set_config() limits it does in the service. It
reads job.json from the working directory and writes result.json there.

Each namespace is loaded by a YaraScanner of its own, with load_rules(), which is what the yara
service runs when it starts a generation: every rule file is compiled on its own and a file that
cannot be read or fails is dropped with its rules, then the files left are compiled together. What
it compiled comes from scanner.compiled_sources, so the errors, warnings and includes reported are
the library's own. If the files of a namespace do not compile together, the ruleset would not load
and the service keeps its previous generation, so nothing is scanned.

The service compiles all namespaces together, but namespaces are independent in YARA (a global rule
applies only to its own namespace), so a namespace compiles the same on its own and the union of
the per-namespace matches is what the combined rules would match. Compiling them apart is what
times each namespace. Each match call goes through YaraScanner.scan(), so the path externals, the
meta filters (file_ext, file_name, mime_type, meta_tags, ...) and the timeout behave as in the
service.
"""

import contextlib
import json
import logging
import os
import sys
import time

import yara
import yara_scanner

PROTOCOL_VERSION = 1
JOB_FILE = "job.json"
RESULT_FILE = "result.json"
# rewritten after each namespace is scanned, so a run that times out still says how far it got
PROGRESS_FILE = "progress.json"

_ERROR_MAX_LENGTH = 2048


def _error_text(e: BaseException) -> str:
    return f"{type(e).__name__}: {e}"[:_ERROR_MAX_LENGTH]


def _is_under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _is_allowed_read(path: str, signature_dir: str) -> bool:
    """Whether a rule file or include at ``path`` may be read while compiling ``signature_dir``: a
    regular file inside it, reached through no symbolic link. A copy of
    ``saq.yara_scanning.include_guard.is_allowed_read``; this file runs in the SVS sandbox and
    cannot import ACE, so a change there is mirrored here. Landlock already holds reads to the
    replay directory, so this is a second line that does not depend on it."""
    given = os.path.abspath(signature_dir)
    rel = os.path.relpath(os.path.abspath(path), given)
    candidate = os.path.normpath(os.path.join(given, rel))
    if not _is_under(candidate, given):
        return False  # absolute path or a `../` escape -- arithmetic only, no filesystem touch
    root = os.path.realpath(given)
    current = root
    tail = os.path.relpath(os.path.normpath(os.path.join(root, rel)), root)
    for part in [] if tail == os.curdir else tail.split(os.sep):
        current = os.path.join(current, part)
        if os.path.islink(current):
            return False
    try:
        return os.path.isfile(current) and not os.path.islink(current)
    except OSError:
        return False


@contextlib.contextmanager
def _guard_includes(signature_dir: str):
    """Hold yara_scanner's rule-file and include reads inside ``signature_dir`` for one compile, by
    binding its module-level ``open``. Mirrors ``saq.yara_scanning.include_guard.guard_includes``."""
    real_open = open
    had_own = "open" in yara_scanner.__dict__
    previous = yara_scanner.__dict__.get("open")

    def guarded_open(file, mode="r", *args, **kwargs):
        if isinstance(file, (str, bytes, os.PathLike)) and "w" not in mode and "a" not in mode and "x" not in mode:
            path = os.fspath(file)
            if isinstance(path, bytes):
                path = os.fsdecode(path)
            if not _is_allowed_read(path, signature_dir):
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


def _write_json(workdir: str, name: str, data: dict) -> None:
    path = os.path.join(workdir, name)
    with open(f"{path}.tmp", "w") as fp:
        json.dump(data, fp)
    os.replace(f"{path}.tmp", path)


def _plain(value):
    """A meta value as JSON can carry it."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="backslashreplace")
    return value


def _rule_entries(rules: yara.Rules) -> list[dict]:
    return [
        {
            "name": rule.identifier,
            "meta": {key: _plain(value) for key, value in rule.meta.items()},
            "tags": list(rule.tags),
            "private": bool(rule.is_private),
            "global": bool(rule.is_global),
        }
        for rule in rules
    ]


def _file_rules(compiled: yara_scanner.CompiledSource) -> list[dict]:
    """The rules of a file that compiled on its own, compiled again from the text the scanner read.
    Only needed when its namespace did not compile together, which leaves scanner.rules None."""
    # yara asks for the includes in the order it asked the first time
    includes = iter(compiled.includes)
    try:
        rules = yara.compile(source=compiled.source, externals=yara_scanner.DEFAULT_YARA_EXTERNALS,
                             include_callback=lambda *_: next(includes).source)
    except Exception:
        # it compiled the same way once, so this is not expected; the ruleset error is still
        # reported, and the rules are only listed for the report's diagnostics
        return []
    return _rule_entries(rules)


def run(workdir: str) -> dict:
    with open(os.path.join(workdir, JOB_FILE)) as fp:
        job = json.load(fp)

    if job.get("version") != PROTOCOL_VERSION:
        raise RuntimeError(f"job protocol version {job.get('version')} is not {PROTOCOL_VERSION}")

    result = {
        "version": PROTOCOL_VERSION,
        "yara_python_version": yara.__version__,
        "yara_scanner_version": yara_scanner.__version__,
        "files": [],
        "ruleset_error": None,
        "warnings": [],
        "include_warnings": [],
        "namespaces": {},
        "units": {},
    }

    # the yara namespace of each namespace: its directory, as the service names it. Two entries of
    # signature_dir can be the same directory, and are still two namespaces there; "/." keeps their
    # names apart and still resolves includes against the directory
    keys: dict[str, str] = {}
    for namespace in job["namespaces"]:
        key = namespace["directory"]
        while key in keys.values():
            key += "/."
        keys[namespace["name"]] = key

    # 1. load each namespace as the service does
    scanners: dict[str, yara_scanner.YaraScanner] = {}
    tree_root = os.path.realpath(job["tree_root"])
    for namespace in job["namespaces"]:
        scanner = yara_scanner.YaraScanner()
        # the files the service loads were listed by the caller, which knows the layout
        scanner.tracked_dirs[keys[namespace["name"]]] = dict.fromkeys(namespace["files"])
        start = time.monotonic()
        # an include is held inside the signature directory (the parent of the set directories, the
        # same boundary the yara service enforces); a sibling set's file still works, an escape does not
        with _guard_includes(os.path.dirname(os.path.realpath(namespace["directory"]))):
            scanner.load_rules()
        compile_seconds = time.monotonic() - start

        rules = {} if scanner.rules is None else {rule["name"]: rule for rule in _rule_entries(scanner.rules)}
        for compiled in scanner.compiled_sources:
            if scanner.rules is None and compiled.error is None:
                file_rules = _file_rules(compiled)
            else:
                file_rules = [rules[name] for name in compiled.rules if name in rules]
            result["files"].append({
                "path": compiled.path, "namespace": namespace["name"], "error": compiled.error,
                "rules": file_rules})
            for included in compiled.includes:
                if not _is_under(os.path.realpath(included.path), tree_root):
                    result["include_warnings"].append({
                        "file": compiled.path, "include": included.name,
                        "error": "the include is outside the repository: it resolves differently in production"})
                if included.error is not None:
                    result["include_warnings"].append(
                        {"file": compiled.path, "include": included.name, "error": included.error[:_ERROR_MAX_LENGTH]})

        if scanner.compile_error is not None:
            if result["ruleset_error"] is None:
                result["ruleset_error"] = scanner.compile_error[:_ERROR_MAX_LENGTH]
            continue

        # with no file left, this repository adds no rules to the namespace; the service still loads the others
        if not any(compiled.error is None for compiled in scanner.compiled_sources):
            continue

        result["warnings"].extend(scanner.rules.warnings or [])
        result["namespaces"][namespace["name"]] = {
            "compile_seconds": compile_seconds, "scan_seconds": 0.0, "rules": len(rules)}
        scanners[namespace["name"]] = scanner

    if result["ruleset_error"] is not None:
        return result

    # 2. scan every unit with each namespace
    for name, scanner in scanners.items():
        timing = result["namespaces"][name]
        start = time.monotonic()
        for unit in job["units"]:
            outcome = result["units"].setdefault(str(unit["id"]), {"matches": [], "errors": []})
            try:
                scanner.scan(unit["path"], timeout=job["file_timeout"], meta_tags=unit["meta_tags"] or None)
            except yara.TimeoutError as e:
                outcome["errors"].append({"namespace": name, "type": "timeout", "message": _error_text(e)})
                continue
            except Exception as e:
                outcome["errors"].append({"namespace": name, "type": "error", "message": _error_text(e)})
                continue

            for match in scanner.scan_results:
                outcome["matches"].append({
                    "namespace": name,
                    "rule": match["rule"],
                    "meta": {key: _plain(value) for key, value in match["meta"].items()},
                })

        timing["scan_seconds"] = time.monotonic() - start
        _write_json(workdir, PROGRESS_FILE, {"namespaces": result["namespaces"]})

    return result


def main() -> int:
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    # the library logs each file and include that fails, which the result already carries, and
    # output past the sandbox's cap stops the scan
    logging.getLogger("yara-scanner").setLevel(logging.CRITICAL)
    workdir = sys.argv[1]
    _write_json(workdir, RESULT_FILE, run(workdir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
