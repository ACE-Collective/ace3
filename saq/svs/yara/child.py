"""Compiles one commit's YARA rules the way the yara service does and scans the replayed samples
with them. This file runs inside the Landlock sandbox (saq/sandbox/), as

    <venv>/bin/python3 -I child.py <workdir>

so it imports nothing from ACE (the sandbox cannot read SAQ_HOME): only the standard library, yara
and yara_scanner, whose import applies the same yara.set_config() limits it does in the service. It
reads job.json from the working directory and writes result.json there.

Compiling follows YaraScanner.compile_and_load_rules (yara_scanner 3.0.0), which the yara service
runs when it starts a generation, through yara.compile() directly so that the errors and the
compiler warnings are kept rather than logged:

1. every rule file is compiled on its own, with the library's include callback (an include that
   cannot be read becomes "" and is reported). A file that fails is dropped with its rules;
2. the surviving files are compiled together, one source per namespace keyed by the namespace's
   directory. If that fails, the ruleset would not load and the service keeps its previous
   generation, so nothing is scanned.

Then each namespace is compiled on its own and every sample is scanned with it, which is what
times each namespace. Namespaces are independent in YARA (a global rule applies only to its own
namespace), so the union of the per-namespace matches is what the combined rules would match.
Each match call goes through YaraScanner.scan(), so the path externals, the meta filters
(file_ext, file_name, mime_type, meta_tags, ...) and the timeout behave as in the service.
"""

import json
import logging
import os
import sys
import time
from typing import Optional

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


class Compiler:
    def __init__(self, tree_root: str):
        self.tree_root = os.path.realpath(tree_root)
        self.current_file_path: Optional[str] = None
        self.include_warnings: list[dict] = []
        # every file was compiled on its own first, so its includes are reported once, from there
        self.report_includes = True

    def include_callback(self, requested_filename: str, filename: Optional[str], namespace: str) -> str:
        """YaraScanner.compile_and_load_rules' callback, which also reports a failed include."""
        if namespace != "default":
            dir_name = namespace
        elif filename is not None:
            dir_name = os.path.dirname(filename)
        else:
            dir_name = os.path.dirname(self.current_file_path)

        relative_path = os.path.join(dir_name, requested_filename)
        if self.report_includes and not _is_under(os.path.realpath(relative_path), self.tree_root):
            self.include_warnings.append({
                "file": self.current_file_path, "include": requested_filename,
                "error": "the include is outside the repository: it resolves differently in production"})

        try:
            with open(relative_path, "r") as fp:
                return fp.read()
        except Exception as e:
            if self.report_includes:
                self.include_warnings.append({
                    "file": self.current_file_path, "include": requested_filename, "error": _error_text(e)})
            return ""

    def compile_file(self, path: str) -> tuple[Optional[str], Optional[yara.Rules]]:
        """(source, rules) of one file compiled on its own. Raises UnicodeDecodeError for a file
        that is not UTF-8 text, and whatever yara.compile() raises."""
        self.current_file_path = path
        with open(path, "r", encoding="utf-8") as fp:
            source = fp.read()

        rules = yara.compile(source=source, externals=yara_scanner.DEFAULT_YARA_EXTERNALS,
                             include_callback=self.include_callback)
        return source, rules

    def compile_sources(self, sources: dict[str, str]) -> yara.Rules:
        self.current_file_path = None
        self.report_includes = False
        return yara.compile(sources=sources, externals=yara_scanner.DEFAULT_YARA_EXTERNALS,
                            include_callback=self.include_callback)


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


def run(workdir: str) -> dict:
    with open(os.path.join(workdir, JOB_FILE)) as fp:
        job = json.load(fp)

    if job.get("version") != PROTOCOL_VERSION:
        raise RuntimeError(f"job protocol version {job.get('version')} is not {PROTOCOL_VERSION}")

    compiler = Compiler(job["tree_root"])
    result = {
        "version": PROTOCOL_VERSION,
        "yara_python_version": yara.__version__,
        "yara_scanner_version": yara_scanner.__version__,
        "files": [],
        "ruleset_error": None,
        "warnings": [],
        "include_warnings": compiler.include_warnings,
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

    # 1. each file on its own
    sources: dict[str, list[str]] = {}
    for namespace in job["namespaces"]:
        for path in namespace["files"]:
            entry = {"path": path, "namespace": namespace["name"], "error": None, "rules": []}
            result["files"].append(entry)
            try:
                source, rules = compiler.compile_file(path)
            except UnicodeDecodeError as e:
                # the service reads a file before its try: this fails the whole load
                entry["error"] = _error_text(e)
                result["ruleset_error"] = f"{path} is not UTF-8 text, which fails the whole load"
                continue
            except Exception as e:
                entry["error"] = _error_text(e)
                continue

            entry["rules"] = _rule_entries(rules)
            sources.setdefault(keys[namespace["name"]], []).append(source)

    if result["ruleset_error"] is not None:
        return result

    # with no file left, this repository adds no rules; the service still loads the others
    joined = {directory: "\r\n".join(parts) for directory, parts in sources.items()}
    if not joined:
        return result

    # 2. the survivors together, as the service loads them
    start = time.monotonic()
    try:
        combined = compiler.compile_sources(joined)
    except Exception as e:
        result["ruleset_error"] = _error_text(e)
        return result

    result["warnings"] = list(combined.warnings or [])
    result["combined_compile_seconds"] = time.monotonic() - start
    del combined

    # 3. each namespace on its own, scanning every unit
    scanner = yara_scanner.YaraScanner()
    for namespace in job["namespaces"]:
        key = keys[namespace["name"]]
        source = joined.get(key)
        if source is None:
            continue

        timing = {"compile_seconds": 0.0, "scan_seconds": 0.0, "rules": 0}
        result["namespaces"][namespace["name"]] = timing
        start = time.monotonic()
        scanner.rules = compiler.compile_sources({key: source})
        timing["compile_seconds"] = time.monotonic() - start
        timing["rules"] = sum(1 for _ in scanner.rules)

        start = time.monotonic()
        for unit in job["units"]:
            outcome = result["units"].setdefault(str(unit["id"]), {"matches": [], "errors": []})
            try:
                scanner.scan(unit["path"], timeout=job["file_timeout"], meta_tags=unit["meta_tags"] or None)
            except yara.TimeoutError as e:
                outcome["errors"].append({"namespace": namespace["name"], "type": "timeout", "message": _error_text(e)})
                continue
            except Exception as e:
                outcome["errors"].append({"namespace": namespace["name"], "type": "error", "message": _error_text(e)})
                continue

            for match in scanner.scan_results:
                outcome["matches"].append({
                    "namespace": namespace["name"],
                    "rule": match["rule"],
                    "meta": {key: _plain(value) for key, value in match["meta"].items()},
                })

        timing["scan_seconds"] = time.monotonic() - start
        _write_json(workdir, PROGRESS_FILE, {"namespaces": result["namespaces"]})

    return result


def main() -> int:
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    workdir = sys.argv[1]
    _write_json(workdir, RESULT_FILE, run(workdir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
