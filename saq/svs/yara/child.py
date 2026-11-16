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

import json
import logging
import os
import sys
import time

import yara
import yara_scanner

PROTOCOL_VERSION = 2
JOB_FILE = "job.json"
RESULT_FILE = "result.json"
# rewritten after each namespace is scanned, so a run that times out still says how far it got
PROGRESS_FILE = "progress.json"

_ERROR_MAX_LENGTH = 2048


def _error_text(e: BaseException) -> str:
    return f"{type(e).__name__}: {e}"[:_ERROR_MAX_LENGTH]


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
    for namespace in job["namespaces"]:
        scanner = yara_scanner.YaraScanner()
        # the files the service loads, and the directory it holds their includes to, come from the
        # caller, which knows the layout. The library refuses an include that leaves the boundary
        # before reading it, as the service does, so nothing outside the tree is compiled in
        key = keys[namespace["name"]]
        scanner.tracked_dirs[key] = dict.fromkeys(namespace["files"])
        scanner.include_boundaries[key] = namespace["include_boundary"]
        start = time.monotonic()
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
