"""Replaying the SVS corpus under two commits of a rule repository (docs/SVS.md, Part 2,
*Validation*).

run_replay() does one validation from start to finish, synchronously:

1. fetches the branches into SVS's mirror of the repository and exports both commits
   (saq.svs.yara.repository) into a private working directory;
2. reads the corpus and writes a plaintext copy of every sample it can (saq.svs.yara.corpus);
3. runs child.py in the Landlock sandbox once per commit, with no network, which compiles the
   rules the way the yara service does and scans every sample (saq.svs.yara.child);
4. reads each commit's rules from source for their uuids and content hashes
   (saq.signatures.loaders.yara.parse_rule_file);
5. compares the two scans against the labels (saq.svs.yara.diff).

The working directory holds every sample in plaintext and is deleted when the replay ends, whatever
happened. Nothing here writes to the database.
"""

import json
import logging
import os
import shutil
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from typing import Any, Optional

from saq.cas import get_cas
from saq.configuration.config import get_config, get_service_config
from saq.configuration.schema import SandboxConfig
from saq.constants import SERVICE_YARA_SCANNER
from saq.environment import get_data_dir
from saq.sandbox.runner import (
    build_sandbox_argv,
    create_workdir,
    landlock_available,
    run_sandboxed,
    sandbox_python,
    sweep_stale_workdirs,
)
from saq.signatures.git_context import GitContext
from saq.signatures.loaders.yara import parse_rule_file
from saq.svs.yara import child
from saq.svs.yara.corpus import Corpus, Skipped, read_corpus, write_units
from saq.svs.yara.diff import Category, ResultRow, RuleInfo, SideScan, diff, duplicate_uuids
from saq.svs.yara.layout import LayoutError, NotLoaded, RepoLayout, TreeLayout, resolve_layout, tree_layout
from saq.svs.yara.repository import Mirror, RepositoryError, is_valid_sha

# the magic database `file` reads for the mime_type filter; /etc/magic is outside the sandbox
_MAGIC_FILE = "/usr/lib/file/magic.mgc"

BASE = "base"
HEAD = "head"


class ReplayError(RuntimeError):
    """The replay could not run; the message is safe to show."""


@dataclass(frozen=True)
class RuleRef:
    uuid: Optional[str]
    name: str
    # relative to the repository root
    file: str


@dataclass(frozen=True)
class FileError:
    file: str
    namespace: str
    error: str
    # the rules (with a uuid) the file defines, which the service drops with it
    dropped: tuple[RuleRef, ...] = ()


@dataclass
class SideReport:
    """How one commit compiled, and how long its namespaces took."""
    sha: str
    namespaces: list[str] = field(default_factory=list)
    absent_namespaces: list[str] = field(default_factory=list)
    not_loaded: list[NotLoaded] = field(default_factory=list)
    # archive members the export refused: (path, reason)
    skipped_members: list[tuple[str, str]] = field(default_factory=list)
    file_errors: list[FileError] = field(default_factory=list)
    # set when the files that compile on their own do not compile together: the service would
    # keep its previous generation
    ruleset_error: Optional[str] = None
    warnings: list[str] = field(default_factory=list)
    include_warnings: list[dict] = field(default_factory=list)
    # namespace -> {compile_seconds, scan_seconds, rules}
    timings: dict[str, dict] = field(default_factory=dict)
    rule_count: int = 0

    @property
    def loads(self) -> bool:
        return self.ruleset_error is None


@dataclass
class ReplayResult:
    repository: str
    base_sha: str
    head_sha: str
    base: SideReport
    head: SideReport
    # False when either commit's ruleset would not load: nothing was compared
    diffed: bool = False
    rows: list[ResultRow] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    # rules whose source differs between the commits, by uuid
    added_rules: list[RuleRef] = field(default_factory=list)
    removed_rules: list[RuleRef] = field(default_factory=list)
    changed_rules: list[RuleRef] = field(default_factory=list)
    # head rules a label cannot follow: no uuid, or a uuid another rule shares
    not_testable: list[dict] = field(default_factory=list)
    # head rules that filter on full_path, which a replay cannot reproduce
    full_path_rules: list[RuleRef] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)
    truncated_paths: int = 0
    units: int = 0
    samples: int = 0
    files: int = 0
    bytes: int = 0
    duration_seconds: float = 0.0
    yara_python_version: Optional[str] = None
    yara_scanner_version: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["base"]["loads"] = self.base.loads
        result["head"]["loads"] = self.head.loads
        return result


def _relative(path: str, root: str) -> str:
    return os.path.relpath(path, root).replace(os.sep, "/")


def _sandbox_env(workdir: str) -> dict[str, str]:
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": workdir}
    if os.path.exists(_MAGIC_FILE):
        env["MAGIC"] = _MAGIC_FILE
    return env


def _check_work_root(root: str) -> None:
    # the extension external and the file_ext filter take everything after the last '.' of the
    # whole path, so a '.' above the sample changes them for a file name without one
    if "." in os.path.realpath(root):
        raise ReplayError(f"svs.yara.work_dir ({root}) has a '.' in its path")


def _export(mirror: Mirror, sha: str, dest: str) -> list[tuple[str, str]]:
    config = get_config().svs.yara
    os.makedirs(dest)
    result = mirror.export(sha, dest, max_bytes=config.max_archive_bytes, max_members=config.max_archive_members,
                           timeout=config.fetch_timeout_seconds)
    return result.skipped


def _resolve(mirror: Mirror, sha: str) -> str:
    resolved = mirror.resolve(sha)
    if resolved is None:
        # a branch that was rebased or deleted since the request no longer contains it
        try:
            mirror.fetch_commit(sha)
        except RepositoryError as e:
            logging.info("%s", e)
        resolved = mirror.resolve(sha)

    if resolved is None:
        raise ReplayError(f"commit {sha} is not in repository {mirror.name}: no fetched branch contains it, "
                          "and the server would not send it by id")

    return resolved


def _run_child(workdir: str, side_dir: str, tree: str, layout: TreeLayout, corpus: Corpus,
               sandbox_config: SandboxConfig) -> dict:
    job = {
        "version": child.PROTOCOL_VERSION,
        "tree_root": tree,
        "file_timeout": get_service_config(SERVICE_YARA_SCANNER).default_timeout,
        "namespaces": [
            {"name": namespace.name, "directory": namespace.directory, "files": namespace.files}
            for namespace in layout.namespaces
        ],
        "units": [
            {"id": unit.id, "path": unit.path, "meta_tags": list(unit.meta_tags)}
            for unit in corpus.units if unit.path is not None
        ],
    }
    with open(os.path.join(side_dir, child.JOB_FILE), "w") as fp:
        json.dump(job, fp)

    timeout = timedelta(seconds=get_config().svs.yara.scan_timeout_seconds)
    argv = build_sandbox_argv(
        [sandbox_python(), "-I", os.path.join(workdir, "child.py"), side_dir], workdir, sandbox_config, timeout)
    try:
        result = run_sandboxed(argv, None, _sandbox_env(workdir), workdir, timeout, sandbox_config.max_output_bytes)
    except RuntimeError as e:
        raise ReplayError(f"{e}{_progress(side_dir)}") from None

    if result.returncode != 0:
        raise ReplayError(f"the scan exited with {result.returncode}: {result.stderr.strip()[-2048:]}")

    with open(os.path.join(side_dir, child.RESULT_FILE)) as fp:
        output = json.load(fp)

    if output.get("version") != child.PROTOCOL_VERSION:
        raise ReplayError("the scan answered in another protocol version")

    return output


def _progress(side_dir: str) -> str:
    """How far a scan that was stopped got, for its error."""
    try:
        with open(os.path.join(side_dir, child.PROGRESS_FILE)) as fp:
            namespaces = json.load(fp)["namespaces"]
    except (OSError, ValueError, KeyError):
        return ""

    done = ", ".join(f"{name} {timing['scan_seconds']:.0f}s" for name, timing in namespaces.items())
    return f" (namespaces scanned: {done})"


def _source_rules(layout: TreeLayout, tree: str, sha: str) -> tuple[dict[str, list[RuleRef]], dict[str, set[str]]]:
    """The rules with a uuid in the commit's loaded files, read from source: file -> rules, and
    uuid -> content hashes."""
    context = GitContext(root=tree, git_remote=None, version=sha)
    by_file: dict[str, list[RuleRef]] = {}
    hashes: dict[str, set[str]] = {}
    for namespace in layout.namespaces:
        for path in namespace.files:
            relative = _relative(path, tree)
            try:
                signatures = parse_rule_file(path, context)
            except Exception as e:
                logging.info("unable to parse %s of %s: %s", relative, sha, e)
                continue

            by_file[relative] = [RuleRef(signature.uuid, signature.name, relative) for signature in signatures]
            for signature in signatures:
                hashes.setdefault(signature.uuid, set()).add(signature.content_hash)

    return by_file, hashes


def _side(sha: str, tree: str, layout: TreeLayout, skipped_members: list, output: dict,
          source_by_file: dict[str, list[RuleRef]], source_hashes: dict[str, set[str]]) -> tuple[SideReport, SideScan, list]:
    report = SideReport(
        sha=sha,
        namespaces=[namespace.name for namespace in layout.namespaces],
        absent_namespaces=list(layout.absent),
        not_loaded=list(layout.not_loaded),
        skipped_members=skipped_members,
        ruleset_error=output["ruleset_error"],
        warnings=list(output["warnings"]),
        include_warnings=[
            {**warning, "file": _relative(warning["file"], tree) if warning.get("file") else None}
            for warning in output["include_warnings"]
        ],
        timings=output["namespaces"],
        rule_count=sum(timing["rules"] for timing in output["namespaces"].values()))

    scan = SideScan(source_uuids=set(source_hashes))
    no_uuid = []
    for entry in output["files"]:
        relative = _relative(entry["path"], tree)
        if entry["error"] is not None:
            report.file_errors.append(FileError(
                relative, entry["namespace"], entry["error"], tuple(source_by_file.get(relative, ()))))
            continue

        for rule in entry["rules"]:
            rule_uuid = rule["meta"].get("uuid")
            rule_uuid = str(rule_uuid).strip() if rule_uuid else None
            if rule_uuid is None:
                if not rule["private"]:
                    no_uuid.append(RuleRef(None, rule["name"], relative))
                continue

            scan.loaded.setdefault(rule_uuid, []).append(
                RuleInfo(rule_uuid, rule["name"], entry["namespace"], relative, rule["meta"]))

    for unit_id, outcome in output["units"].items():
        scan.matches[int(unit_id)] = [(match["namespace"], match["rule"], match["meta"]) for match in outcome["matches"]]
        if outcome["errors"]:
            scan.errors[int(unit_id)] = {error["namespace"] for error in outcome["errors"]}

    return report, scan, no_uuid


def _first_ref(rule_uuid: str, scan: SideScan, by_file: dict[str, list[RuleRef]]) -> RuleRef:
    rules = scan.loaded.get(rule_uuid)
    if rules:
        return RuleRef(rule_uuid, rules[0].name, rules[0].file)

    for refs in by_file.values():
        for ref in refs:
            if ref.uuid == rule_uuid:
                return ref

    return RuleRef(rule_uuid, "", "")


def run_replay(repository: str, base_sha: str, head_sha: str, *, branch: Optional[str] = None,
               retired: frozenset[tuple[str, str]] = frozenset()) -> ReplayResult:
    """Validate head_sha against base_sha of the repository (a name in svs.yara.repositories).
    branch is the branch head_sha is on; the repository's configured branch is fetched too.
    retired holds the (sha256, rule uuid) pairs that are only counted. Raises ReplayError."""
    started = time.monotonic()
    config = get_config().svs.yara
    for sha in (base_sha, head_sha):
        if not is_valid_sha(sha):
            raise ReplayError(f"{sha!r} is not a commit id")

    try:
        repo_layout: RepoLayout = resolve_layout(repository)
    except LayoutError as e:
        raise ReplayError(str(e)) from None

    if not landlock_available():
        raise ReplayError("landlock is unavailable here, so the rules cannot be compiled and scanned")

    work_root = os.path.join(get_data_dir(), config.work_dir)
    _check_work_root(work_root)
    sweep_stale_workdirs(work_root)

    repo_config = get_config().get_git_repo_config(repository)
    mirror = Mirror(repository, repo_config, os.path.join(get_data_dir(), config.mirror_dir), config.fetch_timeout_seconds)

    with create_workdir(work_root) as workdir:
        trees = {}
        skipped_members = {}
        try:
            with mirror.lock():
                mirror.ensure([branch or repo_config.branch, repo_config.branch])
                resolved = {BASE: _resolve(mirror, base_sha), HEAD: _resolve(mirror, head_sha)}
                for side in (BASE, HEAD):
                    trees[side] = os.path.join(workdir, side, "tree")
                    skipped_members[side] = _export(mirror, resolved[side], trees[side])
        except RepositoryError as e:
            raise ReplayError(str(e)) from None

        corpus = read_corpus()
        write_units(corpus, get_cas().pool(get_config().svs.samples.pool), os.path.join(workdir, "u"))
        shutil.copyfile(child.__file__, os.path.join(workdir, "child.py"))

        reports, scans, no_uuid, source = {}, {}, {}, {}
        versions = {}
        for side in (BASE, HEAD):
            layout = tree_layout(repo_layout, trees[side])
            output = _run_child(workdir, os.path.join(workdir, side), trees[side], layout, corpus, config.sandbox)
            versions = {key: output.get(key) for key in ("yara_python_version", "yara_scanner_version")}
            source[side] = _source_rules(layout, trees[side], resolved[side])
            reports[side], scans[side], no_uuid[side] = _side(
                resolved[side], trees[side], layout, skipped_members[side], output, *source[side])

    result = ReplayResult(
        repository=repository, base_sha=resolved[BASE], head_sha=resolved[HEAD],
        base=reports[BASE], head=reports[HEAD], **versions)

    base_hashes, head_hashes = source[BASE][1], source[HEAD][1]
    result.added_rules = [_first_ref(u, scans[HEAD], source[HEAD][0]) for u in sorted(set(head_hashes) - set(base_hashes))]
    result.removed_rules = [_first_ref(u, scans[BASE], source[BASE][0]) for u in sorted(set(base_hashes) - set(head_hashes))]
    result.changed_rules = [
        _first_ref(u, scans[HEAD], source[HEAD][0])
        for u in sorted(set(base_hashes) & set(head_hashes)) if base_hashes[u] != head_hashes[u]
    ]

    source_counts = Counter(ref.uuid for refs in source[HEAD][0].values() for ref in refs)
    duplicates = duplicate_uuids(scans[HEAD], source_counts)
    result.not_testable = [
        {"uuid": None, "name": ref.name, "file": ref.file, "reason": "no uuid"} for ref in no_uuid[HEAD]
    ] + [
        {"uuid": rule_uuid, "name": ref.name, "file": ref.file, "reason": "uuid shared with another rule"}
        for rule_uuid in sorted(duplicates)
        for ref in [ref for refs in source[HEAD][0].values() for ref in refs if ref.uuid == rule_uuid]
    ]
    result.full_path_rules = [
        RuleRef(rule.uuid, rule.name, rule.file)
        for rules in scans[HEAD].loaded.values() for rule in rules
        if any(key.lower() == "full_path" for key in rule.meta)
    ]

    result.skipped = corpus.skipped
    result.truncated_paths = sum(1 for unit in corpus.units if unit.truncated and unit.path is not None)
    replayed = corpus.replayed_sha256s()
    result.units = sum(1 for unit in corpus.units if unit.path is not None)
    result.files = len(replayed)
    result.samples = sum(1 for sha256, _ in corpus.samples if sha256 in replayed)
    result.bytes = corpus.bytes

    result.diffed = result.base.loads and result.head.loads
    if result.diffed:
        result.rows, counts = diff(corpus, scans[BASE], scans[HEAD], retired=set(retired), not_testable=duplicates)
        result.counts = {category.value: counts.get(category, 0) for category in Category}

    result.duration_seconds = time.monotonic() - started
    return result
