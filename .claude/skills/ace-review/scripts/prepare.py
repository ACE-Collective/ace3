#!/usr/bin/env python3
"""Collect everything /ace-review needs about one repo's change into a bundle directory.

    prepare.py --list
    prepare.py [--repo PATH] [--base REF | --range A..B] [--full] [--state-dir DIR]

Plain git only, so it works for core, signatures/ and integration repos hosted
anywhere. Every review of a branch is a round, in its own bundle directory
<state-dir>/<repo>-<branch>/round-<N>/ (state-dir defaults to $SAQ_HOME/local/ace-review).
A round counts as finished once findings.py has written its summary.json; an unfinished
one is redone in place. The bundle gets:

    target.json        repo, kind, base, merge-base, head, round, delta and rule changes;
                       printed on stdout as well
    diff.patch         the full diff from the merge-base, including uncommitted and
                       untracked work when reviewing the checked-out branch
    stat.txt           git diff --stat
    files.txt          changed files, one per line, "<status>\t<path relative to repo>"
    log.txt            commit subjects and bodies in the range
    tests.txt          pytest paths to run (as seen from SAQ_HOME, integration tests
                       through their tests/test_external_integration_<name> symlink)
    unmarked.txt       test functions in changed test files with no unit/integration/system marker
    cov_sources.txt    --cov arguments for the pytest run
    rules/CLAUDE.md    core's CLAUDE.md from the base, which the change is judged by
                       (rules/repo-CLAUDE.md is the reviewed repo's own, for a repo other
                       than core)
    rule-changes.patch what the change does to the CLAUDE.md rule sections or to the
                       skill itself, when it does anything
    leads.json         added lines that match a mechanical check, and doc lines that name a
                       path, function or config key the change removes
    previous.json      round 2 on: every finding of earlier rounds and its status, one of
                       open, fixed, dismissed (by the user's answer) or seen (nits and
                       pre-existing findings, never rechecked)
    delta.patch        round 2 on, when the merge-base hasn't moved: what changed since the
                       last finished round (delta-files.txt lists the files)
"""

import argparse
import ast
import codecs
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

SAQ_HOME = os.environ.get("SAQ_HOME", "/opt/ace")
RUN_MARKERS = {"unit", "integration", "system"}
SKILL_DIR = ".claude/skills/ace-review"
# the CLAUDE.md sections that state rules rather than facts about the code
RULE_SECTIONS = ("## Engineering values", "## Conventions")
DIFF_FLAGS = ["--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/", "-M"]
DISMISSING_ANSWERS = {"wrong", "intentional", "didn't matter"}
STALE_HITS_PER_REF = 10
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
LOGGER = re.compile(r"(^|_)(log|logger|logging)$", re.IGNORECASE)
WAIT_METHODS = {"join", "wait", "acquire", "communicate", "result"}
SUBPROCESS_CALLS = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output"}
HTTP_CALL = re.compile(r"(requests|httpx)\.(get|post|put|patch|delete|head|options|request)")
THREAD_HOPS = {"run_in_threadpool", "to_thread", "run_in_executor"}


def git(repo: str, *args: str, check: bool = True) -> str:
    result = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, errors="replace")
    if check and result.returncode != 0:
        sys.exit(f"git {' '.join(args)} failed in {repo}: {result.stderr.strip()}")
    return result.stdout


def show(repo: str, rev: str, path: str) -> str | None:
    """A file's content at a revision, or None where it doesn't exist there."""
    result = subprocess.run(["git", "-C", repo, "show", f"{rev}:{path}"], capture_output=True, text=True, errors="replace")
    return result.stdout if result.returncode == 0 else None


def load_json(path: str, default):
    if not os.path.exists(path):
        return default
    with open(path) as fp:
        return json.load(fp)


def toplevel(path: str) -> str:
    return git(path, "rev-parse", "--show-toplevel").strip()


def candidate_repos() -> list[str]:
    repos = [toplevel(SAQ_HOME)]
    sig = os.path.join(SAQ_HOME, "signatures")
    if os.path.isdir(sig):
        # a signatures/ without its own .git resolves to the core toplevel
        top = git(sig, "rev-parse", "--show-toplevel", check=False).strip()
        if top and top not in repos:
            repos.append(top)
    integrations = os.path.join(SAQ_HOME, "integrations")
    if os.path.isdir(integrations):
        # integrations/ may itself be one repo holding several integrations, or each
        # integration may be its own repo
        for path in sorted(integration_dirs(integrations)):
            top = git(path, "rev-parse", "--show-toplevel", check=False).strip()
            if top and top not in repos:
                repos.append(top)
    return repos


def detect_base(repo: str) -> str | None:
    head = git(repo, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD", check=False).strip()
    if head:
        return head.removeprefix("refs/remotes/")
    for ref in ("origin/main", "main", "origin/master", "master"):
        if git(repo, "rev-parse", "--verify", "--quiet", ref, check=False).strip():
            return ref
    return None


def repo_kind(repo: str) -> str:
    core = toplevel(SAQ_HOME)
    if repo == core:
        return "core"
    if repo.startswith(os.path.join(core, "signatures")):
        return "signatures"
    if repo.startswith(os.path.join(core, "integrations")):
        return "integration"
    return "other"


def integration_dirs(repo: str) -> list[str]:
    """Absolute paths of the integrations inside an integration repo.

    An integration is a directory holding integration.md, the same rule
    saq/integration/integration_util.py::get_valid_integration_dirs uses.
    """
    found = []
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "node_modules")]
        if "integration.md" in files:
            found.append(root)
            dirs[:] = []
    return found


def has_run_marker(decorators: list[ast.expr]) -> bool:
    for dec in decorators:
        node = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(node, ast.Attribute) and node.attr in RUN_MARKERS:
            return True
    return False


def module_marked(tree: ast.Module) -> bool:
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets):
            src = ast.unparse(node.value)
            if any(f"mark.{m}" in src for m in RUN_MARKERS):
                return True
    return False


def unmarked_tests(path: str, source: str | None) -> list[str]:
    try:
        tree = ast.parse(source or "")
    except (SyntaxError, ValueError) as e:
        return [f"{path}: could not parse ({e})"]
    if module_marked(tree):
        return []
    missing = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
            if not has_run_marker(node.decorator_list):
                missing.append(f"{path}:{node.lineno} {node.name}")
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            class_marked = has_run_marker(node.decorator_list)
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith("test"):
                    if not class_marked and not has_run_marker(item.decorator_list):
                        missing.append(f"{path}:{item.lineno} {node.name}.{item.name}")
    return missing


def saq_test_path(abs_path: str, integrations: list[str]) -> str | None:
    """Map a test file to the path pytest must be given, relative to SAQ_HOME."""
    for idir in integrations:
        tests_dir = os.path.join(idir, "tests")
        if abs_path.startswith(tests_dir + os.sep):
            link = os.path.join("tests", f"test_external_integration_{os.path.basename(idir)}")
            return os.path.join(link, os.path.relpath(abs_path, tests_dir))
    rel = os.path.relpath(abs_path, SAQ_HOME)
    return rel if rel.startswith("tests" + os.sep) else None


def mirrored_test(rel_path: str) -> str | None:
    """saq/foo/bar.py -> tests/saq/foo/test_bar.py, if it exists (core only)."""
    if not rel_path.endswith(".py") or rel_path.startswith("tests" + os.sep):
        return None
    candidate = os.path.join("tests", os.path.dirname(rel_path), "test_" + os.path.basename(rel_path))
    return candidate if os.path.exists(os.path.join(SAQ_HOME, candidate)) else None


def list_repos() -> None:
    for repo in candidate_repos():
        base = detect_base(repo)
        branch = git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
        dirty = len(git(repo, "status", "--porcelain").splitlines())
        ahead = git(repo, "rev-list", "--count", f"{base}..HEAD", check=False).strip() if base else "?"
        print(f"{repo}\tkind={repo_kind(repo)}\tbranch={branch}\tbase={base}\tahead={ahead}\tuncommitted={dirty}")


# --- rounds ---------------------------------------------------------------------------


def snapshot_tree(repo: str) -> str:
    """The tree object of the working tree as it is now, untracked files included.

    Built in a copy of the index, so the real one is untouched. The objects it writes are
    unreferenced, and when git gc prunes one, a later round only loses its delta.
    """
    index = os.path.join(repo, git(repo, "rev-parse", "--git-path", "index").strip())
    with tempfile.TemporaryDirectory() as tmp:
        tmp_index = os.path.join(tmp, "index")
        if os.path.exists(index):
            # the copy keeps the stat cache, so only files that changed are hashed. It must
            # keep the index's mtime too: git rehashes an entry written in the same second
            # as the index ("racily clean") only when the index looks that old
            shutil.copy2(index, tmp_index)
        env = {**os.environ, "GIT_INDEX_FILE": tmp_index}
        for args in (["add", "-A"], ["write-tree"]):
            result = subprocess.run(["git", "-C", repo, *args], env=env, capture_output=True, text=True)
            if result.returncode != 0:
                sys.exit(f"git {' '.join(args)} failed in {repo}: {result.stderr.strip()}")
        return result.stdout.strip()


def safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")


def round_dirs(state: str) -> list[tuple[int, str]]:
    found = []
    if os.path.isdir(state):
        for name in os.listdir(state):
            match = re.fullmatch(r"round-(\d+)", name)
            if match:
                found.append((int(match.group(1)), os.path.join(state, name)))
    return sorted(found)


def finished(round_dir: str) -> bool:
    return os.path.exists(os.path.join(round_dir, "summary.json"))


def next_round(state: str) -> tuple[int, str, str | None]:
    """The new round's number and bundle directory, and the last finished round's."""
    rounds = round_dirs(state)
    done = [path for _, path in rounds if finished(path)]
    if rounds and not finished(rounds[-1][1]):
        number, bundle = rounds[-1]
        shutil.rmtree(bundle)
    else:
        number = rounds[-1][0] + 1 if rounds else 1
        bundle = os.path.join(state, f"round-{number}")
    os.makedirs(bundle)
    return number, bundle, done[-1] if done else None


def build_previous(state: str) -> tuple[list[dict], dict[str, str], list[dict]]:
    """Every finding of the finished rounds with its status, the user's decision on each
    rule-change digest, and the number of new findings per round."""
    ledger: dict[str, dict] = {}
    rule_answers: dict[str, str] = {}
    history = []
    for number, path in round_dirs(state):
        if not finished(path):
            continue
        counts = {"round": number, "blocker": 0, "fix-first": 0, "nit": 0}
        for finding in load_json(os.path.join(path, "verified.json"), []):
            blocking = finding.get("origin") == "new" and finding.get("severity") in ("blocker", "fix-first")
            ledger[finding["id"]] = {**finding, "round": number, "status": "open" if blocking else "seen"}
            if finding.get("origin") == "new" and finding.get("severity") in counts:
                counts[finding["severity"]] += 1
        for carried in load_json(os.path.join(path, "carried.json"), []):
            entry = ledger.get(carried.get("id"))
            if entry and entry["status"] in ("open", "fixed"):
                entry["status"] = carried["status"]
        for answer in load_json(os.path.join(path, "answers.json"), []):
            if answer["id"] == "rules":
                rule_answers[answer["digest"]] = answer["answer"]
            elif answer["id"] in ledger:
                entry = ledger[answer["id"]]
                entry["answer"] = answer["answer"]
                if answer.get("note"):
                    entry["answer_note"] = answer["note"]
                if answer["answer"] in DISMISSING_ANSWERS:
                    entry["status"] = "dismissed"
        history.append(counts)
    return list(ledger.values()), rule_answers, history


# --- rules ----------------------------------------------------------------------------


def section(text: str | None, heading: str) -> str:
    """One '## ' section of a Markdown file, heading included, or '' if it has none."""
    out, inside = [], False
    for line in (text or "").splitlines(keepends=True):
        if line.startswith("## "):
            inside = line.rstrip() == heading
        if inside:
            out.append(line)
    return "".join(out)


def snapshot_rules(core: str, repo: str, rules_rev: str | None, out: str, accepted: str | None = None) -> dict[str, str]:
    """Write the CLAUDE.md files the change is judged by into out/rules/, from the base.

    The reviewed repo's copy comes from its base, so a change that adds or edits one isn't
    judged by it, until the user accepts those edits: then `accepted` is the edited copy.
    The skill's own files are used from the working tree: they have to match the SKILL.md
    that is running, so rule_changes() reports a change to them instead.
    """
    rules = os.path.join(out, "rules")
    os.makedirs(rules)
    copies = [(core, rules_rev if repo == core else detect_base(core), "CLAUDE.md")]
    if repo != core:
        copies.append((repo, rules_rev, "repo-CLAUDE.md"))
    sources = {}
    for source_repo, rev, name in copies:
        if source_repo == repo and accepted is not None:
            text, origin = accepted, "working tree (rule changes accepted)"
        else:
            text, origin = (show(source_repo, rev, "CLAUDE.md"), rev) if rev else (None, None)
        path = os.path.join(source_repo, "CLAUDE.md")
        if text is None and source_repo != repo and os.path.exists(path):
            # core isn't the repo under review, so its working tree is fair to judge by
            with open(path, encoding="utf-8", errors="replace") as fp:
                text, origin = fp.read(), "working tree"
        if text is not None:
            with open(os.path.join(rules, name), "w") as fp:
                fp.write(text)
            sources[name] = origin
    return sources


def unified(path: str, before: str | None, after: str | None) -> list[str]:
    lines = difflib.unified_diff((before or "").splitlines(keepends=True), (after or "").splitlines(keepends=True), f"a/{path}", f"b/{path}")
    return [line if line.endswith("\n") else line + "\n" for line in lines]


def rule_changes(repo: str, kind: str, merge_base: str, changed_paths: set[str], head_text) -> tuple[list[str], str]:
    """What the change does to the rules it is reviewed by: a name per change, and a patch."""
    names, patch = [], []
    if "CLAUDE.md" in changed_paths:
        before, after = show(repo, merge_base, "CLAUDE.md"), head_text("CLAUDE.md")
        # another repo's CLAUDE.md has no known rule sections, so all of it counts
        for heading in RULE_SECTIONS if kind == "core" else (None,):
            old = section(before, heading) if heading else before
            new = section(after, heading) if heading else after
            if (old or "") != (new or ""):
                names.append(f"CLAUDE.md § {heading.removeprefix('## ')}" if heading else "CLAUDE.md")
                patch.extend(unified("CLAUDE.md", old, new))
    if kind == "core":
        for path in sorted(p for p in changed_paths if p.startswith(SKILL_DIR + "/")):
            names.append(path)
            patch.extend(unified(path, show(repo, merge_base, path), head_text(path)))
    return names, "".join(patch)


# --- mechanical leads -----------------------------------------------------------------


def unquote(path: str) -> str:
    """Undo git's C-style quoting of a path with unusual characters."""
    if path.startswith('"') and path.endswith('"'):
        return codecs.escape_decode(path[1:-1].encode())[0].decode("utf-8", "replace")
    return path


def added_lines(diff: str) -> dict[str, set[int]]:
    """New-side line numbers of the lines a diff adds, per file."""
    added: dict[str, set[int]] = {}
    path, line, in_header = None, 0, False
    for text in diff.splitlines():
        if text.startswith("diff --git "):
            path, in_header = None, True
        elif in_header and text.startswith("+++ "):
            target = unquote(text[4:].rstrip("\t"))
            path = None if target == "/dev/null" else target.removeprefix("b/")
        elif match := HUNK.match(text):
            line, in_header = int(match.group(1)), False
        elif path is not None and not in_header:
            if text.startswith("+"):
                added.setdefault(path, set()).add(line)
                line += 1
            elif text.startswith(" "):
                line += 1
    return added


def dotted(node: ast.expr) -> str:
    """'a.b.c' for a plain dotted name, '' for anything else (a call, a subscript)."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    parts.append(node.id)
    return ".".join(reversed(parts))


def silent(stmt: ast.stmt) -> bool:
    if isinstance(stmt, (ast.Pass, ast.Continue)):
        return True
    if isinstance(stmt, ast.Return):
        return stmt.value is None or (isinstance(stmt.value, ast.Constant) and stmt.value.value is None)
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis


class Scanner(ast.NodeVisitor):
    """The lines of one Python file that match a mechanical check, among the added lines."""

    def __init__(self, path: str, source: str, added: set[int]):
        self.path = path
        self.lines = source.splitlines()
        self.added = added
        name = os.path.basename(path)
        self.is_test = "/tests/" in f"/{path}" or name.startswith("test_") or name == "conftest.py"
        self.in_api = path.startswith(("aceapi_v2/", "aceapi_ai/")) and path != "aceapi_v2/sync.py"
        self.handlers: list[ast.ExceptHandler] = []
        self.function_depth = 0
        self.bounded: set[int] = set()
        self.sleeps = {"time.sleep"}
        self.leads: list[dict] = []

    def lead(self, node: ast.AST, check: str, dimension: str, last: int | None = None) -> None:
        if any(line in self.added for line in range(node.lineno, (last or node.lineno) + 1)):
            text = self.lines[node.lineno - 1].strip()[:200]
            self.leads.append({"check": check, "dimension": dimension, "file": self.path, "line": node.lineno, "text": text})

    def commented(self, first: int, last: int) -> bool:
        return any("#" in self.lines[i - 1] for i in range(max(first, 1), min(last, len(self.lines)) + 1))

    def visit_scope(self, node: ast.AST, is_function: bool) -> None:
        # an except handler doesn't reach into a function defined inside it
        saved, self.handlers = self.handlers, []
        self.function_depth += int(is_function)
        self.generic_visit(node)
        self.function_depth -= int(is_function)
        self.handlers = saved

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.visit_scope(node, True)

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.visit_scope(node, False)

    def visit_Import(self, node: ast.Import | ast.ImportFrom) -> None:
        if self.function_depth and not self.commented(node.lineno - 1, node.end_lineno):
            self.lead(node, "local-import", "design")

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "time":
            self.sleeps.update(alias.asname or alias.name for alias in node.names if alias.name == "sleep")
        self.visit_Import(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self.lead(node, "bare-except", "logging")
        if all(silent(stmt) for stmt in node.body) and not self.commented(node.lineno, node.end_lineno):
            self.lead(node, "silent-except", "logging", last=node.end_lineno)
        self.handlers.append(node)
        self.generic_visit(node)
        self.handlers.pop()

    def visit_Raise(self, node: ast.Raise) -> None:
        if self.handlers and node.exc is not None and node.cause is None:
            reraise = isinstance(node.exc, ast.Name) and node.exc.id == self.handlers[-1].name
            if not reraise:
                self.lead(node, "raise-without-from", "logging")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = dotted(node.func)
        attr = node.func.attr if isinstance(node.func, ast.Attribute) else name
        keywords = {k.arg for k in node.keywords if k.arg}
        if name in ("traceback.print_exc", "print_exc"):
            self.lead(node, "print-exc", "logging")
        if (self.handlers and attr in ("error", "critical") and isinstance(node.func, ast.Attribute)
                and LOGGER.search(dotted(node.func.value).rsplit(".", 1)[-1]) and "exc_info" not in keywords):
            self.lead(node, "error-without-traceback", "logging")
        if self.is_test and name in self.sleeps:
            self.lead(node, "sleep-in-test", "tests")
        if self.in_api and attr in THREAD_HOPS:
            self.lead(node, "thread-hop", "design")
        if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
            self.lead(node, "shell-true", "correctness")
        if not self.is_test:
            self.check_bounded(node, name, attr, keywords)
            if self.in_api and attr == "offset" and isinstance(node.func, ast.Attribute):
                self.lead(node, "offset-paging", "performance")
        if attr == "wait_for":
            # asyncio.wait_for(x.wait(), timeout) bounds the wait it is given
            self.bounded.update(id(arg) for arg in node.args[:1])
        self.generic_visit(node)

    def check_bounded(self, node: ast.Call, name: str, attr: str, keywords: set[str]) -> None:
        if "timeout" in keywords or id(node) in self.bounded:
            return
        if isinstance(node.func, ast.Attribute) and not node.args and not keywords & {"blocking", "block"}:
            receiver = dotted(node.func.value).rsplit(".", 1)[-1]
            if attr in WAIT_METHODS or (attr == "get" and re.search(r"queue$|^q$", receiver, re.IGNORECASE)):
                self.lead(node, "unbounded-wait", "uptime")
                return
        if name in SUBPROCESS_CALLS or HTTP_CALL.fullmatch(name):
            self.lead(node, "no-timeout", "uptime")


def scan_python(path: str, source: str, added: set[int]) -> list[dict]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []  # a file that doesn't parse fails its own tests
    scanner = Scanner(path, source, added)
    scanner.visit(tree)
    return scanner.leads


# --- stale references -----------------------------------------------------------------


def top_level_names(source: str | None) -> set[str]:
    try:
        tree = ast.parse(source or "")
    except (SyntaxError, ValueError):
        return set()
    return {node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}


def distinctive(name: str) -> bool:
    """Whether a name is specific enough that a doc line naming it means this one."""
    core = name.strip("_")
    return len(core) >= 6 and ("_" in core or re.search(r"[a-z][A-Z]", core) is not None) and not core.startswith("test")


def config_keys(text: str | None) -> set[str]:
    try:
        data = yaml.safe_load(text or "")
    except yaml.YAMLError:
        return set()
    keys = set()
    stack = [(data, "")]
    while stack:
        node, prefix = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                keys.add(f"{prefix}{key}")
                stack.append((value, f"{prefix}{key}."))
    return keys


def name_ref(kind: str, term: str, pattern: str) -> dict:
    return {"removed": kind, "ref": term, "pattern": re.compile(pattern)}


def path_ref(kind: str, path: str) -> dict:
    tail = "" if path.endswith("/") else r"(?![\w-])"
    return name_ref(kind, path, r"(?<![\w/.-])" + re.escape(path) + tail)


def removed_refs(repo: str, tree: str, merge_base: str, changed: list[tuple[str, str, str]], head_text) -> list[dict]:
    """A doc-line pattern for every path, top-level function or class and config key the
    change removes."""
    removed_files = [old for status, old, _ in changed if status[0] in "DR"]
    present = set(git(repo, "ls-tree", "-r", "-t", "--name-only", tree).splitlines())
    gone = set()
    for old in removed_files:
        parent = os.path.dirname(old)
        while parent and parent not in present:
            gone.add(parent)
            parent = os.path.dirname(parent)
    gone_dirs = sorted(d for d in gone if os.path.dirname(d) not in gone)

    refs = []
    for directory in gone_dirs:
        refs.append(path_ref("directory", directory + "/"))
        if any(f.startswith(directory + "/") and f.endswith(".py") for f in removed_files):
            package = directory.replace("/", ".")
            refs.append(name_ref("package", package, r"(?<![\w.])" + re.escape(package) + r"\.\w"))
    for old in removed_files:
        if any(old.startswith(d + "/") for d in gone_dirs):
            continue
        refs.append(path_ref("file", old))
        if old.endswith(".py"):
            module = old[:-3].removesuffix("/__init__").replace("/", ".")
            refs.append(name_ref("module", module, r"(?<![\w.])" + re.escape(module) + r"(?!\w)"))

    names = set()
    for status, old, path in changed:
        if old.endswith(".py"):
            after = set() if status[0] == "D" else top_level_names(head_text(path))
            names |= {n for n in top_level_names(show(repo, merge_base, old)) - after if distinctive(n)}
    if names:
        # a name that moved to another module still exists and isn't stale
        pattern = r"(def|class)[[:space:]]+(" + "|".join(sorted(names)) + ")"
        found = git(repo, "grep", "-h", "-E", pattern, tree, "--", "*.py", check=False)
        names -= set(re.findall(r"(?:def|class)\s+(\w+)", found))
    for name in sorted(names):
        refs.append(name_ref("function or class", name, r"\b" + re.escape(name) + r"\b"))

    for status, old, path in changed:
        if not old.endswith((".yaml", ".yml")) or not re.search(r"(^|/)etc/", old):
            continue
        after = set() if status[0] == "D" else config_keys(head_text(path))
        keys = config_keys(show(repo, merge_base, old)) - after
        for key in sorted(k for k in keys if k.rpartition(".")[0] not in keys):
            parts = key.split(".")
            leaf = parts[-1]
            if len(parts) > 1 or distinctive(leaf):
                refs.append(name_ref("config key", key, r"(?<![\w.])" + re.escape(key) + r"(?!\w)"))
            if distinctive(leaf):
                if len(parts) > 2:
                    tail = ".".join(parts[-2:])
                    refs.append(name_ref("config key", tail, r"(?<![\w.])" + re.escape(tail) + r"(?!\w)"))
                refs.append(name_ref("config key", f"{leaf}:", r"(?<![\w.])" + re.escape(leaf) + ":"))
    return refs


def stale_references(refs: list[dict], docs: list[str], head_text, added: dict[str, set[int]]) -> list[dict]:
    """Doc lines naming something the change removes, except lines the change itself writes."""
    leads, hits = [], {}
    for doc in docs:
        for number, line in enumerate((head_text(doc) or "").splitlines(), 1):
            if number in added.get(doc, ()):
                continue
            ref = next((r for r in refs if r["pattern"].search(line)), None)
            if ref:
                hits[ref["ref"]] = hits.get(ref["ref"], 0) + 1
                if hits[ref["ref"]] <= STALE_HITS_PER_REF:
                    leads.append({"check": "stale-reference", "dimension": "design", "file": doc, "line": number,
                                  "text": line.strip()[:200], "ref": ref["ref"], "removed": ref["removed"]})
    for lead in leads:
        lead["hits"] = hits[lead["ref"]]
    return leads


# --- main -----------------------------------------------------------------------------


def write(out: str, name: str, content) -> None:
    with open(os.path.join(out, name), "w") as fp:
        if isinstance(content, str):
            fp.write(content)
        else:
            json.dump(content, fp, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", action="store_true", help="list repos in the working tree with their state")
    parser.add_argument("--repo", default=SAQ_HOME)
    parser.add_argument("--base", help="base ref (default: origin/HEAD, main, master)")
    parser.add_argument("--range", help="explicit A..B range instead of merge-base..HEAD")
    parser.add_argument("--full", action="store_true", help="review the whole change, not only what changed since the last round")
    parser.add_argument("--state-dir", default=os.path.join(SAQ_HOME, "local", "ace-review"))
    args = parser.parse_args()

    if args.list:
        list_repos()
        return
    if args.base and args.range:
        parser.error("--base and --range don't go together")

    repo = toplevel(args.repo)
    kind = repo_kind(repo)
    requested = os.path.abspath(args.repo)
    if kind == "core" and requested != repo:
        # integrations/ and signatures/ are gitignored in core, so a path under them
        # without its own .git would silently review core instead
        sys.exit(f"{requested} is not its own git repo (resolves to {repo})")
    core = toplevel(SAQ_HOME)

    if args.range:
        start, _, end = args.range.partition("..")
        merge_base = git(repo, "merge-base", start, end or "HEAD").strip()
        head = git(repo, "rev-parse", end or "HEAD").strip()
        base = rules_rev = start
        include_worktree = False
        tree = git(repo, "rev-parse", f"{head}^{{tree}}").strip()
    else:
        base = rules_rev = args.base or detect_base(repo)
        if not base:
            sys.exit(f"no base branch found in {repo}; pass --base")
        merge_base = git(repo, "merge-base", base, "HEAD").strip()
        head = git(repo, "rev-parse", "HEAD").strip()
        include_worktree = True
        tree = snapshot_tree(repo)
    branch = git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()

    def head_text(path: str) -> str | None:
        if not include_worktree:
            return show(repo, head, path)
        full = os.path.join(repo, path)
        if not os.path.isfile(full):
            return None
        with open(full, encoding="utf-8", errors="replace") as fp:
            return fp.read()

    label = f"range-{args.range}" if args.range else (branch if branch != "HEAD" else head[:12])
    state = os.path.join(args.state_dir, safe_name(f"{os.path.basename(repo)}-{label}"))
    number, out, previous_dir = next_round(state)
    previous_target = load_json(os.path.join(previous_dir, "target.json"), {}) if previous_dir else {}

    # diffing against the snapshot tree takes in uncommitted and untracked work
    diff = git(repo, "diff", *DIFF_FLAGS, merge_base, tree)
    write(out, "diff.patch", diff)
    write(out, "stat.txt", git(repo, "diff", *DIFF_FLAGS, "--stat", merge_base, tree))
    write(out, "log.txt", git(repo, "log", "--no-merges", "--format=--- %h %an%n%B", f"{merge_base}..{head}"))
    changed: list[tuple[str, str, str]] = []
    for line in git(repo, "diff", *DIFF_FLAGS, "--name-status", merge_base, tree).splitlines():
        parts = line.split("\t")
        changed.append((parts[0], parts[1], parts[-1]))
    write(out, "files.txt", "".join(f"{status}\t{path}\n" for status, _, path in changed))

    delta, delta_reason, delta_diff, unchanged = False, None, "", False
    if previous_target:
        previous_tree = previous_target.get("tree", "")
        tree_present = bool(previous_tree) and not subprocess.run(
            ["git", "-C", repo, "cat-file", "-e", f"{previous_tree}^{{tree}}"], capture_output=True).returncode
        unchanged = previous_tree == tree or (
            previous_target.get("merge_base") == merge_base and tree_present
            and not git(repo, "diff", "--name-only", previous_tree, tree).strip())
        if args.full:
            delta_reason = "--full"
        elif previous_target.get("merge_base") != merge_base:
            delta_reason = "the merge-base moved since the last round (a rebase, or a merge from the base)"
        elif not tree_present:
            delta_reason = "the last round's tree is no longer in the object store"
        else:
            delta = True
            delta_diff = git(repo, "diff", *DIFF_FLAGS, previous_tree, tree)
            write(out, "delta.patch", delta_diff)
            write(out, "delta-files.txt", git(repo, "diff", *DIFF_FLAGS, "--name-status", previous_tree, tree))

    integrations = integration_dirs(repo) if kind == "integration" else []
    tests: list[str] = []
    unmarked: list[str] = []
    for status, _, path in changed:
        if status.startswith("D"):
            continue
        abs_path = os.path.join(repo, path)
        name = os.path.basename(path)
        if name.startswith("test_") and name.endswith(".py"):
            mapped = saq_test_path(abs_path, integrations)
            if mapped:
                tests.append(mapped)
            unmarked.extend(unmarked_tests(abs_path, head_text(path)))
        elif kind == "core":
            mirrored = mirrored_test(path)
            if mirrored:
                tests.append(mirrored)
    tests = sorted(set(t for t in tests if os.path.exists(os.path.join(SAQ_HOME, t))))
    write(out, "tests.txt", "".join(t + "\n" for t in tests))
    write(out, "unmarked.txt", "".join(u + "\n" for u in unmarked))

    if kind == "integration":
        cov = [f"--cov={os.path.relpath(os.path.join(i, 'src'), SAQ_HOME)}" for i in integrations]
    elif kind == "core":
        cov = ["--cov"]
    else:
        cov = []
    write(out, "cov_sources.txt", " ".join(cov) + "\n")

    changed_paths = {p for _, old, new in changed for p in (old, new)}
    rule_names, rule_patch = rule_changes(repo, kind, merge_base, changed_paths, head_text)
    digest = hashlib.sha256(rule_patch.encode()).hexdigest()[:16] if rule_patch else None
    previous, rule_answers, history = build_previous(state)
    rule_status = rule_answers.get(digest, "pending") if digest else "none"
    accepted = head_text("CLAUDE.md") if rule_status == "accepted" else None
    rules_sources = snapshot_rules(core, repo, rules_rev, out, accepted)
    if rule_patch:
        write(out, "rule-changes.patch", rule_patch)
    if previous_dir:
        write(out, "previous.json", previous)

    # in a delta round, only what changed since the last round can produce a new lead
    full_added = added_lines(diff)
    scan_added = added_lines(delta_diff) if delta else full_added
    leads = []
    for status, _, path in changed:
        if status[0] != "D" and path.endswith(".py"):
            added = full_added.get(path, set()) & scan_added.get(path, set())
            if added:
                leads.extend(scan_python(path, head_text(path) or "", added))
    refs = removed_refs(repo, tree, merge_base, changed, head_text)
    if refs:
        docs = [p for p in git(repo, "ls-tree", "-r", "--name-only", tree).splitlines()
                if p.endswith(".md") and not p.startswith("tests/") and not os.path.basename(p).startswith("CHANGELOG")]
        leads.extend(stale_references(refs, docs, head_text, full_added))
    write(out, "leads.json", leads)

    target = {
        "repo": repo,
        "kind": kind,
        "bundle": out,
        "round": number,
        "base": base,
        "merge_base": merge_base,
        "head": head,
        "tree": tree,
        "branch": branch,
        "includes_uncommitted": include_worktree,
        "previous_round": int(os.path.basename(previous_dir).removeprefix("round-")) if previous_dir else None,
        "unchanged": unchanged,
        "delta": delta,
        "delta_reason": delta_reason,
        "history": history,
        "rules": rules_sources,
        "rule_changes": rule_names,
        "rule_changes_digest": digest,
        "rule_changes_status": rule_status,
        "integrations": [os.path.basename(i) for i in integrations],
        "changed_files": len(changed),
        "tests_selected": len(tests),
        "unmarked_tests": len(unmarked),
        "leads": len(leads),
        "touches_models": any(p.endswith("saq/database/model.py") for _, _, p in changed),
        "touches_migrations": sorted({p.split("/")[1] for _, _, p in changed if p.startswith("alembic/") and "/versions/" in p}),
    }
    write(out, "target.json", target)
    print(json.dumps(target, indent=2))


if __name__ == "__main__":
    main()
