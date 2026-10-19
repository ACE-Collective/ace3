#!/usr/bin/env python3
"""Collect everything /ace-review needs about one repo's change into a bundle directory.

    prepare.py --list
    prepare.py [--repo PATH] [--base REF] [--range A..B] --out DIR

Plain git only, so it works for core, signatures/ and integration repos hosted
anywhere. Writes into DIR:

    target.json      repo toplevel, kind, base, merge-base, head, integration names
    diff.patch       the full diff (merge-base..HEAD, plus uncommitted work when
                     reviewing the checked-out branch)
    stat.txt         git diff --stat
    files.txt        changed files, one per line, "<status>\t<path relative to repo>"
    log.txt          commit subjects and bodies in the range
    tests.txt        pytest paths to run (as seen from SAQ_HOME, integration tests
                     through their tests/test_external_integration_<name> symlink)
    unmarked.txt     test functions in changed test files with no unit/integration/system marker
    cov_sources.txt  --cov arguments for the pytest run
"""

import argparse
import ast
import json
import os
import subprocess
import sys

SAQ_HOME = os.environ.get("SAQ_HOME", "/opt/ace")
RUN_MARKERS = {"unit", "integration", "system"}


def git(repo: str, *args: str, check: bool = True) -> str:
    result = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    if check and result.returncode != 0:
        sys.exit(f"git {' '.join(args)} failed in {repo}: {result.stderr.strip()}")
    return result.stdout


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


def unmarked_tests(path: str) -> list[str]:
    try:
        with open(path) as fp:
            tree = ast.parse(fp.read())
    except (OSError, SyntaxError) as e:
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true", help="list repos in the working tree with their state")
    parser.add_argument("--repo", default=SAQ_HOME)
    parser.add_argument("--base", help="base ref (default: origin/HEAD, main, master)")
    parser.add_argument("--range", help="explicit A..B range instead of merge-base..HEAD")
    parser.add_argument("--out")
    args = parser.parse_args()

    if args.list:
        list_repos()
        return
    if not args.out:
        parser.error("--out is required")

    repo = toplevel(args.repo)
    kind = repo_kind(repo)
    requested = os.path.abspath(args.repo)
    if kind == "core" and requested != repo:
        # integrations/ and signatures/ are gitignored in core, so a path under them
        # without its own .git would silently review core instead
        sys.exit(f"{requested} is not its own git repo (resolves to {repo})")
    os.makedirs(args.out, exist_ok=True)

    if args.range:
        start, _, end = args.range.partition("..")
        merge_base = git(repo, "merge-base", start, end or "HEAD").strip()
        head = git(repo, "rev-parse", end or "HEAD").strip()
        base = start
        include_worktree = False
    else:
        base = args.base or detect_base(repo)
        if not base:
            sys.exit(f"no base branch found in {repo}; pass --base")
        merge_base = git(repo, "merge-base", base, "HEAD").strip()
        head = git(repo, "rev-parse", "HEAD").strip()
        include_worktree = True

    # with the checked-out branch, diff against the working tree so uncommitted work is reviewed too
    diff_args = [merge_base] if include_worktree else [merge_base, head]
    diff = git(repo, "diff", "-M", *diff_args)
    name_status = git(repo, "diff", "-M", "--name-status", *diff_args)
    untracked = git(repo, "ls-files", "--others", "--exclude-standard").splitlines() if include_worktree else []
    for path in untracked:
        name_status += f"A\t{path}\n"
        diff += git(repo, "diff", "--no-index", "/dev/null", path, check=False)

    with open(os.path.join(args.out, "diff.patch"), "w") as fp:
        fp.write(diff)
    with open(os.path.join(args.out, "stat.txt"), "w") as fp:
        fp.write(git(repo, "diff", "-M", "--stat", *diff_args))
        if untracked:
            fp.write(f" (+ {len(untracked)} untracked: {', '.join(untracked)})\n")
    with open(os.path.join(args.out, "log.txt"), "w") as fp:
        fp.write(git(repo, "log", "--no-merges", "--format=--- %h %an%n%B", f"{merge_base}..{head}"))

    changed: list[tuple[str, str]] = []
    for line in name_status.splitlines():
        parts = line.split("\t")
        changed.append((parts[0], parts[-1]))
    with open(os.path.join(args.out, "files.txt"), "w") as fp:
        fp.writelines(f"{status}\t{path}\n" for status, path in changed)

    integrations = integration_dirs(repo) if kind == "integration" else []
    tests: list[str] = []
    unmarked: list[str] = []
    for status, path in changed:
        if status.startswith("D"):
            continue
        abs_path = os.path.join(repo, path)
        name = os.path.basename(path)
        if name.startswith("test_") and name.endswith(".py"):
            mapped = saq_test_path(abs_path, integrations)
            if mapped:
                tests.append(mapped)
            unmarked.extend(unmarked_tests(abs_path))
        elif kind == "core":
            mirrored = mirrored_test(path)
            if mirrored:
                tests.append(mirrored)
    tests = sorted(set(t for t in tests if os.path.exists(os.path.join(SAQ_HOME, t))))

    with open(os.path.join(args.out, "tests.txt"), "w") as fp:
        fp.writelines(t + "\n" for t in tests)
    with open(os.path.join(args.out, "unmarked.txt"), "w") as fp:
        fp.writelines(u + "\n" for u in unmarked)

    if kind == "integration":
        cov = [f"--cov={os.path.relpath(os.path.join(i, 'src'), SAQ_HOME)}" for i in integrations]
    elif kind == "core":
        cov = ["--cov"]
    else:
        cov = []
    with open(os.path.join(args.out, "cov_sources.txt"), "w") as fp:
        fp.write(" ".join(cov) + "\n")

    target = {
        "repo": repo,
        "kind": kind,
        "base": base,
        "merge_base": merge_base,
        "head": head,
        "branch": git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip(),
        "includes_uncommitted": include_worktree,
        "integrations": [os.path.basename(i) for i in integrations],
        "changed_files": len(changed),
        "tests_selected": len(tests),
        "unmarked_tests": len(unmarked),
        "touches_models": any(p.endswith("saq/database/model.py") for _, p in changed),
        "touches_migrations": sorted({p.split("/")[1] for _, p in changed if p.startswith("alembic/") and "/versions/" in p}),
    }
    with open(os.path.join(args.out, "target.json"), "w") as fp:
        json.dump(target, fp, indent=2)
    print(json.dumps(target, indent=2))


if __name__ == "__main__":
    main()
