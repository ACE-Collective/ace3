import base64
import os
import re
import stat
from typing import Optional

import yaml

from hunt_compiler.models import CompiledHunt, EmbeddedFile

INCLUDE_DIRECTIVE = "include"
QUERY_INCLUDE_PATTERN = re.compile(r"<include:([^>]+)>")

PKG_TOKEN = "__pkg__/"
HUNT_ROOT_MARKER = ".hunt-root"


class PackageRootNotFound(Exception):
    """No .hunt-root marker was found walking up from a file path."""


class OutOfPackageRootError(Exception):
    """A hunt referenced a file outside its package root."""

    def __init__(self, authored_path: str, resolved_abs: str, package_root: str):
        self.authored_path = authored_path
        self.resolved_abs = resolved_abs
        self.package_root = package_root
        super().__init__(
            f"hunt reference {authored_path!r} resolves to {resolved_abs!r}, "
            f"which is outside the package root {package_root!r}"
        )


def find_package_root(file_path: str) -> str:
    """Walk upward from file_path looking for a .hunt-root marker.

    Args:
        file_path: Path to start the walk from. The walk begins at its
            parent directory.

    Returns:
        The absolute path to the directory containing the marker.

    Raises:
        PackageRootNotFound: no marker was found before the filesystem root.
    """
    current = os.path.dirname(os.path.abspath(file_path))
    while True:
        if os.path.isfile(os.path.join(current, HUNT_ROOT_MARKER)):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            raise PackageRootNotFound(
                f"no {HUNT_ROOT_MARKER} marker found walking up from {file_path!r}. "
                f"Place a {HUNT_ROOT_MARKER} file at the intended package root or "
                f"pass package_root= explicitly."
            )
        current = parent


def compile_hunt(file_path: str, package_root: Optional[str] = None) -> CompiledHunt:
    """Compile a hunt YAML file into a self-contained CompiledHunt.

    Args:
        file_path: Path to the main hunt YAML file.
        package_root: Directory that every referenced file must live under.
            Embedded asset paths are stored relative to this directory. When
            None, the compiler walks upward from file_path looking for a
            .hunt-root marker.

    Raises:
        PackageRootNotFound: package_root was None and no marker was found.
        OutOfPackageRootError: the hunt references a file outside package_root.
    """
    file_path = os.path.abspath(file_path)

    if package_root is None:
        package_root = find_package_root(file_path)
    else:
        package_root = os.path.abspath(package_root)

    if not _is_under(file_path, package_root):
        raise OutOfPackageRootError(file_path, file_path, package_root)

    assets: dict[str, EmbeddedFile] = {}
    _process_yaml(file_path, package_root, assets, set())

    return CompiledHunt(
        version=2,
        target=os.path.relpath(file_path, package_root),
        package_root=package_root,
        assets=sorted(assets.values(), key=lambda a: (a.kind, a.path)),
    )


def _process_yaml(
    abs_path: str,
    package_root: str,
    assets: dict[str, EmbeddedFile],
    history: set[str],
) -> None:
    """Parse abs_path, rewrite its path fields to __pkg__/ tokens, record it
    and every file it references in assets."""
    if abs_path in history:
        return
    history.add(abs_path)

    packaged_rel = _check_and_packaged_rel(abs_path, abs_path, package_root)

    with open(abs_path, "r", encoding="utf-8") as fp:
        raw = fp.read()

    parsed = yaml.safe_load(raw)

    if not isinstance(parsed, dict):
        assets[packaged_rel] = EmbeddedFile(
            kind="yaml",
            path=packaged_rel,
            content=raw,
            original_abs=abs_path,
        )
        return

    yaml_dir = os.path.dirname(abs_path)

    includes = parsed.get(INCLUDE_DIRECTIVE)
    if isinstance(includes, list):
        rewritten_includes: list[str] = []
        for include_path in includes:
            inc_abs = _abs_relative_to(include_path, yaml_dir)
            inc_packaged = _check_and_packaged_rel(include_path, inc_abs, package_root)
            rewritten_includes.append(PKG_TOKEN + inc_packaged)
            _process_yaml(inc_abs, package_root, assets, history)
        parsed[INCLUDE_DIRECTIVE] = rewritten_includes

    commands = parsed.get("commands")
    if isinstance(commands, list):
        for cmd in commands:
            if isinstance(cmd, dict):
                _rewrite_command(cmd, yaml_dir, package_root, assets)

    rule = parsed.get("rule")
    if isinstance(rule, dict):
        _rewrite_rule(rule, yaml_dir, package_root, assets)

    assets[packaged_rel] = EmbeddedFile(
        kind="yaml",
        path=packaged_rel,
        content=yaml.safe_dump(
            parsed, sort_keys=False, default_flow_style=False, allow_unicode=True
        ),
        original_abs=abs_path,
    )


def _rewrite_command(
    cmd: dict,
    yaml_dir: str,
    package_root: str,
    assets: dict[str, EmbeddedFile],
) -> None:
    """Rewrite one command dict's path + files fields in place and register
    each referenced file in assets."""
    if cmd.get("type") == "executable" and cmd.get("path"):
        authored = cmd["path"]
        abs_path = _abs_relative_to(authored, yaml_dir)
        packaged_rel = _check_and_packaged_rel(authored, abs_path, package_root)
        cmd["path"] = PKG_TOKEN + packaged_rel
        _add_executable_asset(abs_path, packaged_rel, assets)

    files = cmd.get("files")
    if isinstance(files, list):
        rewritten_files: list[str] = []
        for authored in files:
            abs_path = _abs_relative_to(authored, yaml_dir)
            packaged_rel = _check_and_packaged_rel(authored, abs_path, package_root)
            rewritten_files.append(PKG_TOKEN + packaged_rel)
            _add_support_asset(abs_path, packaged_rel, assets)
        cmd["files"] = rewritten_files


def _rewrite_rule(
    rule: dict,
    yaml_dir: str,
    package_root: str,
    assets: dict[str, EmbeddedFile],
) -> None:
    """Rewrite rule.search/query_file_path, rule.query <include:...> markers,
    and any inline commands inside rule.correlate.logic."""
    for field in ("search", "query_file_path"):
        if rule.get(field):
            authored = rule[field]
            abs_path = _abs_relative_to(authored, yaml_dir)
            packaged_rel = _check_and_packaged_rel(authored, abs_path, package_root)
            rule[field] = PKG_TOKEN + packaged_rel
            _add_query_asset(abs_path, packaged_rel, package_root, assets)
            break

    inline_query = rule.get("query")
    if isinstance(inline_query, str):
        rule["query"] = _rewrite_query_includes(
            inline_query, yaml_dir, package_root, assets
        )

    correlate = rule.get("correlate")
    if isinstance(correlate, dict):
        logic = correlate.get("logic")
        if isinstance(logic, list):
            _rewrite_logic(logic, yaml_dir, package_root, assets)


def _rewrite_logic(
    steps: list,
    yaml_dir: str,
    package_root: str,
    assets: dict[str, EmbeddedFile],
) -> None:
    for step in steps:
        if not isinstance(step, dict):
            continue
        if "transform" in step:
            transform = step.get("transform")
            if isinstance(transform, dict):
                cmd = transform.get("command")
                if isinstance(cmd, dict):
                    _rewrite_command(cmd, yaml_dir, package_root, assets)
        if "when" in step:
            execute = step.get("execute")
            if isinstance(execute, list):
                _rewrite_logic(execute, yaml_dir, package_root, assets)
            else_branch = step.get("else")
            if isinstance(else_branch, list):
                _rewrite_logic(else_branch, yaml_dir, package_root, assets)


def _rewrite_query_includes(
    text: str,
    yaml_dir: str,
    package_root: str,
    assets: dict[str, EmbeddedFile],
) -> str:
    """Replace every <include:path> marker with <include:__pkg__/<rel>> and
    register the referenced file as a query_include asset."""

    def _sub(match: re.Match) -> str:
        authored = match.group(1)
        abs_path = _abs_relative_to(authored, yaml_dir)
        packaged_rel = _check_and_packaged_rel(authored, abs_path, package_root)
        _add_query_include_asset(abs_path, packaged_rel, package_root, assets)
        return f"<include:{PKG_TOKEN}{packaged_rel}>"

    return QUERY_INCLUDE_PATTERN.sub(_sub, text)


def _add_query_asset(
    abs_path: str,
    packaged_rel: str,
    package_root: str,
    assets: dict[str, EmbeddedFile],
) -> None:
    if packaged_rel in assets or not os.path.isfile(abs_path):
        return
    with open(abs_path, "r", encoding="utf-8") as fp:
        content = fp.read()
    content = _rewrite_query_includes(
        content, os.path.dirname(abs_path), package_root, assets
    )
    assets[packaged_rel] = EmbeddedFile(
        kind="query",
        path=packaged_rel,
        content=content,
        original_abs=abs_path,
    )


def _add_query_include_asset(
    abs_path: str,
    packaged_rel: str,
    package_root: str,
    assets: dict[str, EmbeddedFile],
) -> None:
    if packaged_rel in assets or not os.path.isfile(abs_path):
        return
    with open(abs_path, "r", encoding="utf-8") as fp:
        content = fp.read()
    content = _rewrite_query_includes(
        content, os.path.dirname(abs_path), package_root, assets
    )
    assets[packaged_rel] = EmbeddedFile(
        kind="query_include",
        path=packaged_rel,
        content=content,
        original_abs=abs_path,
    )


def _add_executable_asset(
    abs_path: str,
    packaged_rel: str,
    assets: dict[str, EmbeddedFile],
) -> None:
    if packaged_rel in assets or not os.path.isfile(abs_path):
        return
    content, encoding = _read_file_content(abs_path)
    permissions = stat.S_IMODE(os.stat(abs_path).st_mode)
    assets[packaged_rel] = EmbeddedFile(
        kind="executable",
        path=packaged_rel,
        content=content,
        encoding=encoding,
        permissions=permissions,
        original_abs=abs_path,
    )


def _add_support_asset(
    abs_path: str,
    packaged_rel: str,
    assets: dict[str, EmbeddedFile],
) -> None:
    if packaged_rel in assets or not os.path.isfile(abs_path):
        return
    content, encoding = _read_file_content(abs_path)
    assets[packaged_rel] = EmbeddedFile(
        kind="support",
        path=packaged_rel,
        content=content,
        encoding=encoding,
        original_abs=abs_path,
    )


def _read_file_content(abs_path: str) -> tuple[str, str]:
    """Read a file as text if possible, otherwise as base64."""
    try:
        # the encoding must be explicit: without it the locale decides, and under a
        # C/POSIX locale a utf-8 file would fail to decode and be packaged as binary
        with open(abs_path, "r", encoding="utf-8") as fp:
            return fp.read(), "text"
    except (UnicodeDecodeError, ValueError):
        with open(abs_path, "rb") as fp:
            return base64.b64encode(fp.read()).decode("ascii"), "base64"


def _check_and_packaged_rel(
    authored_path: str, abs_path: str, package_root: str
) -> str:
    """Verify abs_path is under package_root and return its packaged relpath."""
    if not _is_under(abs_path, package_root):
        raise OutOfPackageRootError(authored_path, abs_path, package_root)
    return os.path.relpath(abs_path, package_root)


def _is_under(abs_path: str, root: str) -> bool:
    rel = os.path.relpath(abs_path, root)
    return not rel.startswith("..") and not os.path.isabs(rel)


def _abs_relative_to(path: str, base_dir: str) -> str:
    if os.path.isabs(path):
        return os.path.normpath(path)
    return os.path.normpath(os.path.join(base_dir, path))
