"""Which of a repository's directories the yara service loads as namespaces.

The yara service loads `service_yara.signature_dir`: each directory directly inside it is one
namespace, and the `.yar`/`.yara` files directly inside a namespace directory are its rules
(YaraScanner.__init__). Files loose in signature_dir and files nested deeper are not loaded. A
repository (a `git_repo_<name>` section) can feed that in one of two ways, and SVS derives which
from the configuration rather than asking for it again:

- **contained**: signature_dir is the checkout's `local_path` or lies inside it. Every directory
  of signature_dir is a namespace, so the namespaces of a commit are the directories at that path
  in the commit's tree, and a namespace a PR adds is validated with it.
- **linked**: entries of signature_dir are (or are symlinks to) directories inside the checkout.
  Each such entry is a namespace, named after the entry, read from the same path in the commit's
  tree.

Anything else (no entry of signature_dir comes from the checkout) is a configuration error: the
repository holds no rules the yara service loads.
"""

import os
from dataclasses import dataclass, field
from typing import Optional

from saq.configuration.config import get_config, get_service_config
from saq.constants import SERVICE_YARA_SCANNER
from saq.util import abs_path

YARA_FILE_EXTENSIONS = (".yar", ".yara")


class LayoutError(ValueError):
    """The repository is not one SVS can validate."""


@dataclass(frozen=True)
class Namespace:
    # the name of the signature_dir entry: the namespace a detection's details name
    name: str
    # its directory relative to the repository root, posix separators; "" is the root itself
    path: str


@dataclass(frozen=True)
class RepoLayout:
    repository: str
    # contained: signature_dir relative to the repository root ("" when it is the root)
    signature_dir_path: Optional[str] = None
    # linked: the namespaces, in name order
    namespaces: tuple[Namespace, ...] = ()

    @property
    def contained(self) -> bool:
        return self.signature_dir_path is not None


@dataclass(frozen=True)
class NotLoaded:
    # relative to the repository root
    path: str
    reason: str


@dataclass
class TreeNamespace:
    name: str
    # absolute path of its directory in the exported tree
    directory: str
    # absolute paths of its rule files, in name order
    files: list[str] = field(default_factory=list)


@dataclass
class TreeLayout:
    """The namespaces of one exported commit, and the rule files in it the yara service would not
    load."""
    namespaces: list[TreeNamespace] = field(default_factory=list)
    not_loaded: list[NotLoaded] = field(default_factory=list)
    # linked namespaces whose directory does not exist in this commit
    absent: list[str] = field(default_factory=list)


def _is_under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _relative(path: str, root: str) -> str:
    relative = os.path.relpath(path, root)
    return "" if relative == "." else relative.replace(os.sep, "/")


def derive_layout(repository: str, local_path: str, signature_dir: str) -> RepoLayout:
    """The layout of the checkout at local_path relative to signature_dir (both absolute). Raises
    LayoutError when the checkout feeds no namespace."""
    root = os.path.realpath(local_path)
    real_signature_dir = os.path.realpath(signature_dir)
    if _is_under(real_signature_dir, root):
        return RepoLayout(repository, signature_dir_path=_relative(real_signature_dir, root))

    namespaces = []
    if os.path.isdir(signature_dir):
        for entry in sorted(os.listdir(signature_dir)):
            entry_path = os.path.join(signature_dir, entry)
            if not os.path.isdir(entry_path):
                continue

            real_entry = os.path.realpath(entry_path)
            if _is_under(real_entry, root):
                namespaces.append(Namespace(entry, _relative(real_entry, root)))

    if not namespaces:
        raise LayoutError(
            f"repository {repository} ({local_path}) holds no rules the yara service loads: "
            f"service_yara.signature_dir ({signature_dir}) is not inside it, and no directory of "
            "signature_dir is (or links to) a directory inside it")

    return RepoLayout(repository, namespaces=tuple(namespaces))


def resolve_layout(repository: str) -> RepoLayout:
    """The layout of a repository named in svs.yara.repositories. Raises LayoutError."""
    if repository not in get_config().svs.yara.repositories:
        raise LayoutError(f"repository {repository} is not in svs.yara.repositories")

    try:
        repo_config = get_config().get_git_repo_config(repository)
    except ValueError:
        raise LayoutError(f"repository {repository} has no git_repo_{repository} section") from None

    signature_dir = abs_path(get_service_config(SERVICE_YARA_SCANNER).signature_dir)
    return derive_layout(repository, abs_path(repo_config.local_path), signature_dir)


def _is_rule_file(name: str) -> bool:
    return name.lower().endswith(YARA_FILE_EXTENSIONS)


def _rule_files(directory: str) -> list[str]:
    return [
        os.path.join(directory, name) for name in sorted(os.listdir(directory))
        if _is_rule_file(name) and os.path.isfile(os.path.join(directory, name))
    ]


def tree_layout(layout: RepoLayout, tree_root: str) -> TreeLayout:
    """The namespaces of the commit exported at tree_root. Every other rule file in the tree is
    listed as not loaded, with the reason."""
    result = TreeLayout()
    if layout.contained:
        signature_dir = os.path.join(tree_root, layout.signature_dir_path)
        if os.path.isdir(signature_dir):
            for entry in sorted(os.listdir(signature_dir)):
                directory = os.path.join(signature_dir, entry)
                if os.path.isdir(directory):
                    result.namespaces.append(TreeNamespace(entry, directory))
    else:
        for namespace in layout.namespaces:
            directory = os.path.join(tree_root, namespace.path)
            if os.path.isdir(directory):
                result.namespaces.append(TreeNamespace(namespace.name, directory))
            else:
                result.absent.append(namespace.name)

    for namespace in result.namespaces:
        namespace.files = _rule_files(namespace.directory)

    loaded = {path for namespace in result.namespaces for path in namespace.files}
    namespace_dirs = {os.path.realpath(namespace.directory) for namespace in result.namespaces}
    signature_dir = os.path.realpath(os.path.join(tree_root, layout.signature_dir_path)) if layout.contained else None
    for directory, dirnames, filenames in os.walk(tree_root):
        dirnames.sort()
        for name in sorted(filenames):
            path = os.path.join(directory, name)
            if not _is_rule_file(name) or path in loaded:
                continue

            real_directory = os.path.realpath(directory)
            if real_directory in namespace_dirs and not os.path.isfile(path):
                reason = "not a regular file"
            elif real_directory == signature_dir:
                reason = "loose in the signature directory: only the files inside its directories are loaded"
            elif any(_is_under(real_directory, namespace_dir) for namespace_dir in namespace_dirs):
                reason = "nested below a namespace directory: only the files directly inside it are loaded"
            else:
                reason = "not in a directory the yara service loads"

            result.not_loaded.append(NotLoaded(_relative(path, tree_root), reason))

    return result
