import base64
import os

from hunt_compiler.models import CompiledHunt

PKG_TOKEN = "__pkg__/"
SUPPORTED_VERSION = 2


def _path_in(temp_dir: str, rel_path: str, what: str) -> str:
    """Join a package-relative path onto temp_dir, refusing one that would land outside it.

    The CompiledHunt comes from the client, so an asset or target path is untrusted: an absolute
    path, or one that climbs out with `..`, would otherwise write or read anywhere the server
    process can.
    """
    if os.path.isabs(rel_path):
        raise ValueError(f"{what} path {rel_path!r} is absolute; it must be relative to the package root")

    root = os.path.realpath(temp_dir)
    resolved = os.path.realpath(os.path.join(root, rel_path))
    if resolved == root or os.path.commonpath([resolved, root]) != root:
        raise ValueError(f"{what} path {rel_path!r} is outside the package root")

    return os.path.join(temp_dir, os.path.normpath(rel_path))


def load_compiled_hunt(compiled: CompiledHunt, temp_dir: str) -> str:
    """Materialize a CompiledHunt into temp_dir and return the target file path.

    Text assets have their ``__pkg__/`` sentinels expanded to
    ``temp_dir + '/'`` before being written, so references embedded in
    YAML/query files point at the materialized files. Executable permission
    bits are restored from ``EmbeddedFile.permissions``. Binary assets
    (``encoding == 'base64'``) are written raw without token expansion.

    Every asset path and the target must stay inside temp_dir; a ValueError is raised before
    anything is written if one does not.
    """
    if compiled.version != SUPPORTED_VERSION:
        raise ValueError(
            f"unsupported CompiledHunt version: {compiled.version} "
            f"(expected {SUPPORTED_VERSION})"
        )

    target_path = _path_in(temp_dir, compiled.target, "target")
    asset_paths = [_path_in(temp_dir, asset.path, "asset") for asset in compiled.assets]

    expansion = temp_dir.rstrip("/") + "/"

    for asset, abs_path in zip(compiled.assets, asset_paths):
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)

        if asset.encoding == "base64":
            with open(abs_path, "wb") as fp:
                fp.write(base64.b64decode(asset.content))
        else:
            content = asset.content.replace(PKG_TOKEN, expansion)
            with open(abs_path, "w", encoding="utf-8") as fp:
                fp.write(content)

        if asset.kind == "executable" and asset.permissions is not None:
            os.chmod(abs_path, asset.permissions)

    return target_path
