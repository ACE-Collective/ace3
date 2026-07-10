import base64
import os

from hunt_compiler.models import CompiledHunt

PKG_TOKEN = "__pkg__/"
SUPPORTED_VERSION = 2


def load_compiled_hunt(compiled: CompiledHunt, temp_dir: str) -> str:
    """Materialize a CompiledHunt into temp_dir and return the target file path.

    Text assets have their ``__pkg__/`` sentinels expanded to
    ``temp_dir + '/'`` before being written, so references embedded in
    YAML/query files point at the materialized files. Executable permission
    bits are restored from ``EmbeddedFile.permissions``. Binary assets
    (``encoding == 'base64'``) are written raw without token expansion.
    """
    if compiled.version != SUPPORTED_VERSION:
        raise ValueError(
            f"unsupported CompiledHunt version: {compiled.version} "
            f"(expected {SUPPORTED_VERSION})"
        )

    expansion = temp_dir.rstrip("/") + "/"

    for asset in compiled.assets:
        abs_path = os.path.join(temp_dir, asset.path)
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

    return os.path.join(temp_dir, compiled.target)
