"""Reads ACE's built-in signatures

Built-ins are not loaded from a rule repository at all - they are the static
table of identities in saq/signatures/builtin.py, one per piece of ACE-native
detection logic that has no external rule behind it."""

from saq.signatures.builtin import BUILTIN_SIGNATURES, get_builtin_signature_version
from saq.signatures.loaders.util import content_hash, sort_signatures
from saq.signatures.model import Signature, SignatureType

# the registry is code in this repo rather than a file in a rule repo
BUILTIN_SOURCE_PATH = "saq/signatures/builtin.py"


def load_builtin_signatures() -> list[Signature]:
    """Returns a Signature for every built-in detection signature. Takes no
    parameters: there is nothing to traverse.

    The version is the running ACE version rather than a commit hash, because
    that is what DetectionPoint stamps as signature_version for built-in
    detections - it is what these rows have to join to."""
    version = get_builtin_signature_version()

    return sort_signatures([
        Signature(
            name=builtin.name,
            uuid=builtin.uuid,
            type=SignatureType.BUILTIN,
            version=version,
            git_remote=None,
            source_path=BUILTIN_SOURCE_PATH,
            # the declaration is the content: editing a description is a change
            # to the signature, the same way editing a rule body is
            content_hash=content_hash(f"{builtin.name}\n{builtin.uuid}\n{builtin.description}"),
            tags=(),
        )
        for builtin in BUILTIN_SIGNATURES.values()
    ])
