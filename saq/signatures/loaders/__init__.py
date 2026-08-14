"""Loads detection signatures

This is intentionally separate from the code that performs detection: nothing
here compiles a yara rule, instantiates a Hunt, or constructs an
ObservableModifierAnalyzer. It reads rules the same way ACE reads them and
reports what signatures exist, where they came from, and what version of them
we are looking at.

There is one loader per signature type, because there is no single traversal
that is correct for all of them - see each module for the mechanism it mirrors.
load_signatures() dispatches to them for callers that have a SignatureType in
hand; callers that know which type they want should just call it directly.
"""

from typing import Callable

from saq.signatures.loaders.builtin import load_builtin_signatures
from saq.signatures.loaders.hunt import load_hunt_signatures
from saq.signatures.loaders.observable_modifier import load_observable_modifier_signatures
from saq.signatures.loaders.yara import load_yara_signatures
from saq.signatures.model import Signature, SignatureLocation, SignatureType

# signature types loaded from a path, and the loader that reads each one. types
# absent from this map take no parameters and are handled by load_signatures.
PATH_LOADERS: dict[SignatureType, Callable[[str], list[Signature]]] = {
    SignatureType.YARA: load_yara_signatures,
    SignatureType.HUNT: load_hunt_signatures,
    SignatureType.OBSERVABLE_MODIFIER: load_observable_modifier_signatures,
}


def load_signatures(signature_type: SignatureType, path: str | None = None) -> list[Signature]:
    """Loads every signature of the given type.

    What path means depends on the type, because each type is laid out the way
    the part of ACE that loads it expects:

        BUILTIN             no path - the signatures are a static table in code
        YARA                a signature_dir holding one subdirectory per rule set
        HUNT                a single hunt rule directory
        OBSERVABLE_MODIFIER the rules yaml file itself
    """
    if signature_type == SignatureType.BUILTIN:
        if path is not None:
            raise ValueError("built-in signatures are not loaded from a path")

        return load_builtin_signatures()

    loader = PATH_LOADERS.get(signature_type)
    if loader is None:
        raise ValueError(f"no signature loader for type {signature_type}")

    if path is None:
        raise ValueError(f"{signature_type} signatures require a path")

    return loader(path)


def load_from_location(location: SignatureLocation) -> list[Signature]:
    """Loads every signature at one of the locations the configuration declares
    (see saq.signatures.locations).

    Each loader is handed the declared checkouts in the form its own mechanism
    uses, which is why this is a match rather than another entry in PATH_LOADERS:
    yara matches rule directories by name against the signature_dir it is given,
    while hunt and observable modifier match a single path by containment."""
    match location.signature_type:
        case SignatureType.YARA:
            return load_yara_signatures(location.path, git_repo_dirs=list(location.git_dirs))
        case SignatureType.HUNT:
            return load_hunt_signatures(location.path, git_dirs=list(location.git_dirs))
        case SignatureType.OBSERVABLE_MODIFIER:
            return load_observable_modifier_signatures(location.path, git_dirs=list(location.git_dirs))

    raise ValueError(f"{location.signature_type} signatures are not loaded from a location")


__all__ = [
    "PATH_LOADERS",
    "load_builtin_signatures",
    "load_from_location",
    "load_hunt_signatures",
    "load_observable_modifier_signatures",
    "load_signatures",
    "load_yara_signatures",
]
