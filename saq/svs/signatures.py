"""What a run's result says about each signature (docs/SVS_RUNS.md, *Results*): its name, its family
and the content hash of the rule itself, from wherever ACE knows the signature: the YARA rule
inventory, the built-in signatures, or the hunts. A signature none of them knows (a deleted rule)
keeps what the caller already had of it."""

import logging
from dataclasses import dataclass
from typing import Iterable, Optional

from saq.configuration.config import get_config
from saq.signatures.builtin import BUILTIN_SIGNATURES
from saq.signatures.model import SignatureType
from saq.svs import windows


@dataclass(frozen=True)
class SignatureInfo:
    uuid: str
    name: Optional[str]
    family: Optional[str]
    # the rule's own content hash (saq.signatures.model.Signature.content_hash)
    content_hash: Optional[str]


def _yara_signatures() -> dict:
    # local: the inventory imports saq.signatures.locations, which imports the yara scanner, and
    # aceapi_v2 imports this module's callers without it (tests/saq/test_imports.py)
    from saq.signatures.yara_inventory import get_yara_inventory

    try:
        return get_yara_inventory(get_config().svs.samples.inventory_refresh_seconds).by_uuid
    except Exception as e:
        logging.warning("unable to read the yara rule inventory for svs run results: %s", e)
        return {}


def describe_signatures(uuids: Iterable[str]) -> dict[str, SignatureInfo]:
    """What ACE currently knows of each signature; one it doesn't know is left out."""
    uuids = set(uuids)
    result: dict[str, SignatureInfo] = {}
    if not uuids:
        return result

    # local: the saq.signatures.loaders package imports the hunter, which imports the engine stack,
    # which imports aceapi_v2, whose run API imports this module through saq.svs.runs
    from saq.signatures.loaders.builtin import load_builtin_signatures

    builtins = {signature.uuid: signature for signature in load_builtin_signatures()}
    for uuid in uuids & set(BUILTIN_SIGNATURES):
        signature = builtins[uuid]
        result[uuid] = SignatureInfo(uuid, signature.name, SignatureType.BUILTIN.value, signature.content_hash)

    remaining = uuids - set(result)
    if remaining:
        hunts = windows.hunt_info()
        for uuid in remaining & set(hunts):
            hunt = hunts[uuid]
            result[uuid] = SignatureInfo(uuid, hunt.name, SignatureType.HUNT.value, hunt.content_hash)

    remaining = uuids - set(result)
    if remaining:
        yara = _yara_signatures()
        for uuid in remaining & set(yara):
            signature = yara[uuid]
            result[uuid] = SignatureInfo(uuid, signature.name, SignatureType.YARA.value, signature.content_hash)

    return result
