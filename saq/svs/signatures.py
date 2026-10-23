"""What a run's result says about each signature (docs/SVS_RUNS.md, *Results*): its name, its family
and the content hash of the rule itself, from wherever ACE knows the signature: the YARA rule
inventory, the built-in signatures, or the hunts. A signature none of them knows (a deleted rule)
keeps what the caller already had of it.

And the ATT&CK techniques signatures claim through their mitre: tags (docs/SVS_COVERAGE.md, *Manual
mappings*): a hunt's tags, and a YARA rule's tags, which include its mitre_attack meta."""

import logging
from dataclasses import dataclass
from typing import Iterable, Optional

from saq.configuration.config import get_config
from saq.signatures.builtin import BUILTIN_SIGNATURES
from saq.signatures.loaders.builtin import load_builtin_signatures
from saq.signatures.model import SignatureType
from saq.svs import windows
from saq.svs.attack import normalize_technique_id

MITRE_TAG_PREFIX = "mitre:"


@dataclass(frozen=True)
class SignatureInfo:
    uuid: str
    name: Optional[str]
    family: Optional[str]
    # the rule's own content hash (saq.signatures.model.Signature.content_hash)
    content_hash: Optional[str]


@dataclass(frozen=True)
class SignatureTags:
    """The mitre: tags of one signature."""
    uuid: str
    family: str
    name: Optional[str]
    # its tags count toward coverage: the signature is enabled, and a YARA rule isn't in QA mode
    counts: bool
    # the technique ids its tags name (T1059.001), as written but upper-cased, not yet resolved
    # against the ATT&CK release
    declared: tuple[str, ...]
    # the mitre: tags that aren't technique ids: templated ones ({{ technique }}), tactics, typos
    ignored: tuple[str, ...]


class SignatureTagsUnavailable(Exception):
    """The YARA rules couldn't all be read, so their tags aren't known."""


def _parse_mitre_tags(tags: Iterable[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(declared technique ids, ignored mitre: tags) of a signature's tags."""
    declared, ignored = set(), set()
    for tag in tags:
        if not tag.lower().startswith(MITRE_TAG_PREFIX):
            continue
        value = tag[len(MITRE_TAG_PREFIX):]
        technique = normalize_technique_id(value)
        if technique is None:
            ignored.add(tag)
        else:
            declared.add(technique)
    return tuple(sorted(declared)), tuple(sorted(ignored))


def _yara_inventory_or_raise() -> dict:
    # local: the inventory and the locations import the yara scanner, and aceapi_v2 imports this
    # module's callers without it (tests/saq/test_imports.py)
    from saq.signatures.locations import get_signature_locations
    from saq.signatures.yara_inventory import get_yara_inventory
    from saq.signatures.yara_meta import is_qa_signature

    if not get_signature_locations(SignatureType.YARA):
        return {}

    try:
        inventory = get_yara_inventory(get_config().svs.samples.inventory_refresh_seconds)
    except Exception as e:
        raise SignatureTagsUnavailable(f"unable to read the yara rule inventory: {e}") from e
    if inventory.error:
        raise SignatureTagsUnavailable(inventory.error)
    return {uuid: (signature, signature.enabled and not is_qa_signature(signature))
            for uuid, signature in inventory.by_uuid.items()}


def signature_techniques() -> dict[str, SignatureTags]:
    """The mitre: tags of every hunt and YARA rule that has any, by signature uuid; a uuid both use
    is the hunt's. Raises SignatureTagsUnavailable when a YARA rule location couldn't be read."""
    result: dict[str, SignatureTags] = {}
    for uuid, hunt in windows.hunt_info().items():
        declared, ignored = _parse_mitre_tags(hunt.tags)
        if declared or ignored:
            result[uuid] = SignatureTags(uuid, SignatureType.HUNT.value, hunt.name, hunt.enabled, declared, ignored)

    for uuid, (signature, counts) in _yara_inventory_or_raise().items():
        if uuid in result:
            continue
        declared, ignored = _parse_mitre_tags(signature.tags)
        if declared or ignored:
            result[uuid] = SignatureTags(uuid, SignatureType.YARA.value, signature.name, counts, declared, ignored)
    return result


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
