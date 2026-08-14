"""Shared helpers for the signature loaders"""

import hashlib


def content_hash(content: str) -> str:
    """Returns the sha256 hex digest of a signature's content."""
    return hashlib.sha256(content.encode("utf-8", errors="surrogateescape")).hexdigest()


def normalize_tags(tags) -> tuple[str, ...]:
    """Returns the given tags as a sorted, deduplicated tuple of non-empty strings.
    Accepts anything iterable (rule files are analyst-authored - a scalar where a
    list was expected shouldn't blow up the load)."""
    if not tags:
        return ()

    if isinstance(tags, str):
        tags = [tags]

    result = set()
    for tag in tags:
        if tag is None:
            continue
        tag = str(tag).strip()
        if tag:
            result.add(tag)

    return tuple(sorted(result))


def sort_signatures(signatures: list) -> list:
    """Returns the signatures in a deterministic order."""
    return sorted(signatures, key=lambda s: (s.source_path, s.name, s.uuid))
