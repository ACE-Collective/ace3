"""Which YARA rules this deployment loads, read from rule source.

Read through the signature loader (saq/signatures/loaders/yara.py) at the locations the
configuration declares (service_yara.signature_dir), with `modifiers` and `enabled` read by the same
helpers the scanner module uses (saq/signatures/yara_meta.py). It is the only way to know about a
rule that has never matched anything, and to read a rule's content hash.

Parsing every rule file takes seconds, so the inventory is cached per process. Each caller says how
old an inventory it accepts (YARA QA's listing, yara_qa.inventory_refresh_seconds; SVS capture,
svs.samples.inventory_refresh_seconds), and a rebuild parses only the files that changed.
"""

import logging
import threading
import time
from typing import Optional

from saq.signatures.loaders.yara import ParseCache, load_yara_signatures
from saq.signatures.locations import get_signature_locations
from saq.signatures.model import Signature, SignatureType, YaraInventory
from saq.signatures.yara_meta import is_qa_signature


class _InventoryCache:
    def __init__(self):
        self._lock = threading.Lock()
        self._inventory: Optional[YaraInventory] = None
        # one parse cache per signature_dir
        self._parse_caches: dict[str, ParseCache] = {}

    def get(self, max_age_seconds: float) -> YaraInventory:
        with self._lock:
            if self._inventory is not None and time.monotonic() - self._inventory.built_at < max_age_seconds:
                return self._inventory

            self._inventory = self._build()
            return self._inventory

    def _build(self) -> YaraInventory:
        by_uuid: dict[str, Signature] = {}
        errors = []
        locations = get_signature_locations(SignatureType.YARA)
        if not locations:
            errors.append("no yara signature location is configured")

        for location in locations:
            parse_cache = self._parse_caches.setdefault(location.path, {})
            try:
                signatures = load_yara_signatures(location.path, git_repo_dirs=list(location.git_dirs),
                                                  parse_cache=parse_cache)
            except Exception as e:
                logging.warning("unable to load yara signatures from %s: %s", location.path, e)
                errors.append(f"unable to load yara signatures from {location.path}: {e}")
                continue

            for signature in signatures:
                existing = by_uuid.get(signature.uuid)
                # uuids should be unique; if two rules share one, the one in qa mode wins, because
                # it is the one whose matches YARA QA stores under that uuid (docs/YARA_QA.md)
                if existing is None or (is_qa_signature(signature) and not is_qa_signature(existing)):
                    by_uuid[signature.uuid] = signature

        return YaraInventory(by_uuid=by_uuid, built_at=time.monotonic(), error="; ".join(errors) or None)

    def reset(self) -> None:
        with self._lock:
            self._inventory = None
            self._parse_caches.clear()


_cache = _InventoryCache()


def get_yara_inventory(max_age_seconds: float) -> YaraInventory:
    """The yara rule inventory, rebuilt if the cached one is max_age_seconds old or older (0 always
    rebuilds). Blocking: async callers run it in a thread."""
    return _cache.get(max_age_seconds)


def reset_yara_inventory() -> None:
    """Drop the cached inventory. Used by tests."""
    _cache.reset()
