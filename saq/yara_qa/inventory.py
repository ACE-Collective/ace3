"""Which YARA rules exist, and which of them are in QA mode (docs/YARA_QA.md).

Read from rule source through the signature inventory (saq/signatures/loaders/yara.py) at the
locations the configuration declares (service_yara.signature_dir), which is the only way to list a
QA rule that has never matched anything. QA mode and enabled are read with the same helpers the
scanner module uses (saq/signatures/yara_meta.py).

Parsing every rule file takes seconds, so the inventory is cached per process: it is rebuilt at
most every yara_qa.inventory_refresh_seconds, and a rebuild parses only the files that changed.
"""

import logging
import threading
import time
from typing import Optional

from saq.configuration.config import get_config
from saq.signatures.loaders.yara import ParseCache, load_yara_signatures
from saq.signatures.locations import get_signature_locations
from saq.signatures.model import Signature, SignatureType
from saq.yara_qa.model import YaraInventory, is_qa_signature


class _InventoryCache:
    def __init__(self):
        self._lock = threading.Lock()
        self._inventory: Optional[YaraInventory] = None
        # one parse cache per signature_dir
        self._parse_caches: dict[str, ParseCache] = {}

    def get(self) -> YaraInventory:
        refresh_seconds = get_config().yara_qa.inventory_refresh_seconds
        with self._lock:
            if self._inventory is not None and time.monotonic() - self._inventory.built_at < refresh_seconds:
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
                # uuids should be unique; if two rules share one, the one in qa mode is the one
                # whose matches are stored under it
                if existing is None or (is_qa_signature(signature) and not is_qa_signature(existing)):
                    by_uuid[signature.uuid] = signature

        return YaraInventory(by_uuid=by_uuid, built_at=time.monotonic(), error="; ".join(errors) or None)

    def reset(self) -> None:
        with self._lock:
            self._inventory = None
            self._parse_caches.clear()


_cache = _InventoryCache()


def get_yara_inventory() -> YaraInventory:
    """The current yara rule inventory (cached; see the module docstring). Blocking: async callers
    run it in a thread."""
    return _cache.get()


def reset_yara_inventory() -> None:
    """Drop the cached inventory. Used by tests."""
    _cache.reset()
