"""Exports the observables enabled for detection into a Splunk KV store collection.

The collection is meant to be used as a lookup by hunts that search for the detections. Each document
carries the detection in two forms:

- ``value``: the detection exactly as ACE stores it. A hunt turns these into search terms, and the
  value a hunt reports back is what becomes the observable on the alert -- so it has to match what
  the analysis engine matches on, case included.
- ``pattern``: the lowercased value wrapped in wildcards, for a lookup definition with
  ``match_type = WILDCARD(pattern)``. Matched against a lowercased field (or the whole lowercased
  event), it tells the hunt which detection an event actually contains.

Documents are keyed on the `observable_detections` row id, which makes publishing an upsert -- a
detection that has not changed simply overwrites itself.
"""

import logging
import re
from typing import Optional

from pydantic import Field

from saq.constants import F_URI_PATH, F_URL
from saq.observables.export.base import (
    ExportEntry,
    ObservableExport,
    ObservableExportList,
    select_detections,
)
from saq.observables.export.config import ObservableExportConfig

# the types whose pattern is matched as a substring of a longer value (a url inside a proxy log line,
# a path inside a full url), and therefore need the parts logs disagree on removed
SUBSTRING_TYPES = frozenset({F_URL, F_URI_PATH})

# a url scheme, per RFC 3986: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) "://"
URL_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://")


def build_pattern(observable_type: str, value: str) -> str:
    """The wildcard pattern a lookup matches the given detection with.

    Lowercased because the hunt lowercases what it matches against; a KV store lookup's own
    case handling is not something to depend on.

    A url is matched as a substring, so its pattern drops the scheme and any trailing slash: a proxy
    logs ``host/path``, a firewall ``host/path/``, and a feed that keeps the scheme may not keep the
    one the analyst typed. The consequence is that a url with no path (``http://evil.com/``) becomes
    ``*evil.com*`` and matches every url on that host -- an analyst who means the host should enable
    an fqdn detection instead.

    A literal ``*`` in the value is left alone on purpose: a WILDCARD lookup has no documented escape,
    and a pattern that matches too much is a better failure than one that silently never matches.
    """
    pattern = value.lower()
    if observable_type in SUBSTRING_TYPES:
        pattern = URL_SCHEME_RE.sub("", pattern).rstrip("/")

    return f"*{pattern}*"


class SplunkKVStoreExportConfig(ObservableExportConfig):
    collection: str = Field(default="", description="the KV store collection to publish into")
    export_list: list[str] = Field(default_factory=list, description="the observable types to export")
    max_export: int = Field(default=500, description="how many documents to send per batch save request")
    api: str = Field(default="default", description="which splunk_config_<name> block to connect through")
    # NOTE: these are only used when the splunk config named by `api` leaves them unset -- SplunkClient
    # overrides both from splunk_config_<api>.user_context / .app_context when those are present.
    user_context: Optional[str] = Field(default=None, description="user context to use if the splunk config does not set one")
    app: Optional[str] = Field(default=None, description="app context to use if the splunk config does not set one")


class SplunkKVStoreExport(ObservableExport):

    @classmethod
    def get_config_class(cls) -> type[ObservableExportConfig]:
        return SplunkKVStoreExportConfig

    def build_export_list(self, detections: dict[str, list[dict]]) -> ObservableExportList:
        """The detections of a configured type."""
        entries = []
        for observable_type, detection in select_detections(detections, self.config.export_list):
            entries.append(
                ExportEntry(id=detection["id"], type=observable_type, value=detection["value"]))

        return ObservableExportList(entries)

    def build_documents(self, export_list: ObservableExportList) -> list[dict]:
        """The KV store documents for the given export list. See the module docstring for the shape."""
        documents = []
        for entry in export_list:
            documents.append({
                "_key": str(entry.id),
                "id": entry.id,
                "type": entry.type,
                "value": entry.value,
                "pattern": build_pattern(entry.type, entry.value),
            })

        return documents

    def publish(self, export_list: ObservableExportList, force: bool = False) -> None:
        # accepted for the interface: this target rewrites everything on every publish,
        # so there is nothing for force to skip past
        collection = self.config.collection
        if not collection:
            raise ValueError(
                f"observable export {self.name} has no collection configured")

        from saq.splunk import SplunkClient

        splunk = SplunkClient(
            self.config.api,
            user_context=self.config.user_context,
            app=self.config.app)

        documents = self.build_documents(export_list)
        desired_keys = {document["_key"] for document in documents}

        current_keys = {
            str(document["_key"]) for document in splunk.kvstore_query(collection)
            if "_key" in document
        }

        stale_keys = current_keys - desired_keys
        if stale_keys:
            # one delete per chunk rather than the one-request-per-id loop this replaces
            for chunk in self._chunked(sorted(stale_keys)):
                splunk.kvstore_delete(collection, {"_key": {"$in": chunk}})

            logging.info(f"deleted {len(stale_keys)} stale observables from "
                         f"splunk kv store collection {collection}")

        if not documents:
            logging.info(f"no observables to export to splunk kv store collection {collection}")
            return

        for chunk in self._chunked(documents):
            splunk.kvstore_batch_save(collection, chunk)

        logging.info(f"exported {len(documents)} observables to splunk kv store "
                     f"collection {collection}")

    def _chunked(self, items: list) -> list[list]:
        """Splits items into request-sized chunks."""
        size = self.config.max_export
        return [items[offset:offset + size] for offset in range(0, len(items), size)]
