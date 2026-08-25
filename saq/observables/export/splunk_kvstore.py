"""Exports the observables enabled for detection into a Splunk KV store collection.

The collection is meant to be used as a lookup: each document carries the observable type and its
value wrapped in wildcards, so a Splunk search can match it against a field with `LIKE`.

Documents are keyed on the `observable_detections` row id, which makes publishing an upsert -- a
detection that has not changed simply overwrites itself.
"""

import logging
from typing import Optional

from pydantic import Field

from saq.observables.export.base import (
    ExportEntry,
    ObservableExport,
    ObservableExportList,
    select_detections,
)
from saq.observables.export.config import ObservableExportConfig


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
        """The KV store documents for the given export list.

        The value is lowercased and wrapped in wildcards so the collection works as a lookup; a
        literal `*` in the value is escaped so it stays literal rather than becoming a wildcard.
        """
        documents = []
        for entry in export_list:
            escaped_value = entry.value.lower().replace("*", "\\*")
            documents.append({
                "_key": str(entry.id),
                "id": entry.id,
                "type": entry.type,
                "value": f"*{escaped_value}*",
            })

        return documents

    def publish(self, export_list: ObservableExportList) -> None:
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
