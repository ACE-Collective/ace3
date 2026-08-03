"""Exports the observables enabled for detection into the local redis cache.

This is the map the analysis engine matches every observable against -- see
saq.modules.observable_detection.ObservableDetectionAnalyzer, which looks up
``f"{observable.type}:{observable.value}"`` and adds a detection point on a hit.

Redis is node-local (each engine node runs its own container), so every node materializes the same
`observable_detections` table into its own copy of the cache.

The rebuild uses two databases: the live one the engine reads, and a scratch one this builds into and
then swaps in. The swap is atomic, so the engine never reads a partially built map and never sees an
empty one.
"""

import logging
from typing import Optional

from saq.constants import REDIS_DB_FOR_DETECTION_A, REDIS_DB_FOR_DETECTION_B
from saq.observables.export.base import ExportEntry, ObservableExport, ObservableExportList
from saq.redis_client import get_redis_connection

# Where the fingerprint of the published list is stored, inside the cache itself.
#
# Deliberately contains no colon: every observable key is "{type}:{value}", so a key without one
# cannot collide with a detection no matter what types are configured.
FINGERPRINT_KEY = "__ace_export_fingerprint__"

# the redis configuration section to use -- must match what ObservableDetectionAnalyzer reads
REDIS_CONFIG_NAME = "local"


class RedisObservableExport(ObservableExport):

    def build_export_list(self, detections: dict[str, list[dict]]) -> ObservableExportList:
        """Every active detection, unfiltered.

        ObservableDetectionAnalyzer declares no valid_observable_types, so it runs against every
        observable type. The cache has to cover all of them.
        """
        return ObservableExportList([
            ExportEntry(id=detection["id"], type=observable_type, value=detection["value"])
            for observable_type, type_detections in detections.items()
            for detection in type_detections
        ])

    def get_last_fingerprint(self) -> Optional[str]:
        """The fingerprint recorded in the live database.

        Read from the cache rather than from a state file on purpose: redis is in-memory, so a
        restart drops the data. Reading the record from the same place as the data means losing one
        loses the other, and the next run rebuilds instead of skipping against an empty cache.
        """
        return get_redis_connection(
            database=REDIS_DB_FOR_DETECTION_A, config_name=REDIS_CONFIG_NAME).get(FINGERPRINT_KEY)

    def record_fingerprint(self, fingerprint: str) -> None:
        """Nothing to do -- publish() already recorded it.

        The fingerprint is written into the database being built, so it swaps into the live database
        together with the data it describes. Writing it here instead would be a second, non-atomic
        step after the swap.
        """

    def publish(self, export_list: ObservableExportList) -> None:
        connection = get_redis_connection(
            database=REDIS_DB_FOR_DETECTION_B, config_name=REDIS_CONFIG_NAME)

        logging.info("rebuilding the for_detection observable cache in redis")

        # only the scratch database, so the live one keeps serving reads throughout the rebuild
        connection.flushdb()

        for entry in export_list:
            connection.set(f"{entry.type}:{entry.value}", entry.id)

        connection.set(FINGERPRINT_KEY, export_list.fingerprint())

        # atomic cutover: readers see either the entire previous generation or the entire new one.
        # what was live becomes the scratch database, flushed at the top of the next rebuild.
        connection.swapdb(REDIS_DB_FOR_DETECTION_A, REDIS_DB_FOR_DETECTION_B)
        logging.info(f"cached {len(export_list)} for_detection observables in redis")
