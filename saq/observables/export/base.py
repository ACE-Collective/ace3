from abc import ABC, abstractmethod
from dataclasses import dataclass
import hashlib
import json
from collections.abc import Iterable

from saq.observables.export.config import ObservableExportConfig


@dataclass(frozen=True)
class ExportEntry:
    """One detection as it will appear in an export.

    The id is ``observable_detections.id``. It is load bearing, not decoration: the yara export
    embeds it into generated rules as ``$obsd_<id>`` and FileTypeAnalyzer parses it back out to
    resolve which detection fired.
    """

    id: int
    type: str
    value: str


class ObservableExportList:
    """The canonical, order-stable list one export target intends to publish.

    This is what the change detection compares between runs, so it must be built cheaply -- see
    ObservableExport.build_export_list.
    """

    def __init__(self, entries: Iterable[ExportEntry]):
        # sorted so that two runs producing the same set of detections produce the same fingerprint
        # regardless of the order the database handed them back
        self.entries: list[ExportEntry] = sorted(entries, key=lambda entry: (entry.type, entry.id))

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self):
        return iter(self.entries)

    @property
    def types(self) -> list[str]:
        """The observable types present in this list, in sorted order."""
        return sorted({entry.type for entry in self.entries})

    def entries_by_type(self) -> dict[str, list[ExportEntry]]:
        """The entries grouped by observable type."""
        grouped: dict[str, list[ExportEntry]] = {}
        for entry in self.entries:
            grouped.setdefault(entry.type, []).append(entry)

        return grouped

    def fingerprint(self) -> str:
        """A stable hash of this list, used to decide whether an export needs to run at all."""
        canonical = json.dumps(
            [[entry.type, entry.id, entry.value] for entry in self.entries],
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"))

        return hashlib.sha256(canonical.encode("utf8")).hexdigest()


class ObservableExport(ABC):
    """An export target: a system that consumes the observables enabled for detection.

    An export runs in two stages so the common case -- nothing changed since the last run -- is
    cheap enough to schedule every minute:

    1. :meth:`build_export_list` filters the active detections down to what this target would
       publish. It must stay cheap: filtering only, no rendering, no network, no disk.
    2. :meth:`publish` does the expensive work, and only runs when the export list actually changed
       (or the caller passed --force).
    """

    def __init__(self, config: ObservableExportConfig):
        self.config = config

    @classmethod
    def get_config_class(cls) -> type[ObservableExportConfig]:
        """The Pydantic config class used to validate this target's config block.

        Mirrors AnalysisModule.get_config_class(). Targets with their own config fields override
        this to return their ObservableExportConfig subclass.
        """
        return ObservableExportConfig

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    @abstractmethod
    def build_export_list(self, detections: dict[str, list[dict]]) -> ObservableExportList:
        """Returns what this target would publish, given the active detections by type.

        `detections` is the result of
        saq.database.util.observable_detection.get_active_detections_by_type():
        ``{observable_type: [{'id': ..., 'value': ...}, ...]}``.
        """

    @abstractmethod
    def publish(self, export_list: ObservableExportList) -> None:
        """Publishes the given export list to the target system.

        Raises on failure. The caller only records the run as successful if this returns cleanly, so
        a failed publish is retried on the next run rather than being masked by the change check.
        """
