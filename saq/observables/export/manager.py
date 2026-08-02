import importlib
import logging
import os
from typing import Optional

from saq.configuration import get_config
from saq.observables.export.base import ObservableExport
from saq.observables.export.config import ObservableExportConfig
from saq.observables.export.state import read_fingerprint, write_fingerprint


def load_observable_export_from_config(config: ObservableExportConfig) -> ObservableExport:
    """Returns an ObservableExport instance as defined by an ObservableExportConfig."""
    module = importlib.import_module(config.python_module)
    class_definition = getattr(module, config.python_class)
    return class_definition(config)


def get_observable_exports(names: Optional[list[str]] = None) -> list[ObservableExport]:
    """Returns the requested export targets, or every enabled target if none were requested.

    A name that is not configured raises a ValueError.
    """
    configs = {config.name: config for config in get_config().observable_exports}

    if names:
        unknown = [name for name in names if name not in configs]
        if unknown:
            raise ValueError(f"unknown observable export target(s): {', '.join(sorted(unknown))} "
                             f"(configured: {', '.join(sorted(configs)) or 'none'})")

        selected = [configs[name] for name in names]
    else:
        selected = [config for config in configs.values() if config.enabled]

    return [load_observable_export_from_config(config) for config in selected]


def run_exports(names: Optional[list[str]] = None, force: bool = False) -> int:
    """Exports the observables enabled for detection to the requested targets.

    Runs in two stages per target: build the export list and compare its fingerprint against what
    that target last published, then publish only if it changed (or force is set). Returns a process
    exit code.
    """
    from saq.database.util.observable_detection import get_active_detections_by_type

    try:
        exports = get_observable_exports(names)
    except ValueError as e:
        logging.error(str(e))
        return os.EX_USAGE

    if not exports:
        logging.info("no observable export targets are enabled")
        return os.EX_OK

    # queried once and shared: every target filters the same set of active detections
    detections = get_active_detections_by_type()

    result = os.EX_OK
    for export in exports:
        try:
            export_list = export.build_export_list(detections)
        except Exception as e:
            logging.error(f"unable to build export list for {export.name}: {e}")
            result = os.EX_SOFTWARE
            continue

        fingerprint = export_list.fingerprint()
        if not force and fingerprint == read_fingerprint(export.name):
            logging.info(f"no updates needed for observable export {export.name}")
            continue

        try:
            export.publish(export_list)
        except Exception as e:
            logging.error(f"unable to publish observable export {export.name}: {e}")
            result = os.EX_SOFTWARE
            continue

        # only recorded after a successful publish, so a failure retries on the next run
        write_fingerprint(export.name, fingerprint)
        logging.info(f"exported {len(export_list)} observables to {export.name}")

    return result
