"""The ACE service wrapper for the yara scanner server (docs/YARA_SCANNER.md)."""

import logging
import os
from typing import Optional

from pydantic import Field, model_validator

from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import SERVICE_YARA_SCANNER
from saq.environment import get_data_dir
from saq.git import get_commit_hash
from saq.service import ACEServiceInterface
from saq.util import abs_path
from saq.yara_scanning.server import ScannerSettings, YaraScannerServer

# what stopping takes beyond the longest scan a worker may be finishing: see YaraScannerServer.stop
SHUTDOWN_MARGIN_SECONDS = 4


class YaraScannerServiceConfig(ServiceConfig):
    socket_dir: str = Field(..., description="relative directory where the unix socket for the yara scanner server is located (relative to DATA_DIR)")
    signature_dir: str = Field(..., description="global configuration of yara rules (relative to SAQ_HOME or absolute path)")
    update_frequency: int = Field(..., description="how often to check the yara rules for changes (in seconds)")
    backlog: int = Field(..., description="parameter to the socket.listen() function (how many connections to backlog)")
    blacklist_path: str = Field(..., description="the blacklist contains a list of rule names (one per line) to exclude from the results")
    scan_failure_dir: str = Field(..., description="a directory that contains all the files that fail to scan (relative to DATA_DIR)")
    default_timeout: int = Field(..., gt=0, description="how long (in seconds) a single scan is allowed to take")
    git_repo_dirs: list[str] = Field(default_factory=list, description="subdirectories of signature_dir that are part of a git repository. matches on their rules report the repo's commit as signature_version, and only new commits (rather than file modifications) trigger a rule reload. entries are a subdirectory name or a path to one. a directory listed here that is not in a git repository is not scanned at all")
    worker_count: Optional[int] = Field(default=None, gt=0, description="how many scanning processes to run; defaults to the number of CPUs this process may use")
    compile_timeout: int = Field(..., gt=0, description="how long (in seconds) compiling the rules may take before a new generation of scanners is given up on")
    io_timeout: float = Field(..., gt=0, description="how long (in seconds) a scanner waits on a client that stops sending or receiving")
    client_queue_timeout: float = Field(..., gt=0, description="how long (in seconds) a client waits for a free scanner before it scans locally instead")
    max_data_bytes: int = Field(..., gt=0, description="the largest data stream (in bytes) a client may send to be scanned")
    max_requests_per_worker: int = Field(..., ge=0, description="replace a scanning process after it served this many requests; 0 disables this")
    qa_spool_dir: str = Field(..., description="relative directory (relative to DATA_DIR) where the scanners spool the matches of rules in QA mode for the qa recorder; it must be on the same filesystem as the engine's storage, or every matched file is copied")
    qa_spool_max_jobs: int = Field(..., ge=0, description="the most QA match jobs the spool may hold before new QA matches are dropped; 0 is no limit")

    @model_validator(mode="after")
    def _shutdown_fits(self) -> "YaraScannerServiceConfig":
        if self.default_timeout + SHUTDOWN_MARGIN_SECONDS >= self.shutdown_deadline_seconds:
            raise ValueError(
                f"default_timeout ({self.default_timeout}) + {SHUTDOWN_MARGIN_SECONDS} must be less than "
                f"shutdown_deadline_seconds ({self.shutdown_deadline_seconds}): a stopping scanner finishes the scan it is running")

        return self


def get_validated_git_repo_dirs() -> list[str]:
    """Returns the configured git_repo_dirs, minus any entry that is not a
    directory inside a git repo."""
    config = get_service_config(SERVICE_YARA_SCANNER)
    signature_dir = abs_path(config.signature_dir)

    result = []
    for entry in config.git_repo_dirs:
        # entries may be a subdirectory name, a relative path or an absolute one
        # (matching YaraScanner._resolve_signature_subdir)
        resolved = entry if os.path.isabs(entry) else os.path.join(signature_dir, entry)

        if not os.path.isdir(resolved):
            logging.error(
                "%s git_repo_dirs entry %s (%s) is not a directory - ignoring it so its rules are still scanned",
                SERVICE_YARA_SCANNER, entry, resolved)
            continue

        if get_commit_hash(resolved) is None:
            logging.error(
                "%s git_repo_dirs entry %s (%s) is not part of a git repository - ignoring it so its rules are "
                "still scanned, but matches on them will have no signature version",
                SERVICE_YARA_SCANNER, entry, resolved)
            continue

        result.append(entry)

    return result


def get_scanner_settings() -> ScannerSettings:
    config = get_service_config(SERVICE_YARA_SCANNER)
    return ScannerSettings(
        socket_dir=os.path.join(get_data_dir(), config.socket_dir),
        signature_dir=abs_path(config.signature_dir),
        git_repo_dirs=tuple(get_validated_git_repo_dirs()),
        worker_count=config.worker_count or os.process_cpu_count() or 1,
        update_frequency=config.update_frequency,
        default_timeout=config.default_timeout,
        compile_timeout=config.compile_timeout,
        io_timeout=config.io_timeout,
        max_data_bytes=config.max_data_bytes,
        max_requests_per_worker=config.max_requests_per_worker,
        backlog=config.backlog,
        qa_spool_dir=os.path.join(get_data_dir(), config.qa_spool_dir),
        qa_spool_max_jobs=config.qa_spool_max_jobs,
    )


class YaraScannerService(ACEServiceInterface):

    def __init__(self):
        self.server = YaraScannerServer(get_scanner_settings())

    def start(self):
        self.server.start()

    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.server.wait_for_start(timeout)

    def start_single_threaded(self):
        # the scanners are processes either way: this just runs the service in the foreground
        self.server.start()
        self.server.wait()

    def stop(self):
        self.server.stop()

    def wait(self):
        self.server.wait()

    @classmethod
    def get_config_class(cls) -> type[ServiceConfig]:
        return YaraScannerServiceConfig
