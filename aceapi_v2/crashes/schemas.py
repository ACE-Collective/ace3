"""Schemas for the analysis module crash report API."""

from typing import Optional

from pydantic import BaseModel, Field


class CrashReportFile(BaseModel):
    """One file inside a crash report, relative to the report directory."""
    path: str
    size: int


class CrashReportSummary(BaseModel):
    """One row of the crash report listing, built from the database index."""

    crash_id: str = Field(description="the opaque id logged as crash_id= when the crash happened")
    crash_type: str = Field(description="exception (the module raised), timeout (it hung past maximum_analysis_time), or killed (the worker manager SIGKILLed the worker)")
    insert_date: Optional[str] = None
    node: Optional[str] = Field(default=None, description="the node that wrote this report (its origin)")
    module_path: Optional[str] = None
    module_name: Optional[str] = None
    analysis_mode: Optional[str] = None
    root_uuid: Optional[str] = None
    observable_type: Optional[str] = None
    observable_value: Optional[str] = None
    exception_type: Optional[str] = None
    exception_message: Optional[str] = None
    has_file: bool = Field(default=False, description="true if the report carries the bytes of the file observable the module crashed on")
    local: bool = Field(default=False, description="true if this report is on this node's own disk. With crash_reporting.replicate on, a report that is not local may still be downloadable from the shared copy, or may not be yet; GET /crashes/{crash_id} is the answer (downloadable: true, or a 409). See node for origin.")


class CrashReportDetail(CrashReportSummary):
    """A crash report's full metadata, read from the report directory or from shared storage."""

    downloadable: bool = Field(default=False, description="true if /download will succeed from this node right now. When it would not, this endpoint answers 409 wrong_node instead, so a 200 always carries true.")
    remote: bool = Field(default=False, description="true if this response was served from shared object storage rather than from this node's own disk")
    complete: bool = Field(default=True, description="false if the report has no metadata.json, meaning the worker was killed while writing its own crash report. The report is still served; what is there is still evidence.")
    report_dir: Optional[str] = Field(default=None, description="the report directory, relative to the data dir")
    timestamp: Optional[str] = None
    hostname: Optional[str] = None
    pid: Optional[int] = None
    worker_name: Optional[str] = None
    observable_uuid: Optional[str] = None
    maximum_analysis_time: Optional[int] = None
    module_start_time: Optional[str] = None
    elapsed_seconds: Optional[float] = None
    root_storage_dir: Optional[str] = None
    root_description: Optional[str] = None
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    file_sha256: Optional[str] = None
    omitted: list[dict] = Field(default_factory=list, description="what this report does not contain and why (size caps, missing sources). An empty list means the report is complete.")
    files: list[CrashReportFile] = Field(default_factory=list)
