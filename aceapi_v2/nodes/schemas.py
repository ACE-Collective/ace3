"""Node schemas for ACE API v2."""

from datetime import datetime

from pydantic import BaseModel


class CollectorStatusRead(BaseModel):
    name: str
    status: str
    backlog_count: int
    last_update: datetime


class NodeRead(BaseModel):
    id: int
    name: str
    location: str
    company_id: int
    status: str
    # operator intent (online/offline), as opposed to the observed state in status.
    # draining sets this to offline so a planned shutdown stays distinguishable from a
    # crash once the node reaches status = stopped.
    expected_state: str
    last_update: datetime
    is_primary: bool
    any_mode: bool
    # outstanding work counts -- used to watch drain progress
    # note that a node can be drained with delayed_analysis_count > 0 when no
    # compatible node exists to transfer the delayed work to (that work resumes
    # when the node starts back up)
    workload_count: int
    delayed_analysis_count: int
    collectors: list[CollectorStatusRead] = []
