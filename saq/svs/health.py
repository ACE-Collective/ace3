"""The health of service_svs (docs/SVS.md, Part 5, *Health*).

Nothing else tells an operator that the service stopped: runs just stay `started` past their
observation window and validations sit `queued`, which on a quiet day looks the same as a healthy
service with nothing to do. So each of the service's loops records, in svs_service_loops, when it
last went round and when it last failed (record_pass, record_failure), by the database clock, and
service_health() judges them against their intervals, next to what the data shows: runs the timers
should have ended, validations waiting, and validations whose worker stopped renewing its lease.
`ace svs status` prints it, and exits non-zero when the service is not healthy.

Recording never raises: a loop that can't record still does its work, and a missing record shows up
as a stale loop.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.dialects.mysql import insert as mysql_insert

from saq.configuration.config import get_config, get_service_config
from saq.constants import SERVICE_SVS
from saq.database.model import SVSRun, SVSServiceLoop, SVSValidation
from saq.database.private_session import private_transaction
from saq.environment import get_global_runtime_settings
from saq.svs.constants import RunState, ValidationState

# a loop is late once it hasn't gone round for this many of its intervals
STALE_INTERVALS = 3
# and never sooner than this, so a short interval doesn't make a busy pass look like a stopped loop
MIN_STALE_SECONDS = 60
# a queued validation waiting longer than this is reported (it is not unhealthy by itself: one long
# validation keeps the others waiting)
QUEUED_WARNING_SECONDS = 600
MAX_ERROR = 4096


class Loop(StrEnum):
    TIMERS = "timers"
    CATALOG = "catalog"
    COVERAGE = "coverage"
    VALIDATIONS = "validations"


class LoopState(StrEnum):
    OK = "ok"
    # the last pass failed
    FAILING = "failing"
    # it hasn't gone round for STALE_INTERVALS of its interval
    STALE = "stale"
    # it never went round
    NEVER = "never"
    # nothing for it to do in this configuration (no repositories configured)
    IDLE = "idle"


def _db_now(session) -> datetime:
    return session.execute(select(func.now(6))).scalar()


def record_start(loops: list[Loop]) -> None:
    """The service started on this node with these loops."""
    node = get_global_runtime_settings().saq_node
    try:
        with private_transaction() as session:
            now = _db_now(session)
            for loop in loops:
                session.execute(mysql_insert(SVSServiceLoop).values(name=loop.value, node=node, started_at=now)
                                .on_duplicate_key_update(node=node, started_at=now))
    except Exception as e:
        logging.warning("unable to record the start of service_svs: %s", e)


def record_pass(loop: Loop, error: Optional[str] = None) -> None:
    """The loop went round (error None) or failed (with why)."""
    node = get_global_runtime_settings().saq_node
    try:
        with private_transaction() as session:
            now = _db_now(session)
            values = {"failed_at": now, "error": error[:MAX_ERROR]} if error is not None else {"passed_at": now}
            session.execute(mysql_insert(SVSServiceLoop).values(name=loop.value, node=node, started_at=now, **values)
                            .on_duplicate_key_update(node=node, **values))
    except Exception as e:
        logging.warning("unable to record a pass of the svs %s loop: %s", loop.value, e)


def loop_interval(loop: Loop) -> float:
    """How often the loop goes round, in seconds."""
    config = get_config().svs
    if loop == Loop.TIMERS:
        return config.runs.timer_interval_seconds
    if loop == Loop.CATALOG:
        return config.catalog.refresh_interval_seconds
    if loop == Loop.COVERAGE:
        return config.coverage.refresh_interval_seconds
    # an idle worker polls; a busy one renews its lease
    service = get_service_config(SERVICE_SVS)
    return max(service.poll_interval_seconds, service.heartbeat_interval_seconds)


def loop_applies(loop: Loop) -> bool:
    """The loop has something to do in this configuration."""
    config = get_config().svs
    if loop == Loop.CATALOG:
        return bool(config.catalog.repositories)
    if loop == Loop.VALIDATIONS:
        return bool(config.yara.repositories)
    return True


@dataclass
class LoopHealth:
    loop: Loop
    state: LoopState
    interval_seconds: float
    node: Optional[str] = None
    started_at: Optional[datetime] = None
    passed_at: Optional[datetime] = None
    # seconds since the last pass, by the database clock
    age_seconds: Optional[float] = None
    failed_at: Optional[datetime] = None
    error: Optional[str] = None


@dataclass
class ServiceHealth:
    now: datetime
    loops: list[LoopHealth] = field(default_factory=list)
    # started runs whose observation window ended more than STALE_INTERVALS timer intervals ago
    overdue_runs: int = 0
    oldest_overdue_run: Optional[str] = None
    queued_validations: int = 0
    oldest_queued_seconds: Optional[float] = None
    # running validations whose lease expired: their worker stopped
    abandoned_validations: int = 0

    @property
    def problems(self) -> list[str]:
        problems = []
        for loop in self.loops:
            if loop.state == LoopState.NEVER:
                problems.append(f"the {loop.loop.value} loop never ran: is service_svs running on the primary node?")
            elif loop.state == LoopState.STALE:
                problems.append(f"the {loop.loop.value} loop last went round {loop.age_seconds:.0f}s ago "
                                f"(every {loop.interval_seconds:.0f}s): service_svs looks stopped")
            elif loop.state == LoopState.FAILING:
                problems.append(f"the {loop.loop.value} loop is failing: {loop.error}")
        if self.overdue_runs:
            problems.append(f"{self.overdue_runs} started run(s) are past their observation window "
                            f"(oldest {self.oldest_overdue_run}): the run timers are not moving them")
        if self.abandoned_validations:
            problems.append(f"{self.abandoned_validations} running validation(s) have an expired lease: their "
                            "worker stopped")
        return problems

    @property
    def warnings(self) -> list[str]:
        if self.oldest_queued_seconds is not None and self.oldest_queued_seconds > QUEUED_WARNING_SECONDS:
            return [f"{self.queued_validations} validation(s) queued, the oldest for {self.oldest_queued_seconds:.0f}s"]
        return []

    @property
    def healthy(self) -> bool:
        return not self.problems


def _judge(loop: Loop, row: Optional[SVSServiceLoop], now: datetime) -> LoopHealth:
    interval = loop_interval(loop)
    health = LoopHealth(loop=loop, state=LoopState.NEVER, interval_seconds=interval)
    if row is not None:
        health.node, health.started_at, health.passed_at = row.node, row.started_at, row.passed_at
        health.failed_at, health.error = row.failed_at, row.error

    if not loop_applies(loop):
        health.state = LoopState.IDLE
        return health
    if health.passed_at is None and health.failed_at is None:
        return health

    latest = max(t for t in (health.passed_at, health.failed_at) if t is not None)
    health.age_seconds = (now - latest).total_seconds()
    if health.age_seconds > max(STALE_INTERVALS * interval, MIN_STALE_SECONDS):
        health.state = LoopState.STALE
    elif health.failed_at is not None and (health.passed_at is None or health.failed_at > health.passed_at):
        health.state = LoopState.FAILING
    else:
        health.state = LoopState.OK
    return health


def service_health() -> ServiceHealth:
    """How service_svs is doing now (docs/SVS.md, Part 5, *Health*)."""
    lease_seconds = get_service_config(SERVICE_SVS).lease_seconds
    timer_interval = get_config().svs.runs.timer_interval_seconds
    with private_transaction() as session:
        now = _db_now(session)
        rows = {row.name: row for row in session.execute(select(SVSServiceLoop)).scalars()}
        health = ServiceHealth(now=now, loops=[_judge(loop, rows.get(loop.value), now) for loop in Loop])

        overdue = (SVSRun.state == RunState.STARTED.value,
                   SVSRun.observation_ends_at < now - timedelta(seconds=max(STALE_INTERVALS * timer_interval,
                                                                            MIN_STALE_SECONDS)))
        health.overdue_runs = session.execute(select(func.count()).select_from(SVSRun).where(*overdue)).scalar()
        if health.overdue_runs:
            health.oldest_overdue_run = session.execute(
                select(SVSRun.uuid).where(*overdue).order_by(SVSRun.observation_ends_at).limit(1)).scalar()

        queued = session.execute(select(func.count(), func.min(SVSValidation.created_at))
                                 .where(SVSValidation.state == ValidationState.QUEUED.value)).one()
        health.queued_validations = queued[0]
        if queued[1] is not None:
            health.oldest_queued_seconds = (now - queued[1]).total_seconds()

        health.abandoned_validations = session.execute(
            select(func.count()).select_from(SVSValidation)
            .where(SVSValidation.state == ValidationState.RUNNING.value,
                   SVSValidation.heartbeat_at < now - timedelta(seconds=lease_seconds))).scalar()
    return health
