"""Seeds a database with the reference rows ACE needs before it can start.

``seed()`` is what ``docker/startup/setup.sh`` runs against the primary database on every
start. ``seed_unittest()`` is the much smaller set a test database needs: the rows that
``tests/conftest.py::execute_global_db_setup`` does not delete and re-create itself.
Both connect as the superuser (saq.database.admin) and are idempotent.

The command line front end is ``bin/seed_database.py``.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from saq.database.admin import create_superuser_engine
from saq.database.model import (
    AnalysisModePriority,
    AuthUserPermission,
    Company,
    EventPreventionTool,
    EventRemediation,
    EventRiskLevel,
    EventStatus,
    EventType,
    EventVector,
    Tag,
    ThreatType,
    User,
)
from saq.permissions.catalog import sync_permission_catalog

PRIMARY_DATABASE = "ace"

# the user ACE attributes its own actions to; global.automation_user_id must match it
AUTOMATION_USER_ID = 1
ANALYST_USER_ID = 2


def _ensure(session: Session, model, unique_attr: str, values: list[str]) -> None:
    """Insert rows if they don't already exist, matching on a unique column."""
    existing = {v for (v,) in session.execute(select(getattr(model, unique_attr)))}
    for value in values:
        if value not in existing:
            session.add(model(**{unique_attr: value}))


def _add_if_missing(session: Session, model, key, **values) -> bool:
    """Adds the row with primary key ``key`` unless it exists. A row that exists is left as it
    is: seed() runs on every start, and an operator may have changed it since. Returns True
    when the row was added."""
    if session.get(model, key) is not None:
        return False

    session.add(model(**values))
    return True


def seed(db_name: str = PRIMARY_DATABASE) -> None:
    """Seeds the primary ACE database with its initial reference data."""
    engine = create_superuser_engine(db_name)
    with Session(engine) as session:
        _add_if_missing(session, Company, 1, id=1, name="default")
        _add_if_missing(session, Tag, 1, id=1, name="whitelisted")

        # the analyst account, whose password is public, belongs to a new database only: an
        # operator who changed or deleted it must not get it back on the next start
        new_database = session.execute(select(User.id).limit(1)).first() is None

        _add_if_missing(session, User, AUTOMATION_USER_ID,
            id=AUTOMATION_USER_ID, username="ace", email="ace@localhost",
            omniscience=0, display_name="automation",
        )
        if new_database:
            session.add(User(
                id=ANALYST_USER_ID, username="analyst",
                password_hash="pbkdf2:sha256:150000$MeWyGorw$433cf8984d385cec417cc5081140d3ee3edba8263cd49eb979209c6fabcd56bf",
                email="analyst@localhost", omniscience=0,
                timezone="UTC", display_name="analyst",
            ))

        # Event reference data (auto-increment PK — use _ensure for idempotency)
        _ensure(session, EventStatus, "value",
                ["OPEN", "CLOSED", "IGNORE"])
        _ensure(session, EventRemediation, "value",
                ["not remediated", "cleaned with antivirus", "cleaned manually",
                 "reimaged", "credentials reset", "removed from mailbox",
                 "network block", "domain takedown", "NA", "escalated"])
        _ensure(session, EventVector, "value",
                ["corporate email", "webmail", "usb", "website", "unknown",
                 "business application", "compromised website", "sms", "vpn"])
        _ensure(session, EventRiskLevel, "value",
                ["1", "2", "3", "0"])
        _ensure(session, EventPreventionTool, "value",
                ["response team", "ips", "fw", "proxy", "antivirus",
                 "email filter", "application whitelisting", "user", "edr"])
        _ensure(session, EventType, "value",
                ["phish", "recon", "host compromise", "credential compromise",
                 "web browsing", "pentest", "third party",
                 "large number of customer records", "public media"])

        # Threat types (auto-increment PK)
        _ensure(session, ThreatType, "name",
                ["unknown", "keylogger", "infostealer", "downloader",
                 "botnet", "rat", "ransomware", "rootkit", "fraud",
                 "customer threat", "wiper", "traffic direction system",
                 "advanced persistent threat"])

        # Permission catalog — seed from the authoritative code-defined catalog.
        # prune=False so a fresh seed never removes rows another process may rely on.
        sync_permission_catalog(session, prune=False)

        # Built-in user permissions (auto-increment PK — check by unique key)
        existing_user_perms = {
            (uid, major, minor)
            for uid, major, minor in session.execute(
                select(AuthUserPermission.user_id, AuthUserPermission.major, AuthUserPermission.minor)
            )
        }
        builtin_perms = [(AUTOMATION_USER_ID, "*", "*")]
        if new_database:
            builtin_perms.append((ANALYST_USER_ID, "*", "*"))
        for user_id, major, minor in builtin_perms:
            if (user_id, major, minor) not in existing_user_perms:
                session.add(AuthUserPermission(user_id=user_id, major=major, minor=minor))

        _add_if_missing(session, AnalysisModePriority, "correlation", analysis_mode="correlation", priority=1)

        session.commit()
    engine.dispose()


def seed_unittest(db_name: str) -> None:
    """Seeds a unittest ACE database.

    Only the rows the test suite's database reset leaves alone are needed here: the
    default company (kept by ``DELETE FROM company WHERE name != 'default'``) and the
    correlation analysis mode priority (never touched by the reset). Everything else the
    tests rely on is created by the suite itself."""
    engine = create_superuser_engine(db_name)
    with Session(engine) as session:
        session.merge(Company(id=1, name="default"))
        session.merge(AnalysisModePriority(analysis_mode="correlation", priority=1))
        session.commit()
    engine.dispose()
