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


def _ensure(session: Session, model, unique_attr: str, values: list[str]) -> None:
    """Insert rows if they don't already exist, matching on a unique column."""
    existing = {v for (v,) in session.execute(select(getattr(model, unique_attr)))}
    for value in values:
        if value not in existing:
            session.add(model(**{unique_attr: value}))


def seed(db_name: str = PRIMARY_DATABASE) -> None:
    """Seeds the primary ACE database with its initial reference data."""
    engine = create_superuser_engine(db_name)
    with Session(engine) as session:
        # Default company and tag (have explicit PKs — merge is safe)
        session.merge(Company(id=1, name="default"))
        session.merge(Tag(id=1, name="whitelisted"))

        # System users (have explicit PKs — merge is safe)
        session.merge(User(
            id=1, username="ace", email="ace@localhost",
            omniscience=0, display_name="automation",
        ))
        session.merge(User(
            id=2, username="analyst",
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
        for user_id, major, minor in [(1, "*", "*"), (2, "*", "*")]:
            if (user_id, major, minor) not in existing_user_perms:
                session.add(AuthUserPermission(user_id=user_id, major=major, minor=minor))

        # Analysis mode priority (PK is analysis_mode — merge is safe)
        session.merge(AnalysisModePriority(analysis_mode="correlation", priority=1))

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
