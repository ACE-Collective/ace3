"""Seed the database with initial reference data."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from urllib.parse import quote_plus

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from saq.database.model import (
    AnalysisModePriority,
    AuthPermissionCatalog,
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


def get_engine(db_name: str = "ace"):
    password = os.environ.get("ACE_SUPERUSER_DB_USER_PASSWORD") or ""
    if not password:
        with open("/auth/passwords/ace-superuser") as fp:
            password = fp.read().strip()
    password = quote_plus(password)
    host = os.environ.get("ACE_DB_HOST", "ace-db")
    url = f"mysql+pymysql://ace-superuser:{password}@{host}:3306/{db_name}"
    return create_engine(url)


def _ensure(session: Session, model, unique_attr: str, values: list[str]) -> None:
    """Insert rows if they don't already exist, matching on a unique column."""
    existing = {v for (v,) in session.execute(select(getattr(model, unique_attr)))}
    for value in values:
        if value not in existing:
            session.add(model(**{unique_attr: value}))


def seed() -> None:
    engine = get_engine()
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

        # Permission catalog (auto-increment PK — check by unique key)
        existing_perms = {
            (major, minor)
            for major, minor in session.execute(
                select(AuthPermissionCatalog.major, AuthPermissionCatalog.minor)
            )
        }
        permissions = [
            ("system", "read", "Read system metadata and supported types via API."),
            ("email", "read", "Read archived email content via API/GUI."),
            ("alert", "create", "Create new alerts or upload alert data via API/GUI."),
            ("alert", "read", "Read alert data, submissions, status, and files via API/GUI."),
            ("alert", "write", "Modify alerts."),
            ("lock", "delete", "Clear processing locks on alerts or resources."),
            ("event", "read", "View events, details, and export event data."),
            ("event", "write", "Modify events."),
            ("observable", "read", "Query observables via the API."),
            ("observable", "write", "Modify observables."),
            ("user", "read", "Read user data via API/GUI."),
            ("user", "write", "Modify user data via API/GUI."),
        ]
        for major, minor, desc in permissions:
            if (major, minor) not in existing_perms:
                session.add(AuthPermissionCatalog(major=major, minor=minor, description=desc))

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
    engine = get_engine(db_name)
    with Session(engine) as session:
        session.merge(Company(id=1, name="default"))
        session.merge(AnalysisModePriority(analysis_mode="correlation", priority=1))
        session.commit()
    engine.dispose()


if __name__ == "__main__":
    seed()
    seed_unittest("ace-unittest")
    seed_unittest("ace-unittest-2")
