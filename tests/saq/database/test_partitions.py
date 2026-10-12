import argparse
import time
import uuid
from datetime import date, datetime, timedelta

import pytest

from saq.cli.commands.partitions import cli_maintain
from saq.configuration.config import get_config
from saq.constants import DB_ANALYSIS_RESULT_CACHE, DB_EMAIL_ARCHIVE
from saq.database import partitions
from saq.database.partitions import (
    AUTO_INCREMENT_HEADROOM,
    CATCHALL,
    Granularity,
    ManagedTable,
    Partition,
    PartitionError,
    _swap_in_rebuilt_table,
    get_managed_tables,
    inspect_table,
    maintain_all,
    maintain_table,
    partition_connection,
    partition_name,
    period_start,
    plan_maintenance,
    rebuild_table,
)

# a Monday
TODAY = date(2026, 10, 12)


def _weekly(table: str = "t", retention_days: int = 30) -> ManagedTable:
    return ManagedTable(DB_EMAIL_ARCHIVE, table, "insert_date", Granularity.WEEK, retention_days, 4)


def _bound(value: str) -> datetime:
    return datetime.fromisoformat(value)


#
# partition naming and planning
#

@pytest.mark.unit
def test_period_start_and_names():
    assert period_start(Granularity.WEEK, date(2026, 10, 15)) == date(2026, 10, 12)
    assert period_start(Granularity.DAY, date(2026, 10, 15)) == date(2026, 10, 15)
    assert partition_name(Granularity.DAY, date(2026, 10, 15)) == "p20261015"
    assert partition_name(Granularity.WEEK, date(2026, 10, 12)) == "p2026w42"
    # ISO weeks: 2026 has 53, and the week starting 2025-12-29 is week 1 of 2026
    assert partition_name(Granularity.WEEK, date(2026, 12, 28)) == "p2026w53"
    assert partition_name(Granularity.WEEK, date(2025, 12, 29)) == "p2026w01"


@pytest.mark.unit
def test_plan_for_an_empty_table_covers_retention_and_future_weeks():
    plan = plan_maintenance(_weekly(), [Partition(CATCHALL, None)], TODAY)

    assert plan.drop == []
    # the week holding the cutoff (2026-09-12) through four weeks past the current one
    assert [name for name, _ in plan.create] == [f"p2026w{week}" for week in range(37, 47)]
    assert plan.create[0][1] == date(2026, 9, 14)
    assert plan.create[-1][1] == date(2026, 11, 16)


@pytest.mark.unit
def test_plan_drops_weeks_entirely_past_retention_and_extends_the_top():
    existing = [Partition(f"p2026w{week}", _bound((date(2026, 9, 14) + timedelta(weeks=week - 37)).isoformat()))
                for week in range(37, 47)] + [Partition(CATCHALL, None)]

    plan = plan_maintenance(_weekly(), existing, TODAY + timedelta(weeks=1))

    # cutoff is 2026-09-19: w37 (< 09-14) is all older, w38 (< 09-21) still holds two retained days
    assert plan.drop == ["p2026w37"]
    assert plan.create == [("p2026w47", date(2026, 11, 23))]


@pytest.mark.unit
def test_plan_daily():
    table = ManagedTable(DB_ANALYSIS_RESULT_CACHE, "t", "created_at", Granularity.DAY, 35, 7)
    plan = plan_maintenance(table, [Partition(CATCHALL, None)], TODAY)

    assert plan.create[0] == ("p20260907", date(2026, 9, 8))
    assert plan.create[-1] == ("p20261019", date(2026, 10, 20))
    assert len(plan.create) == 43


@pytest.mark.unit
def test_plan_continues_above_an_unaligned_bound():
    plan = plan_maintenance(_weekly(), [Partition("legacy", _bound("2026-10-14 06:00:00")), Partition(CATCHALL, None)], TODAY)

    assert plan.create[0] == ("p2026w42", date(2026, 10, 19))


@pytest.mark.unit
def test_plan_refuses_a_name_that_is_already_taken():
    with pytest.raises(PartitionError):
        plan_maintenance(_weekly(), [Partition("p2026w45", _bound("2026-10-01")), Partition(CATCHALL, None)], TODAY)


@pytest.mark.unit
def test_email_history_has_its_own_retention(monkeypatch):
    email_archive = get_config().email_archive
    monkeypatch.setattr(email_archive, "partition_retention_days", 30)
    monkeypatch.setattr(email_archive, "email_history_retention_days", 255)

    retention = {t.key: t.retention_days for t in get_managed_tables()}

    assert retention["email_archive.archive"] == 30
    assert retention["email_archive.archive_index"] == 30
    assert retention["email_archive.email_history"] == 255


@pytest.mark.unit
def test_maintain_command_skips_on_a_node_that_is_not_the_primary(monkeypatch):
    monkeypatch.setenv("ACE_IS_PRIMARY_NODE", "0")
    monkeypatch.setattr(partitions, "maintain_all", lambda **kwargs: pytest.fail("maintenance ran"))

    assert cli_maintain(argparse.Namespace(force=False, dry_run=False)) == 0


#
# against the database
#

@pytest.fixture
def scratch(monkeypatch):
    """Creates scratch tables in the email archive database and drops them afterwards.

    Call it with partitioned=False for a table that is not partitioned, and composite_key=True for a
    table keyed like archive_index (several columns, no AUTO_INCREMENT)."""
    created = []
    monkeypatch.setattr(partitions, "CATCHALL_SPLIT_MAX_ROWS", 10)

    def _create(partitioned: bool = True, composite_key: bool = False) -> ManagedTable:
        name = f"pt_{uuid.uuid4().hex[:8]}"
        created.append(name)
        if composite_key:
            columns = ("hash BINARY(32) NOT NULL, archive_id INT NOT NULL, field ENUM('message_id', 'url') NOT NULL, "
                       "insert_date DATETIME NOT NULL, PRIMARY KEY (hash, archive_id, field, insert_date)")
        else:
            columns = ("id BIGINT NOT NULL AUTO_INCREMENT, insert_date DATETIME NOT NULL, value VARCHAR(32) NOT NULL, "
                       "PRIMARY KEY (id, insert_date), KEY idx_insert_date (insert_date)")

        partitioning = f" PARTITION BY RANGE COLUMNS(insert_date) (PARTITION {CATCHALL} VALUES LESS THAN (MAXVALUE))" if partitioned else ""
        with partition_connection(DB_EMAIL_ARCHIVE) as connection, connection.cursor() as cursor:
            cursor.execute(f"CREATE TABLE `{name}` ({columns}){partitioning}")

        return _weekly(name)

    yield _create

    with partition_connection(DB_EMAIL_ARCHIVE) as connection, connection.cursor() as cursor:
        for name in created:
            for suffix in ("", "__old", "__rebuild"):
                cursor.execute(f"DROP TABLE IF EXISTS `{name}{suffix}`")


def _insert(table: ManagedTable, dates: list[datetime]):
    with partition_connection(DB_EMAIL_ARCHIVE) as connection, connection.cursor() as cursor:
        cursor.executemany(f"INSERT INTO `{table.table}` (insert_date, value) VALUES (%s, %s)",
                           [(d, f"row {i}") for i, d in enumerate(dates)])


def _query(sql: str, params=None) -> list:
    with partition_connection(DB_EMAIL_ARCHIVE) as connection, connection.cursor() as cursor:
        cursor.execute(sql, params)
        return list(cursor.fetchall())


def _maintain(table: ManagedTable, today: date = TODAY):
    with partition_connection(DB_EMAIL_ARCHIVE) as connection:
        return maintain_table(connection, table, today)


def _state(table: ManagedTable, name: str | None = None):
    with partition_connection(DB_EMAIL_ARCHIVE) as connection:
        return inspect_table(connection, name or table.table)


def _days_ago(days: int) -> datetime:
    return datetime.combine(TODAY, datetime.min.time()) - timedelta(days=days, hours=-12)


@pytest.mark.integration
def test_maintain_provisions_an_empty_catchall(scratch):
    table = scratch()

    result = _maintain(table)

    assert result.ok, result.problems
    assert result.created == [f"p2026w{week}" for week in range(37, 47)]
    state = _state(table)
    assert [p.name for p in state.partitions] == result.created + [CATCHALL]
    assert state.dated_partitions[-1].upper_bound == datetime(2026, 11, 16)

    # running it again changes nothing
    again = _maintain(table)
    assert again.ok and again.created == [] and again.dropped == []


@pytest.mark.integration
def test_maintain_drops_expired_partitions_and_their_rows(scratch):
    table = scratch()
    _maintain(table)
    _insert(table, [_days_ago(28), _days_ago(1)])

    three_weeks_later = TODAY + timedelta(weeks=3)
    result = _maintain(table, three_weeks_later)

    assert result.ok, result.problems
    assert result.dropped == ["p2026w37", "p2026w38", "p2026w39"]
    assert result.created == ["p2026w47", "p2026w48", "p2026w49"]
    assert [row[0] for row in _query(f"SELECT value FROM `{table.table}`")] == ["row 1"]


@pytest.mark.integration
def test_maintain_splits_a_catchall_holding_a_few_rows(scratch):
    table = scratch()
    _insert(table, [_days_ago(2)] * 5)

    result = _maintain(table)

    assert result.ok, result.problems
    assert _query(f"SELECT COUNT(*) FROM `{table.table}` PARTITION (p2026w41)") == [(5,)]
    assert _state(table).catchall_rows == 0


@pytest.mark.integration
def test_maintain_refuses_to_split_a_full_catchall(scratch):
    table = scratch()
    _insert(table, [_days_ago(days) for days in range(20)])

    result = _maintain(table)

    assert not result.ok
    assert f"ace partitions rebuild {table.key}" in result.problems[0]
    assert result.created == []
    assert [p.name for p in _state(table).partitions] == [CATCHALL]


@pytest.mark.integration
def test_maintain_still_drops_expired_partitions_when_the_catchall_is_full(scratch):
    table = scratch()
    _maintain(table)
    # rows past every provisioned week land in the catchall
    _insert(table, [datetime(2027, 1, 1)] * 20)

    result = _maintain(table, TODAY + timedelta(weeks=3))

    assert not result.ok
    assert result.dropped == ["p2026w37", "p2026w38", "p2026w39"]
    assert result.created == []


@pytest.mark.integration
def test_maintain_gives_up_instead_of_waiting_for_a_busy_table(scratch, monkeypatch):
    monkeypatch.setattr(partitions, "DDL_LOCK_WAIT_TIMEOUT_SECONDS", 1)
    table = scratch()

    # an open transaction that has read the table holds a metadata lock on it until it ends
    with partition_connection(DB_EMAIL_ARCHIVE) as reader, reader.cursor() as cursor:
        cursor.execute("BEGIN")
        cursor.execute(f"SELECT COUNT(*) FROM `{table.table}`")

        started = time.monotonic()
        result = _maintain(table)
        elapsed = time.monotonic() - started

        cursor.execute("ROLLBACK")

    assert not result.ok
    assert "table busy" in result.problems[0]
    assert elapsed < 10
    assert [p.name for p in _state(table).partitions] == [CATCHALL]


@pytest.mark.integration
def test_maintain_partitions_a_small_unpartitioned_table(scratch):
    table = scratch(partitioned=False)
    _insert(table, [_days_ago(3)])

    result = _maintain(table)

    assert result.ok, result.problems
    assert _state(table).partitioned
    assert _query(f"SELECT COUNT(*) FROM `{table.table}` PARTITION (p2026w41)") == [(1,)]


@pytest.mark.integration
def test_maintain_refuses_to_partition_a_large_table(scratch):
    table = scratch(partitioned=False)
    _insert(table, [_days_ago(3)] * 20)

    result = _maintain(table)

    assert not result.ok
    assert not _state(table).partitioned


@pytest.mark.integration
def test_rebuild_dry_run_changes_nothing(scratch):
    table = scratch()
    _insert(table, [_days_ago(days) for days in range(20)])

    result = rebuild_table(table, today=TODAY, out=lambda message: None)

    assert not result.executed and not result.swapped
    assert "would swap in a rebuilt" in result.notes[0]
    assert [p.name for p in _state(table).partitions] == [CATCHALL]


@pytest.mark.integration
def test_rebuild_has_nothing_to_do_for_a_healthy_table(scratch):
    table = scratch()

    result = rebuild_table(table, execute=True, today=TODAY, out=lambda message: None)

    assert not result.swapped
    assert result.notes[0].startswith("nothing to do")


@pytest.mark.integration
def test_rebuild_keeps_retained_rows_and_drops_the_rest(scratch):
    table = scratch()
    old_rows = [_days_ago(days) for days in range(40, 90)]
    retained = [_days_ago(days) for days in range(0, 30)]
    _insert(table, old_rows + retained)
    expected = _query(f"SELECT id, insert_date, value FROM `{table.table}` WHERE insert_date >= '2026-09-07' ORDER BY id")
    highest_id = _query(f"SELECT MAX(id) FROM `{table.table}`")[0][0]

    result = rebuild_table(table, execute=True, today=TODAY, batch_size=7, pause_seconds=0, out=lambda message: None)

    assert result.swapped
    assert result.retained_from == date(2026, 9, 7)
    assert result.rows_copied == len(retained) == len(expected)
    assert result.rows_scanned == len(old_rows) + len(retained)
    assert _query(f"SELECT id, insert_date, value FROM `{table.table}` ORDER BY id") == expected

    state = _state(table)
    assert [p.name for p in state.dated_partitions] == [f"p2026w{week}" for week in range(37, 47)]
    assert state.catchall_rows == 0
    assert not _state(table, table.table + "__old").exists

    # rows written after the swap get ids above every old row
    _insert(table, [_days_ago(0)])
    newest_id = _query(f"SELECT MAX(id) FROM `{table.table}`")[0][0]
    assert newest_id >= highest_id + AUTO_INCREMENT_HEADROOM


@pytest.mark.integration
def test_rebuild_walks_a_composite_primary_key(scratch):
    table = scratch(composite_key=True)
    rows = [(f"{i % 3}".encode().ljust(32, b"\0"), i // 2, "url" if i % 2 else "message_id", _days_ago(i % 60))
            for i in range(200)]
    with partition_connection(DB_EMAIL_ARCHIVE) as connection, connection.cursor() as cursor:
        cursor.executemany(f"INSERT INTO `{table.table}` VALUES (%s, %s, %s, %s)", rows)

    expected = sorted(row for row in rows if row[3] >= datetime(2026, 9, 7))

    result = rebuild_table(table, execute=True, today=TODAY, batch_size=9, pause_seconds=0, out=lambda message: None)

    assert result.rows_scanned == len(rows)
    copied = _query(f"SELECT hash, archive_id, field, insert_date FROM `{table.table}`")
    assert sorted(copied) == expected


@pytest.mark.integration
def test_rebuild_resumes_an_interrupted_copy(scratch):
    table = scratch()
    _insert(table, [_days_ago(days) for days in range(0, 60)])

    # stop after the swap, before anything was copied back
    with partition_connection(DB_EMAIL_ARCHIVE) as connection:
        _swap_in_rebuilt_table(connection, table, TODAY, out=lambda message: None)
    assert _query(f"SELECT COUNT(*) FROM `{table.table}`") == [(0,)]

    messages = []
    result = rebuild_table(table, execute=True, today=TODAY, batch_size=11, pause_seconds=0, out=messages.append)

    assert any("resuming" in message for message in messages)
    assert _query(f"SELECT COUNT(*) FROM `{table.table}`") == [(result.rows_copied,)]
    assert result.rows_copied == len([d for d in range(0, 60) if _days_ago(d) >= datetime(2026, 9, 7)])
    assert not _state(table, table.table + "__old").exists


@pytest.fixture
def restore_managed_tables():
    """Puts the managed tables back the way the migrations leave them."""
    yield
    with partition_connection(DB_EMAIL_ARCHIVE) as connection, connection.cursor() as cursor:
        for table in ("archive", "archive_index", "email_history"):
            cursor.execute(f"ALTER TABLE `{table}` PARTITION BY RANGE COLUMNS(insert_date) "
                           f"(PARTITION {CATCHALL} VALUES LESS THAN (MAXVALUE))")

    with partition_connection(DB_ANALYSIS_RESULT_CACHE) as connection, connection.cursor() as cursor:
        for table in ("analysis_result_cache", "blob_refs"):
            if inspect_table(connection, table).partitioned:
                cursor.execute(f"ALTER TABLE `{table}` REMOVE PARTITIONING")


@pytest.mark.integration
def test_maintain_all_manages_the_configured_tables(restore_managed_tables):
    results = maintain_all(today=TODAY)

    assert [r.key for r in results] == [t.key for t in get_managed_tables()]
    assert all(r.ok for r in results), [r.problems for r in results]
    by_key = {r.key: r for r in results}
    assert by_key["email_archive.archive_index"].created[-1] == "p2026w46"
    # the analysis cache tables are created unpartitioned and get partitioned on the first run
    assert by_key["analysis_result_cache.blob_refs"].created[:2] == [CATCHALL, "p20260907"]
    assert by_key["analysis_result_cache.blob_refs"].created[-1] == "p20261019"
