"""Maintenance of the date-partitioned tables (docs/DATABASE_PARTITIONS.md).

The email archive and analysis result cache tables are RANGE COLUMNS partitioned by a date column:
one partition per day or ISO week, plus ``p_catchall VALUES LESS THAN (MAXVALUE)`` on top. Retention
is enforced by dropping whole partitions, which is instant, instead of deleting rows.

Everything here protects one invariant: ``p_catchall`` stays (nearly) empty. Splitting a partition
copies every row in it, and blocks writes to the table and fills the InnoDB redo log for as long as
the copy runs, so splitting an empty catchall is instant and splitting a full one is an outage. So
maintenance provisions partitions ahead of time, never splits a catchall holding more than
CATCHALL_SPLIT_MAX_ROWS rows, and runs every DDL statement with a short lock_wait_timeout so that it
gives up instead of queueing ahead of the application's writes.

A table whose catchall already holds data is repaired by rebuild_table(), which swaps in a freshly
partitioned copy of the table and copies the rows still inside retention back in small batches.

All of this needs DDL privileges, so it connects as the database superuser (saq.database.admin).
"""

import logging
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from enum import Enum
from typing import Optional

import pymysql
from pymysql.connections import Connection

from saq.configuration.config import get_config, get_database_config
from saq.configuration.schema import DatabaseConfig
from saq.constants import DB_ANALYSIS_RESULT_CACHE, DB_EMAIL_ARCHIVE
from saq.database.admin import SUPERUSER_NAME, get_superuser_password
from saq.util import abs_path

CATCHALL = "p_catchall"

# the most rows a catchall may hold and still be split in place. reorganizing this many rows takes
# well under a second; anything bigger is left for rebuild_table()
CATCHALL_SPLIT_MAX_ROWS = 10_000

# how long a DDL statement may wait for its metadata lock. while it waits it also blocks every new
# statement on the table, so it has to give up quickly rather than queue behind a long transaction
DDL_LOCK_WAIT_TIMEOUT_SECONDS = 5

# MySQL error code for "Lock wait timeout exceeded"
ER_LOCK_WAIT_TIMEOUT = 1205

# how far above the old table's AUTO_INCREMENT counter a rebuilt table starts, to cover the rows the
# application inserts into the old table between reading the counter and the swap
AUTO_INCREMENT_HEADROOM = 1_000_000

REBUILD_SUFFIX = "__rebuild"
OLD_SUFFIX = "__old"


class PartitionError(Exception):
    pass


class TableBusyError(PartitionError):
    """A DDL statement gave up waiting for its metadata lock."""


class Granularity(str, Enum):
    DAY = "day"
    WEEK = "week"


def period_start(granularity: Granularity, value: date) -> date:
    """Returns the first day of the period containing value (weeks start on Monday, as ISO weeks do)."""
    if granularity == Granularity.WEEK:
        return value - timedelta(days=value.weekday())

    return value


def period_length(granularity: Granularity) -> timedelta:
    return timedelta(days=7 if granularity == Granularity.WEEK else 1)


def partition_name(granularity: Granularity, start: date) -> str:
    """Returns the name of the partition for the period starting at start: pYYYYMMDD or pGGGGwVV."""
    if granularity == Granularity.WEEK:
        iso_year, iso_week, _ = start.isocalendar()
        return f"p{iso_year:04d}w{iso_week:02d}"

    return f"p{start:%Y%m%d}"


@dataclass(frozen=True)
class ManagedTable:
    """A table whose partitions are maintained here."""
    database: str           # the ACE database name (database_<name> in the config)
    table: str
    column: str             # the DATETIME column the table is partitioned by
    granularity: Granularity
    retention_days: int     # partitions entirely older than this many days are dropped
    future_periods: int     # how many periods past the current one to provision
    minimum_retention_days: int = 1

    @property
    def key(self) -> str:
        return f"{self.database}.{self.table}"

    def cutoff(self, today: date) -> date:
        """Rows older than this are past retention."""
        return today - timedelta(days=self.retention_days)


def get_managed_tables() -> list[ManagedTable]:
    """Returns every table whose partitions are maintained, configured from the ACE config."""
    config = get_config()
    email_retention = config.email_archive.partition_retention_days
    history_retention = config.email_archive.email_history_retention_days
    cache_retention = config.analysis_cache.partition_retention_days
    return [
        ManagedTable(DB_EMAIL_ARCHIVE, "archive", "insert_date", Granularity.WEEK, email_retention, 4),
        ManagedTable(DB_EMAIL_ARCHIVE, "archive_index", "insert_date", Granularity.WEEK, email_retention, 4),
        ManagedTable(DB_EMAIL_ARCHIVE, "email_history", "insert_date", Granularity.WEEK, history_retention, 4),
        # cache rows live for up to 30 days (the longest module cache_ttl), so a partition must outlive that
        ManagedTable(DB_ANALYSIS_RESULT_CACHE, "analysis_result_cache", "created_at", Granularity.DAY, cache_retention, 7,
                     minimum_retention_days=31),
        ManagedTable(DB_ANALYSIS_RESULT_CACHE, "blob_refs", "created_at", Granularity.DAY, cache_retention, 7,
                     minimum_retention_days=31),
    ]


def get_managed_table(key: str) -> ManagedTable:
    for table in get_managed_tables():
        if table.key == key:
            return table

    known = ", ".join(t.key for t in get_managed_tables())
    raise PartitionError(f"unknown table {key} (known tables: {known})")


@dataclass(frozen=True)
class Partition:
    name: str
    upper_bound: Optional[datetime]     # VALUES LESS THAN this; None for MAXVALUE


@dataclass
class TableState:
    exists: bool
    partitioned: bool = False
    partitions: list[Partition] = field(default_factory=list)
    has_catchall: bool = False
    # rows in p_catchall (or in the whole table when it is not partitioned), counted no higher than
    # CATCHALL_SPLIT_MAX_ROWS + 1 so that a full catchall costs no more to check than an empty one
    catchall_rows: int = 0

    @property
    def catchall_too_full(self) -> bool:
        return self.catchall_rows > CATCHALL_SPLIT_MAX_ROWS

    @property
    def needs_rebuild(self) -> bool:
        """True when maintenance cannot fix the table without blocking writes to it."""
        return self.catchall_too_full or (self.partitioned and not self.has_catchall)

    @property
    def dated_partitions(self) -> list[Partition]:
        return [p for p in self.partitions if p.upper_bound is not None]


@dataclass
class MaintenancePlan:
    drop: list[str] = field(default_factory=list)
    create: list[tuple[str, date]] = field(default_factory=list)   # (name, VALUES LESS THAN)


def plan_maintenance(table: ManagedTable, partitions: list[Partition], today: date) -> MaintenancePlan:
    """Works out which partitions to drop and which to create.

    A partition is dropped once every row it can hold is past retention. New partitions are only
    ever split off the catchall, above every existing partition (RANGE partitions must increase),
    up to the end of the last provisioned period. A table with no dated partitions left gets
    partitions for its whole retention window, which costs nothing when the catchall is empty."""
    plan = MaintenancePlan()
    cutoff = datetime.combine(table.cutoff(today), datetime.min.time())
    remaining = []
    for partition in partitions:
        if partition.upper_bound is None:
            continue

        if partition.upper_bound <= cutoff:
            plan.drop.append(partition.name)
        else:
            remaining.append(partition)

    step = period_length(table.granularity)
    last_bound = period_start(table.granularity, today + step * table.future_periods) + step
    if remaining:
        highest = max(p.upper_bound for p in remaining if p.upper_bound is not None)
        bound = period_start(table.granularity, highest.date())
        while datetime.combine(bound, datetime.min.time()) <= highest:
            bound += step
    else:
        bound = period_start(table.granularity, table.cutoff(today)) + step

    existing_names = {p.name for p in remaining}
    while bound <= last_bound:
        name = partition_name(table.granularity, bound - step)
        if name in existing_names:
            raise PartitionError(f"{table.key} already has a partition named {name} below its highest partition")

        plan.create.append((name, bound))
        bound += step

    return plan


@dataclass
class TableResult:
    key: str
    dropped: list[str] = field(default_factory=list)
    created: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def _connect_kwargs(database_config: DatabaseConfig) -> dict:
    """Connection arguments for the server and database the config names, as the superuser."""
    kwargs: dict = {
        "user": SUPERUSER_NAME,
        "password": get_superuser_password(),
        "database": database_config.database,
        "charset": "utf8mb4",
        "autocommit": True,
    }

    if database_config.unix_socket:
        kwargs["unix_socket"] = database_config.unix_socket
    else:
        kwargs["host"] = database_config.hostname
        kwargs["port"] = database_config.port

    ssl = {}
    if database_config.ssl_ca:
        ssl["ca"] = abs_path(database_config.ssl_ca)
    if database_config.ssl_cert:
        ssl["cert"] = abs_path(database_config.ssl_cert)
    if database_config.ssl_key:
        ssl["key"] = abs_path(database_config.ssl_key)
    if ssl:
        kwargs["ssl"] = ssl

    return kwargs


@contextmanager
def partition_connection(database: str) -> Iterator[Connection]:
    """A superuser connection to the given ACE database, set up for partition DDL."""
    connection = pymysql.connect(**_connect_kwargs(get_database_config(database)))
    try:
        with connection.cursor() as cursor:
            cursor.execute("SET SESSION lock_wait_timeout = %s", (DDL_LOCK_WAIT_TIMEOUT_SECONDS,))
            # information_schema otherwise serves AUTO_INCREMENT (and row estimates) cached for up to a day
            cursor.execute("SET SESSION information_schema_stats_expiry = 0")

        yield connection
    finally:
        connection.close()


def _quote(identifier: str) -> str:
    return "`" + identifier.replace("`", "``") + "`"


def _execute_ddl(connection: Connection, sql: str):
    """Executes a DDL statement, raising TableBusyError if it gave up waiting for its lock."""
    try:
        with connection.cursor() as cursor:
            cursor.execute(sql)
    except pymysql.err.OperationalError as e:
        if e.args and e.args[0] == ER_LOCK_WAIT_TIMEOUT:
            statement = sql if len(sql) <= 100 else sql[:100] + "..."
            raise TableBusyError(f"gave up after waiting {DDL_LOCK_WAIT_TIMEOUT_SECONDS}s for a lock: {statement}") from e

        raise


def _table_exists(connection: Connection, table: str) -> bool:
    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s",
                       (table,))
        return cursor.fetchone()[0] > 0


def _parse_bound(description: Optional[str]) -> Optional[datetime]:
    """Parses a RANGE COLUMNS PARTITION_DESCRIPTION such as '2026-10-19 00:00:00'; None for MAXVALUE."""
    if description is None or description.strip().upper() == "MAXVALUE":
        return None

    return datetime.fromisoformat(description.strip().strip("'"))


def inspect_table(connection: Connection, table: str) -> TableState:
    if not _table_exists(connection, table):
        return TableState(exists=False)

    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT PARTITION_NAME, PARTITION_DESCRIPTION FROM information_schema.PARTITIONS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND PARTITION_NAME IS NOT NULL
            ORDER BY PARTITION_ORDINAL_POSITION""", (table,))
        partitions = [Partition(name, _parse_bound(description)) for name, description in cursor.fetchall()]

    state = TableState(exists=True, partitioned=bool(partitions), partitions=partitions,
                       has_catchall=CATCHALL in {p.name for p in partitions})
    if state.partitioned and not state.has_catchall:
        return state

    source = f"{_quote(table)} PARTITION ({CATCHALL})" if state.partitioned else _quote(table)
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT COUNT(*) FROM (SELECT 1 FROM {source} LIMIT {CATCHALL_SPLIT_MAX_ROWS + 1}) AS sample")
        state.catchall_rows = cursor.fetchone()[0]

    return state


def _partition_definitions(create: list[tuple[str, date]]) -> str:
    definitions = [f"PARTITION {_quote(name)} VALUES LESS THAN ('{bound.isoformat()}')" for name, bound in create]
    definitions.append(f"PARTITION {CATCHALL} VALUES LESS THAN (MAXVALUE)")
    return ", ".join(definitions)


def maintain_table(connection: Connection, table: ManagedTable, today: date, dry_run: bool = False) -> TableResult:
    """Drops the table's expired partitions and provisions the coming ones. Never raises for a
    problem with the table itself; those are reported in the result."""
    result = TableResult(table.key)
    rebuild_hint = f"run `ace partitions rebuild {table.key}` (docs/DATABASE_PARTITIONS.md)"

    if table.retention_days < table.minimum_retention_days:
        result.problems.append(f"retention of {table.retention_days} days is below the minimum of {table.minimum_retention_days}")
        return result

    try:
        state = inspect_table(connection, table.table)
        if not state.exists:
            result.problems.append("table does not exist")
            return result

        if state.partitioned and not state.has_catchall:
            result.problems.append(f"table has no {CATCHALL} partition to split new partitions off; {rebuild_hint}")
            return result

        if not state.partitioned:
            if state.catchall_too_full:
                result.problems.append(f"table is not partitioned and holds more than {CATCHALL_SPLIT_MAX_ROWS} rows; {rebuild_hint}")
                return result

            if dry_run:
                state = TableState(exists=True, partitioned=True, partitions=[Partition(CATCHALL, None)], has_catchall=True,
                                   catchall_rows=state.catchall_rows)
            else:
                # cheap while the table is this small: partitioning copies every row
                _execute_ddl(connection, f"ALTER TABLE {_quote(table.table)} PARTITION BY RANGE COLUMNS({_quote(table.column)}) "
                                         f"(PARTITION {CATCHALL} VALUES LESS THAN (MAXVALUE))")
                logging.info("partitioned %s", table.key)
                state = inspect_table(connection, table.table)

            result.created.append(CATCHALL)

        plan = plan_maintenance(table, state.partitions, today)
        if plan.drop:
            if not dry_run:
                _execute_ddl(connection, f"ALTER TABLE {_quote(table.table)} DROP PARTITION {', '.join(_quote(p) for p in plan.drop)}")
                logging.info("dropped partitions %s from %s", plan.drop, table.key)

            result.dropped.extend(plan.drop)

        if state.catchall_too_full:
            result.problems.append(f"{CATCHALL} holds more than {CATCHALL_SPLIT_MAX_ROWS} rows and cannot be split "
                                   f"without blocking writes to the table; {rebuild_hint}")
        elif plan.create:
            if not dry_run:
                _execute_ddl(connection, f"ALTER TABLE {_quote(table.table)} REORGANIZE PARTITION {CATCHALL} "
                                         f"INTO ({_partition_definitions(plan.create)})")
                logging.info("created partitions %s in %s", [name for name, _ in plan.create], table.key)

            result.created.extend(name for name, _ in plan.create)

    except TableBusyError as e:
        result.problems.append(f"table busy, will try again next run: {e}")
    except (PartitionError, pymysql.err.MySQLError) as e:
        result.problems.append(str(e))

    return result


def maintain_all(today: Optional[date] = None, dry_run: bool = False, tables: Optional[list[ManagedTable]] = None) -> list[TableResult]:
    """Maintains every managed table, one superuser connection per database."""
    today = today or datetime.now(UTC).date()
    tables = get_managed_tables() if tables is None else tables
    results = []
    for database in dict.fromkeys(t.database for t in tables):
        database_tables = [t for t in tables if t.database == database]
        try:
            with partition_connection(database) as connection:
                for table in database_tables:
                    results.append(maintain_table(connection, table, today, dry_run=dry_run))
        except (pymysql.err.MySQLError, RuntimeError) as e:
            done = {r.key for r in results}
            results.extend(TableResult(t.key, problems=[f"unable to connect: {e}"]) for t in database_tables if t.key not in done)

    for result in results:
        if not result.ok:
            logging.error("partition maintenance for %s needs attention: %s", result.key, "; ".join(result.problems))

    return results


#
# rebuild
#

@dataclass
class RebuildResult:
    key: str
    executed: bool = False
    swapped: bool = False
    rows_scanned: int = 0
    rows_copied: int = 0
    retained_from: Optional[date] = None
    notes: list[str] = field(default_factory=list)


def _columns(connection: Connection, table: str) -> tuple[list[str], list[str], Optional[str]]:
    """Returns (all columns, primary key columns, auto_increment column) of a table."""
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT COLUMN_NAME, EXTRA FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s ORDER BY ORDINAL_POSITION""", (table,))
        rows = cursor.fetchall()
        cursor.execute("""
            SELECT COLUMN_NAME FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND INDEX_NAME = 'PRIMARY' ORDER BY SEQ_IN_INDEX""", (table,))
        primary_key = [row[0] for row in cursor.fetchall()]

    auto_increment = next((name for name, extra in rows if "auto_increment" in (extra or "").lower()), None)
    return [name for name, _ in rows], primary_key, auto_increment


def _keyset(columns: list[str], operator: str) -> str:
    """A predicate comparing the key (columns...) to a key of %s placeholders, spelled out as
    a > x OR (a = x AND (b > y OR ...)): MySQL scans an index range for that form but scans the
    whole index for the equivalent row constructor (a, b) > (x, y). operator is > or <=."""
    strict = ">" if operator == ">" else "<"
    column = _quote(columns[0])
    if len(columns) == 1:
        return f"{column} {operator} %s"

    return f"({column} {strict} %s OR ({column} = %s AND {_keyset(columns[1:], operator)}))"


def _keyset_params(key: tuple) -> list:
    params: list = []
    for value in key[:-1]:
        params.extend((value, value))

    params.append(key[-1])
    return params


def _auto_increment_counter(connection: Connection, table: str, column: str) -> int:
    with connection.cursor() as cursor:
        cursor.execute("SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s",
                       (table,))
        counter = cursor.fetchone()[0] or 1
        cursor.execute(f"SELECT MAX({_quote(column)}) FROM {_quote(table)}")
        highest = cursor.fetchone()[0] or 0

    return max(counter, highest + 1)


def _swap_in_rebuilt_table(connection: Connection, table: ManagedTable, today: date, out: Callable[[str], None]):
    """Creates an empty, freshly partitioned copy of the table and atomically swaps it in."""
    rebuild, old = table.table + REBUILD_SUFFIX, table.table + OLD_SUFFIX
    _, _, auto_increment = _columns(connection, table.table)

    # left over from an attempt that stopped before its swap; it was never live
    _execute_ddl(connection, f"DROP TABLE IF EXISTS {_quote(rebuild)}")
    _execute_ddl(connection, f"CREATE TABLE {_quote(rebuild)} LIKE {_quote(table.table)}")
    plan = plan_maintenance(table, [], today)
    _execute_ddl(connection, f"ALTER TABLE {_quote(rebuild)} PARTITION BY RANGE COLUMNS({_quote(table.column)}) "
                             f"({_partition_definitions(plan.create)})")
    out(f"created {rebuild} with {len(plan.create)} partitions from {plan.create[0][0]} to {plan.create[-1][0]}")

    if auto_increment:
        start = _auto_increment_counter(connection, table.table, auto_increment) + AUTO_INCREMENT_HEADROOM
        _execute_ddl(connection, f"ALTER TABLE {_quote(rebuild)} AUTO_INCREMENT = {start}")
        out(f"{auto_increment} continues from {start} in the rebuilt table")

    for attempt in range(1, 13):
        try:
            _execute_ddl(connection, f"RENAME TABLE {_quote(table.table)} TO {_quote(old)}, {_quote(rebuild)} TO {_quote(table.table)}")
            break
        except TableBusyError:
            if attempt == 12:
                raise

            out(f"{table.table} is busy, retrying the swap ({attempt})")
            time.sleep(5)

    out(f"swapped: new writes go to the rebuilt {table.table}; the old table is now {old}")


def _copy_back(connection: Connection, table: ManagedTable, retained_from: date, batch_size: int, pause_seconds: float,
               result: RebuildResult, out: Callable[[str], None]):
    """Copies the rows still inside retention from the old table into the live one, walking the old
    table's primary key in batches. INSERT IGNORE makes it safe to run again after an interruption."""
    old = table.table + OLD_SUFFIX
    columns, primary_key, _ = _columns(connection, old)
    if not primary_key:
        raise PartitionError(f"{old} has no primary key to walk")

    column_list = ", ".join(_quote(c) for c in columns)
    key_list = ", ".join(_quote(c) for c in primary_key)
    insert = (f"INSERT IGNORE INTO {_quote(table.table)} ({column_list}) SELECT {column_list} FROM {_quote(old)} "
              f"WHERE {_quote(table.column)} >= %s")
    last: Optional[tuple] = None
    last_report = time.monotonic()
    while True:
        after = f" AND {_keyset(primary_key, '>')}" if last else ""
        after_params = _keyset_params(last) if last else []
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT {key_list} FROM {_quote(old)} WHERE 1=1{after} ORDER BY {key_list} LIMIT 1 OFFSET {batch_size - 1}",
                           after_params)
            end = cursor.fetchone()
            if end is None:
                copied = cursor.execute(insert + after, [retained_from, *after_params])
                cursor.execute(f"SELECT COUNT(*) FROM {_quote(old)} WHERE 1=1{after}", after_params)
                result.rows_scanned += cursor.fetchone()[0]
                result.rows_copied += copied
                break

            copied = cursor.execute(insert + after + f" AND {_keyset(primary_key, '<=')}",
                                    [retained_from, *after_params, *_keyset_params(end)])

        result.rows_scanned += batch_size
        result.rows_copied += copied
        last = end
        if time.monotonic() - last_report > 30:
            out(f"scanned {result.rows_scanned:,} rows of {old}, copied {result.rows_copied:,}")
            last_report = time.monotonic()

        if pause_seconds:
            time.sleep(pause_seconds)


def rebuild_table(table: ManagedTable, *, execute: bool = False, force: bool = False, today: Optional[date] = None,
                  batch_size: int = 5_000, pause_seconds: float = 0.1,
                  out: Callable[[str], None] = print) -> RebuildResult:
    """Repairs a table whose catchall holds data, without blocking the application's writes.

    1. creates an empty copy of the table, partitioned for the retention window and the coming periods
    2. swaps it in with one atomic RENAME TABLE, so new rows go to the rebuilt table from then on
    3. copies the rows still inside retention back from the old table, a batch at a time
    4. drops the old table, and with it every row past retention

    Lookups miss rows that have not been copied back yet while step 3 runs. If it is interrupted,
    running it again picks up at step 3. Without execute it only reports what it would do."""
    today = today or datetime.now(UTC).date()
    old = table.table + OLD_SUFFIX
    retained_from = period_start(table.granularity, table.cutoff(today))
    result = RebuildResult(table.key, executed=execute, retained_from=retained_from)

    if table.retention_days < table.minimum_retention_days:
        raise PartitionError(f"{table.key}: retention of {table.retention_days} days is below the minimum of {table.minimum_retention_days}")

    with partition_connection(table.database) as connection:
        resuming = _table_exists(connection, old)
        if not resuming:
            state = inspect_table(connection, table.table)
            if not state.exists:
                raise PartitionError(f"{table.key} does not exist")

            if not state.needs_rebuild and not force:
                result.notes.append("nothing to do: `ace partitions maintain` can handle this table (--force rebuilds anyway)")
                return result

        if not execute:
            if resuming:
                result.notes.append(f"{old} exists: would resume copying rows back from it, then drop it")
            else:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT TABLE_ROWS FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s",
                                   (table.table,))
                    estimate = cursor.fetchone()[0] or 0
                result.notes.append(f"would swap in a rebuilt {table.table}, copy back the rows from {retained_from} on "
                                    f"(the table holds roughly {estimate:,} rows in all), and drop the old table "
                                    f"with every row before {retained_from}")
            return result

        if resuming:
            out(f"{old} exists, resuming the copy")
        else:
            _swap_in_rebuilt_table(connection, table, today, out)

        result.swapped = True
        _copy_back(connection, table, retained_from, batch_size, pause_seconds, result, out)
        out(f"copied {result.rows_copied:,} of {result.rows_scanned:,} rows back from {old}")
        _execute_ddl(connection, f"DROP TABLE {_quote(old)}")
        out(f"dropped {old}")

    return result
