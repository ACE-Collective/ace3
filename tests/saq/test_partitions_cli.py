"""Tests for the output of the `ace partitions` commands; the partitioning itself is tested in
tests/saq/database/test_partitions.py."""

import json
from datetime import datetime

import pytest

import saq.cli.commands.partitions  # registers the commands
from saq.cli.cli_main import get_cli_parser
from saq.database import partitions
from saq.database.partitions import CATCHALL, CATCHALL_SPLIT_MAX_ROWS, Partition, RebuildResult, TableResult, TableState, get_managed_tables


def _ace(*argv) -> int:
    args = get_cli_parser().parse_args(["partitions", *argv])
    return args.func(args)


@pytest.mark.integration
def test_status_lists_every_managed_table(capsys):
    assert _ace("status", "--json") == 0

    report = json.loads(capsys.readouterr().out)
    assert [row["table"] for row in report] == [table.key for table in get_managed_tables()]
    assert all(row["exists"] for row in report)


def _dated(*bounds: str) -> list[Partition]:
    return [Partition(f"p{bound.replace('-', '')}", datetime.fromisoformat(bound)) for bound in bounds] + [Partition(CATCHALL, None)]


@pytest.mark.integration
def test_status_says_what_each_table_needs(monkeypatch, capsys):
    states = iter([
        TableState(exists=False),
        TableState(exists=True, partitioned=False, catchall_rows=3),
        TableState(exists=True, partitioned=True, partitions=_dated("2026-10-05", "2026-10-12"), has_catchall=True,
                   catchall_rows=CATCHALL_SPLIT_MAX_ROWS + 1),
        TableState(exists=True, partitioned=True, partitions=_dated("2026-10-05", "2026-10-12"), has_catchall=True),
    ])
    monkeypatch.setattr(partitions, "get_managed_tables", lambda: get_managed_tables()[:4])
    monkeypatch.setattr(partitions, "inspect_table", lambda connection, table: next(states))
    keys = [table.key for table in get_managed_tables()[:4]]

    assert _ace("status") == 0

    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split()[:3] == ["TABLE", "PARTS", "OLDEST"]
    assert lines[1].startswith(keys[0]) and lines[1].endswith("MISSING")
    assert lines[2].endswith("not partitioned yet (maintain will partition it)")
    assert lines[3].endswith(f"NEEDS REBUILD: ace partitions rebuild {keys[2]}")
    assert f"> {CATCHALL_SPLIT_MAX_ROWS}" in lines[3]
    assert lines[4].endswith("ok")
    assert lines[4].split()[1:5] == ["2", "p20261005", "p20261012", "2026-10-12"]


@pytest.mark.unit
@pytest.mark.parametrize("dry_run", [False, True])
def test_maintain_reports_each_table(monkeypatch, capsys, dry_run):
    monkeypatch.setenv("ACE_IS_PRIMARY_NODE", "1")
    calls = []

    def _maintain_all(dry_run):
        calls.append(dry_run)
        return [TableResult("db.healthy", dropped=["p20260101"], created=["p20261102"]),
                TableResult("db.broken", problems=["catchall holds rows"])]

    monkeypatch.setattr(partitions, "maintain_all", _maintain_all)

    assert _ace("maintain", *(["--dry-run"] if dry_run else [])) == 1

    assert calls == [dry_run]
    drop, create = ("would drop", "would create") if dry_run else ("dropped", "created")
    assert capsys.readouterr().out.splitlines() == [
        f"db.healthy: {drop} 1, {create} 1",
        "  - p20260101",
        "  + p20261102",
        f"db.broken: {drop} 0, {create} 0 -- NEEDS ATTENTION",
        "  ! catchall holds rows",
    ]


@pytest.mark.unit
def test_maintain_on_a_secondary_node_with_force(monkeypatch):
    monkeypatch.setenv("ACE_IS_PRIMARY_NODE", "0")
    monkeypatch.setattr(partitions, "maintain_all", lambda dry_run: [TableResult("db.healthy")])

    assert _ace("maintain", "--force") == 0


@pytest.mark.unit
@pytest.mark.parametrize("argv, notes, expected", [
    ([], ["would swap in a rebuilt t"], ["would swap in a rebuilt t", "re-run with --execute to do it"]),
    ([], ["nothing to do: `ace partitions maintain` can handle this table"], ["nothing to do: `ace partitions maintain` can handle this table"]),
    (["--execute"], ["swapped in a rebuilt t"], ["swapped in a rebuilt t"]),
])
def test_rebuild(monkeypatch, capsys, argv, notes, expected):
    table = get_managed_tables()[0]
    calls = []

    def _rebuild_table(managed_table, **kwargs):
        calls.append((managed_table, kwargs))
        return RebuildResult(managed_table.key, notes=list(notes))

    monkeypatch.setattr(partitions, "rebuild_table", _rebuild_table)

    assert _ace("rebuild", table.key, "--batch-size", "10", "--pause", "0", *argv) == 0

    assert calls == [(table, dict(execute=bool(argv), force=False, batch_size=10, pause_seconds=0.0))]
    assert capsys.readouterr().out.splitlines() == expected
