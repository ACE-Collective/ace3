import hashlib
import os
from argparse import Namespace

import pytest
from sqlalchemy import select

from saq.cas import Hold, get_cas
from saq.cli.commands.cas import (
    cli_gc,
    cli_get,
    cli_hold_add,
    cli_hold_release,
    cli_orphans,
    cli_pools,
    cli_purge,
    cli_stat,
    cli_verify,
)
from saq.database.model import CASPurge
from saq.database.pool import get_db

from tests.saq.cas.conftest import age_object, backend_path

pytestmark = pytest.mark.integration

PAYLOAD = b"cli payload " * 100
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


def _maint(**kwargs) -> Namespace:
    args = {"pool": None, "dry_run": False, "force": False, "sample": None, "grace": None}
    args.update(kwargs)
    return Namespace(**args)


def test_pools_lists_configured_and_unconfigured_pools(plain_pool, capsys):
    plain_pool.put(PAYLOAD)
    # rows of a pool that is no longer in the config
    from saq.cas import index
    with index.transaction() as session:
        index.insert_object_if_absent(session, "renamed_pool", "f" * 64, 7, 7, None)

    assert cli_pools(Namespace()) == 0
    out = capsys.readouterr().out
    lines = {line.split()[0]: line for line in out.splitlines()[1:]}
    assert set(lines) == {"test_plain", "test_encrypted", "test_permanent", "renamed_pool"}
    assert "local" in lines["test_plain"] and str(len(PAYLOAD)) in lines["test_plain"]
    assert "system" in lines["test_encrypted"]
    assert "permanent" in lines["test_permanent"]
    assert "NOT CONFIGURED" in lines["renamed_pool"]


def test_stat(plain_pool, capsys):
    plain_pool.put(PAYLOAD, hold=Hold("k", "1"))
    assert cli_stat(Namespace(pool="test_plain", digest=DIGEST)) == 0
    out = capsys.readouterr().out
    assert f"digest         {DIGEST}" in out
    assert "state          present" in out
    assert "hold k:1 expires never" in out

    assert cli_stat(Namespace(pool="test_plain", digest="0" * 64)) == 1
    assert "does not exist" in capsys.readouterr().out

    assert cli_stat(Namespace(pool="no_such_pool", digest=DIGEST)) == 1


def test_get(enc_pool, tmp_path, capsys):
    enc_pool.put(PAYLOAD)
    dest = tmp_path / "out"
    assert cli_get(Namespace(pool="test_encrypted", digest=DIGEST, dest=str(dest), force=False)) == 0
    assert dest.read_bytes() == PAYLOAD

    assert cli_get(Namespace(pool="test_encrypted", digest=DIGEST, dest=str(dest), force=False)) == 1
    assert "exists" in capsys.readouterr().out
    dest.write_bytes(b"stale")
    assert cli_get(Namespace(pool="test_encrypted", digest=DIGEST, dest=str(dest), force=True)) == 0
    assert dest.read_bytes() == PAYLOAD

    assert cli_get(Namespace(pool="test_encrypted", digest="0" * 64, dest=str(tmp_path / "none"), force=False)) == 1
    assert not (tmp_path / "none").exists()


def test_gc_and_primary_node_gate(plain_pool, monkeypatch, capsys):
    digest = plain_pool.put(PAYLOAD)
    age_object(plain_pool, digest, 3600 + 60)

    assert cli_gc(_maint(dry_run=True)) == 0
    out = capsys.readouterr().out
    assert "test_plain: would delete 1 object(s)" in out
    assert "test_permanent: retention permanent, nothing to collect" in out
    assert plain_pool.exists(digest)

    monkeypatch.setenv("ACE_IS_PRIMARY_NODE", "0")
    assert cli_gc(_maint()) == 0
    assert "skipping cas gc: not the primary node" in capsys.readouterr().out
    assert plain_pool.exists(digest)

    assert cli_gc(_maint(force=True, pool="test_plain")) == 0
    out = capsys.readouterr().out
    assert "test_plain: deleted 1 object(s)" in out
    assert "test_permanent" not in out
    assert not plain_pool.exists(digest)


def test_verify_exit_code(plain_pool, capsys):
    digest = plain_pool.put(PAYLOAD)
    assert cli_verify(_maint()) == 0
    assert "test_plain: checked 1, intact 1" in capsys.readouterr().out

    open(backend_path(plain_pool, digest), "wb").write(b"corrupt")
    assert cli_verify(_maint(pool="test_plain")) == 2
    assert f"FAILED test_plain/{digest}" in capsys.readouterr().out
    assert plain_pool.exists(digest)


def test_orphans(plain_pool, capsys):
    orphan = os.path.join(plain_pool.backend.root, plain_pool.key("a" * 64))
    os.makedirs(os.path.dirname(orphan), exist_ok=True)
    open(orphan, "wb").write(b"orphan")
    os.utime(orphan, (1, 1))

    assert cli_orphans(_maint(pool="test_plain", dry_run=True)) == 0
    assert "would delete 1" in capsys.readouterr().out
    assert os.path.exists(orphan)

    assert cli_orphans(_maint(pool="test_plain")) == 0
    assert "deleted 1 (6 bytes)" in capsys.readouterr().out
    assert not os.path.exists(orphan)


def test_hold_and_purge(plain_pool, capsys, monkeypatch):
    plain_pool.put(PAYLOAD, hold=Hold("k", "1"))

    assert cli_hold_add(Namespace(pool="test_plain", digest=DIGEST, id="case-1", actor="counsel")) == 0
    assert plain_pool.holds(DIGEST) == [Hold("k", "1"), Hold.legal("case-1")]

    purge = Namespace(pool="test_plain", digest=DIGEST, reason="mistake", actor="admin", yes=True)
    assert cli_purge(purge) == 1
    assert "legal hold" in capsys.readouterr().out
    assert plain_pool.exists(DIGEST)

    assert cli_hold_release(Namespace(pool="test_plain", digest=DIGEST, id="case-1", actor="counsel")) == 0
    assert cli_hold_release(Namespace(pool="test_plain", digest=DIGEST, id="case-1", actor="counsel")) == 1

    # the prompt: declining aborts, accepting purges
    monkeypatch.setattr("builtins.input", lambda _: "n")
    assert cli_purge(Namespace(pool="test_plain", digest=DIGEST, reason="mistake", actor="admin", yes=False)) == 1
    assert plain_pool.exists(DIGEST)
    monkeypatch.setattr("builtins.input", lambda _: "y")
    assert cli_purge(Namespace(pool="test_plain", digest=DIGEST, reason="mistake", actor="admin", yes=False)) == 0
    assert not plain_pool.exists(DIGEST)

    rows = get_db().execute(select(CASPurge).where(CASPurge.digest == DIGEST)).scalars().all()
    assert [(row.reason, row.actor) for row in rows] == [("mistake", "admin")]

    assert cli_purge(purge) == 1
    assert "does not exist" in capsys.readouterr().out
    assert cli_hold_add(Namespace(pool="test_plain", digest=DIGEST, id="x", actor="a")) == 1
