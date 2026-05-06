"""tests for component B (the long-running asyncio service)."""

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.unit


# --- helpers ---


def _drop(spool: Path, name: str, content: bytes = b"x") -> str:
    """atomically write `content` into spool/<name> via a .new + rename."""
    final = spool / name
    tmp = spool / f"{name}.new"
    tmp.write_bytes(content)
    os.rename(tmp, final)
    return str(final)


def _make_ctx(amc_s3_service, *, s3_client=None, bucket="b", scan_size_bytes=1024,
              yara_rule_path=None, default_decision="allow", spool_dir=".",
              yara_pool=None):
    return amc_s3_service.ServiceContext(
        s3_client=s3_client or MagicMock(),
        bucket=bucket,
        default_decision=default_decision,
        scan_size_bytes=scan_size_bytes,
        yara_rule_path=yara_rule_path,
        spool_dir=spool_dir,
        yara_pool=yara_pool or ThreadPoolExecutor(max_workers=1),
    )


# --- inotify_task ---


async def test_inotify_enqueues_on_moved_to(amc_s3_service, tmp_spool):
    queue: asyncio.Queue = asyncio.Queue()
    in_flight: set = set()

    task = asyncio.create_task(
        amc_s3_service.inotify_task(str(tmp_spool), queue, in_flight)
    )
    try:
        await asyncio.sleep(0.05)  # give the watch time to install
        path = _drop(tmp_spool, "abc123")
        got = await asyncio.wait_for(queue.get(), timeout=2)
        assert got == path
        assert path in in_flight
    finally:
        task.cancel()
        with pytest.raises((asyncio.CancelledError, BaseException)):
            await task


async def test_inotify_ignores_dot_new(amc_s3_service, tmp_spool):
    queue: asyncio.Queue = asyncio.Queue()
    in_flight: set = set()

    task = asyncio.create_task(
        amc_s3_service.inotify_task(str(tmp_spool), queue, in_flight)
    )
    try:
        await asyncio.sleep(0.05)
        # only create the .new file (no rename); inotify must not enqueue it
        (tmp_spool / "incomplete.new").write_bytes(b"x")
        # also do a moved_to of a different file to ensure the watcher is alive
        good = _drop(tmp_spool, "ok")
        got = await asyncio.wait_for(queue.get(), timeout=2)
        assert got == good
        assert queue.empty()
    finally:
        task.cancel()
        with pytest.raises(BaseException):
            await task


async def test_inotify_dedups_against_in_flight(amc_s3_service, tmp_spool):
    queue: asyncio.Queue = asyncio.Queue()
    pre_path = str(tmp_spool / "already-known")
    in_flight: set = {pre_path}

    task = asyncio.create_task(
        amc_s3_service.inotify_task(str(tmp_spool), queue, in_flight)
    )
    try:
        await asyncio.sleep(0.05)
        _drop(tmp_spool, "already-known")
        # nothing should land in the queue (it's marked in-flight)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(queue.get(), timeout=0.3)
    finally:
        task.cancel()
        with pytest.raises(BaseException):
            await task


# --- rescan_task ---


async def test_rescan_finds_orphans(amc_s3_service, tmp_spool):
    queue: asyncio.Queue = asyncio.Queue()
    in_flight: set = set()
    path = _drop(tmp_spool, "orphan")

    task = asyncio.create_task(
        amc_s3_service.rescan_task(str(tmp_spool), queue, in_flight, interval=10)
    )
    try:
        got = await asyncio.wait_for(queue.get(), timeout=2)
        assert got == path
        assert path in in_flight
    finally:
        task.cancel()
        with pytest.raises(BaseException):
            await task


async def test_rescan_skips_dot_new(amc_s3_service, tmp_spool):
    queue: asyncio.Queue = asyncio.Queue()
    in_flight: set = set()
    (tmp_spool / "partial.new").write_bytes(b"x")
    real = _drop(tmp_spool, "complete")

    task = asyncio.create_task(
        amc_s3_service.rescan_task(str(tmp_spool), queue, in_flight, interval=10)
    )
    try:
        got = await asyncio.wait_for(queue.get(), timeout=2)
        assert got == real
        # only one item — the .new was skipped
        await asyncio.sleep(0.1)
        assert queue.empty()
    finally:
        task.cancel()
        with pytest.raises(BaseException):
            await task


# --- process_one ---


async def test_process_one_block_deletes_no_upload(amc_s3_service, tmp_spool, monkeypatch):
    path = _drop(tmp_spool, "blockme")
    monkeypatch.setattr(amc_s3_service, "yara_scan",
                        lambda *a, **kw: amc_s3_service.BLOCK)

    s3 = MagicMock()
    s3.upload_file = AsyncMock()
    ctx = _make_ctx(amc_s3_service, s3_client=s3)
    in_flight = {path}

    await amc_s3_service.process_one(path, ctx, in_flight)

    s3.upload_file.assert_not_awaited()
    assert not os.path.exists(path)
    assert path not in in_flight


async def test_process_one_allow_uploads_then_deletes(amc_s3_service, tmp_spool, monkeypatch):
    path = _drop(tmp_spool, "allowme")
    expected_key = os.path.basename(path)
    monkeypatch.setattr(amc_s3_service, "yara_scan",
                        lambda *a, **kw: amc_s3_service.ALLOW)

    s3 = MagicMock()
    s3.upload_file = AsyncMock()
    ctx = _make_ctx(amc_s3_service, s3_client=s3, bucket="my-bucket")
    in_flight = {path}

    await amc_s3_service.process_one(path, ctx, in_flight)

    s3.upload_file.assert_awaited_once_with(path, "my-bucket", expected_key)
    assert not os.path.exists(path)
    assert path not in in_flight


async def test_process_one_upload_failure_keeps_file(amc_s3_service, tmp_spool, monkeypatch):
    path = _drop(tmp_spool, "uploadfail")
    monkeypatch.setattr(amc_s3_service, "yara_scan",
                        lambda *a, **kw: amc_s3_service.ALLOW)

    s3 = MagicMock()
    s3.upload_file = AsyncMock(side_effect=RuntimeError("nope"))
    ctx = _make_ctx(amc_s3_service, s3_client=s3, bucket="b")
    in_flight = {path}

    await amc_s3_service.process_one(path, ctx, in_flight)

    s3.upload_file.assert_awaited_once()
    assert os.path.exists(path)  # left for rescan to retry
    assert path not in in_flight  # cleared so rescan can re-enqueue


async def test_process_one_ignores_missing_file(amc_s3_service, tmp_spool):
    path = str(tmp_spool / "ghost")
    s3 = MagicMock()
    s3.upload_file = AsyncMock()
    ctx = _make_ctx(amc_s3_service, s3_client=s3)
    in_flight = {path}

    await amc_s3_service.process_one(path, ctx, in_flight)

    s3.upload_file.assert_not_awaited()
    assert path not in in_flight


# --- worker concurrency cap ---


async def test_workers_cap_concurrency(amc_s3_service, monkeypatch):
    """N=2 workers must never run more than 2 process_one invocations at once."""
    active = 0
    high_water = 0
    release = asyncio.Event()

    async def fake_process_one(path, ctx, in_flight):
        nonlocal active, high_water
        active += 1
        high_water = max(high_water, active)
        try:
            await release.wait()
        finally:
            active -= 1
            in_flight.discard(path)

    monkeypatch.setattr(amc_s3_service, "process_one", fake_process_one)

    queue: asyncio.Queue = asyncio.Queue()
    in_flight: set = set()
    ctx = _make_ctx(amc_s3_service)

    for i in range(5):
        path = f"/fake/path-{i}"
        in_flight.add(path)
        await queue.put(path)

    workers = [
        asyncio.create_task(amc_s3_service.worker_task(queue, in_flight, ctx))
        for _ in range(2)
    ]

    # let workers pick up the first batch
    await asyncio.sleep(0.05)
    assert active == 2
    assert high_water == 2

    # release them all; queue should drain
    release.set()

    # wait for queue to be empty + all tasks done
    await asyncio.wait_for(queue.join(), timeout=2)

    for w in workers:
        w.cancel()
    await asyncio.gather(*workers, return_exceptions=True)

    assert high_water == 2  # never exceeded the cap


# --- yara_scan ---


def test_yara_scan_allow(amc_s3_service, tmp_spool, tiny_yara_rule):
    p = tmp_spool / "good"
    p.write_bytes(b"prefix GOOD payload")
    decision = amc_s3_service.yara_scan(str(p), 1024, str(tiny_yara_rule), "allow")
    assert decision == amc_s3_service.ALLOW


def test_yara_scan_block(amc_s3_service, tmp_spool, tiny_yara_rule):
    p = tmp_spool / "bad"
    p.write_bytes(b"prefix BAD payload")
    decision = amc_s3_service.yara_scan(str(p), 1024, str(tiny_yara_rule), "allow")
    assert decision == amc_s3_service.BLOCK


def test_yara_scan_no_rule_returns_default(amc_s3_service, tmp_spool):
    p = tmp_spool / "nope"
    p.write_bytes(b"anything")
    assert amc_s3_service.yara_scan(str(p), 1024, None, "allow") == "allow"
    assert amc_s3_service.yara_scan(str(p), 1024, None, "block") == "block"


def test_yara_scan_only_reads_first_n_bytes(amc_s3_service, tmp_spool, tiny_yara_rule):
    """if BAD is past the scan window, decision should fall back to default."""
    p = tmp_spool / "late-bad"
    # 'BAD' appears at byte 100, but we only scan the first 50 bytes
    p.write_bytes(b"a" * 100 + b"BAD" + b"a" * 100)
    decision = amc_s3_service.yara_scan(str(p), 50, str(tiny_yara_rule), "allow")
    assert decision == amc_s3_service.ALLOW
