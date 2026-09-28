import os
import time

import pytest

from saq.cas.cache import ReadCache

D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64


def _fill_with(data: bytes):
    def fill(fp):
        fp.write(data)

    return fill


@pytest.mark.unit
def test_miss_fills_hit_reuses_and_refreshes_mtime(tmp_path):
    cache = ReadCache(str(tmp_path), 1024)
    calls = []

    def fill(fp):
        calls.append(1)
        fp.write(b"data")

    path = cache.get_or_fill("p", D1, fill)
    assert path == cache.path("p", D1)
    assert open(path, "rb").read() == b"data"
    assert len(calls) == 1

    os.utime(path, (1, 1))
    assert cache.get_or_fill("p", D1, fill) == path
    assert len(calls) == 1
    assert os.stat(path).st_mtime > 1


@pytest.mark.unit
def test_failed_fill_leaves_nothing(tmp_path):
    cache = ReadCache(str(tmp_path), 1024)

    def fill(fp):
        fp.write(b"partial")
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        cache.get_or_fill("p", D1, fill)

    assert not os.path.exists(cache.path("p", D1))
    assert not any(name.startswith(".fill-") for _, _, names in os.walk(tmp_path) for name in names)
    assert cache.total_bytes() == 0


@pytest.mark.unit
def test_eviction_oldest_first(tmp_path):
    cache = ReadCache(str(tmp_path), 250)
    p1 = cache.get_or_fill("p", D1, _fill_with(b"a" * 100))
    os.utime(p1, (100, 100))
    p2 = cache.get_or_fill("p", D2, _fill_with(b"b" * 100))
    os.utime(p2, (200, 200))
    assert cache.total_bytes() == 200

    # the third entry pushes the total to 300; the oldest goes
    p3 = cache.get_or_fill("q", D3, _fill_with(b"c" * 100))
    assert not os.path.exists(p1)
    assert os.path.exists(p2) and os.path.exists(p3)
    assert cache.total_bytes() == 200


@pytest.mark.unit
def test_remove_and_clear(tmp_path):
    cache = ReadCache(str(tmp_path), 1024)
    cache.get_or_fill("p", D1, _fill_with(b"x"))
    cache.remove("p", D1)
    cache.remove("p", D1)
    assert cache.total_bytes() == 0
    cache.get_or_fill("p", D2, _fill_with(b"x"))
    cache.clear()
    assert not tmp_path.exists()


@pytest.mark.unit
def test_disabled_cache():
    assert ReadCache("/nonexistent", 0).enabled is False
    assert ReadCache("/nonexistent", 1).enabled is True


@pytest.mark.unit
def test_open_or_fill_refills_an_entry_evicted_before_the_open(tmp_path, monkeypatch):
    # another process's eviction can remove the entry between get_or_fill() returning its path and
    # the caller opening it
    cache = ReadCache(str(tmp_path), 1024)
    calls = []
    get_or_fill = cache.get_or_fill

    def evicting_get_or_fill(pool, digest, fill):
        path = get_or_fill(pool, digest, fill)
        if not calls:
            os.unlink(path)

        calls.append(path)
        return path

    monkeypatch.setattr(cache, "get_or_fill", evicting_get_or_fill)
    with cache.open_or_fill("p", D1, _fill_with(b"data")) as fp:
        assert fp.read() == b"data"

    assert len(calls) == 2


@pytest.mark.unit
def test_eviction_keeps_an_entry_used_since_the_walk(tmp_path, monkeypatch):
    cache = ReadCache(str(tmp_path), 1024)
    p1 = cache.get_or_fill("p", D1, _fill_with(b"a" * 100))
    p2 = cache.get_or_fill("p", D2, _fill_with(b"b" * 100))
    cache.max_bytes = 150
    os.utime(p1, (100, 100))
    os.utime(p2, (200, 200))

    # the walk saw p1 as the oldest, but it was read (its mtime refreshed) before eviction got to it
    entries = cache._entries()
    os.utime(p1)
    monkeypatch.setattr(cache, "_entries", lambda: entries)
    cache._evict_if_needed()
    assert os.path.exists(p1)
    assert not os.path.exists(p2)


@pytest.mark.unit
def test_budget_check_is_throttled(tmp_path, monkeypatch):
    # a check every max_bytes / 100 bytes filled by this process, plus one on its first fill
    cache = ReadCache(str(tmp_path), 10_000)
    checks = []
    monkeypatch.setattr(cache, "_evict_if_needed", lambda: checks.append(1) or 0)
    for n in range(21):
        cache.get_or_fill("p", f"{n:064x}", _fill_with(b"x" * 10))

    # the first fill, then after every further 100 bytes (10 fills of 10 bytes)
    assert len(checks) == 3
