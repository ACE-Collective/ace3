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
