import pytest

from saq.cas import metrics


@pytest.fixture(autouse=True)
def fresh_metrics():
    metrics.reset()
    yield
    metrics.reset()


def _by_phase(pool=None):
    return {(r["operation"], r["phase"]): r for r in metrics.snapshot(pool)}


@pytest.mark.unit
def test_operation_timer_records_total_phases_and_counters():
    with metrics.operation_timer("p", "put") as timer:
        with timer.phase("spool"):
            pass

        timer.count("deduplicated")

    records = _by_phase("p")
    assert set(records) == {("put", "total"), ("put", "spool"), ("put", "deduplicated")}
    assert records[("put", "total")]["count"] == 1
    assert records[("put", "total")]["errors"] == 0
    assert sum(records[("put", "spool")]["buckets"]) == 1
    assert records[("put", "deduplicated")]["total_seconds"] == 0.0


@pytest.mark.unit
def test_an_exception_counts_as_an_error_and_propagates():
    with pytest.raises(ValueError):
        with metrics.operation_timer("p", "hold") as timer:
            with timer.phase("lock"):
                raise ValueError()

    records = _by_phase("p")
    assert records[("hold", "total")]["errors"] == 1
    assert records[("hold", "lock")]["errors"] == 1


@pytest.mark.unit
def test_buckets_and_percentile():
    for seconds in (0.0005, 0.003, 0.003, 0.2, 100.0):
        metrics.record("p", "open", "total", seconds)

    [record] = metrics.snapshot("p")
    buckets = record["buckets"]
    assert record["count"] == 5 and record["max_seconds"] == 100.0
    assert buckets[0] == 1                                   # <= 1 ms
    assert buckets[metrics.BUCKET_BOUNDS.index(0.005)] == 2
    assert buckets[-1] == 1                                  # slower than the last bound
    assert metrics.percentile(buckets, 0.5) == 0.005
    assert metrics.percentile(buckets, 1.0) is None
    assert metrics.percentile([0] * len(buckets), 0.5) is None


@pytest.mark.unit
def test_snapshot_filters_by_pool_and_reset_forgets():
    metrics.record("a", "put", "total", 0.01)
    metrics.record("b", "put", "total", 0.01)
    assert [r["pool"] for r in metrics.snapshot()] == ["a", "b"]
    assert [r["pool"] for r in metrics.snapshot("b")] == ["b"]
    metrics.reset()
    assert metrics.snapshot() == []
