"""Unit tests for the phishkit celery client (saq/phishkit.py).

These cover get_async_scan_result, which every other phishkit test monkeypatches
out. The polling behavior it implements is load-bearing: the engine calls it once
per delayed-analysis pass, per scanned observable.
"""

import os

import pytest

import saq.phishkit
from saq.phishkit import (
    SCANNER_VERSION_FAILURE_TTL_SECONDS,
    SCANNER_VERSION_SUCCESS_TTL_SECONDS,
    get_async_scan_result,
    get_phishkit_scanner_version,
)


class FakeAsyncResult:
    """Stands in for celery's AsyncResult.

    get() records whether it was called and how, so a test can assert the client
    never blocks on a job that isn't finished.
    """

    def __init__(self, ready: bool, result_dir=None):
        self._ready = ready
        self._result_dir = result_dir
        self.get_called = False
        self.get_timeout = None

    def ready(self) -> bool:
        return self._ready

    def get(self, timeout=None):
        self.get_called = True
        self.get_timeout = timeout
        if not self._ready:
            # celery's get() blocks until the timeout elapses and then raises.
            # If the client ever reaches here on an unfinished job it has burned
            # the engine's thread for the whole timeout.
            raise AssertionError("get() must not be called before ready()")
        return self._result_dir


@pytest.mark.unit
def test_get_async_scan_result_returns_none_without_calling_get(monkeypatch):
    """An unfinished job returns None and must not block.

    get() waits on the backend's result consumer -- for redis, draining a pub/sub
    channel -- so polling with it blocks the caller for the full timeout. ready()
    is a plain read of the stored result key.
    """
    fake = FakeAsyncResult(ready=False)
    monkeypatch.setattr("saq.phishkit.AsyncResult", lambda result_id, app=None: fake)

    assert get_async_scan_result("job-1", "/tmp/does-not-matter") is None
    assert not fake.get_called, "must not block on get() for an unfinished job"


@pytest.mark.unit
def test_get_async_scan_result_copies_files_when_ready(tmpdir, monkeypatch):
    """A finished job is collected and its files copied into the output dir."""
    source_dir = str(tmpdir / "scan-output")
    os.makedirs(os.path.join(source_dir, "nested"))
    with open(os.path.join(source_dir, "dom.html"), "w") as fp:
        fp.write("<html></html>")
    with open(os.path.join(source_dir, "nested", "screenshot.png"), "w") as fp:
        fp.write("png")

    fake = FakeAsyncResult(ready=True, result_dir=source_dir)
    monkeypatch.setattr("saq.phishkit.AsyncResult", lambda result_id, app=None: fake)

    output_dir = str(tmpdir / "collected")
    results = get_async_scan_result("job-1", output_dir)

    assert fake.get_called
    assert sorted(os.path.basename(p) for p in results) == ["dom.html", "screenshot.png"]
    # relative paths are preserved, not flattened
    assert os.path.exists(os.path.join(output_dir, "nested", "screenshot.png"))


@pytest.mark.unit
def test_get_async_scan_result_honors_timeout_argument(tmpdir, monkeypatch):
    """The timeout argument must reach get().

    It used to be ignored in favor of a hardcoded 5 -- the engine passes
    timeout=1 and silently got 5.
    """
    source_dir = str(tmpdir / "scan-output")
    os.makedirs(source_dir)

    fake = FakeAsyncResult(ready=True, result_dir=source_dir)
    monkeypatch.setattr("saq.phishkit.AsyncResult", lambda result_id, app=None: fake)

    get_async_scan_result("job-1", str(tmpdir / "collected"), timeout=7)
    assert fake.get_timeout == 7


@pytest.mark.unit
def test_get_async_scan_result_binds_the_phishkit_app(monkeypatch):
    """AsyncResult must be bound to the phishkit app explicitly.

    A bare AsyncResult resolves its backend through celery's current app --
    whichever Celery() the process constructed most recently. In an engine
    worker that has also run the js_deobfuscator client, that is the
    js_deobfuscator app, whose backend is a different redis db where phishkit
    job ids never appear: ready() stays False and every scan on that worker
    times out with no error.
    """
    # constructing the js_deobfuscator app second makes it celery's current
    # app -- the exact state in which a bare AsyncResult reads the wrong db
    from phishkit.phishkit import app as phishkit_app
    from js_deobfuscator.js_deobfuscator import app as js_app  # noqa: F401

    captured = {}

    def fake_async_result(result_id, app=None):
        captured["app"] = app
        return FakeAsyncResult(ready=False)

    monkeypatch.setattr("saq.phishkit.AsyncResult", fake_async_result)

    get_async_scan_result("job-1", "/tmp/does-not-matter")
    assert captured["app"] is phishkit_app


IMAGE = {"image_url": "phishkit:latest", "image_id": "sha256:aaa"}


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class FakeProbe:
    """Stands in for get_phishkit_scanner_image: counts calls, returns or raises."""

    def __init__(self, result=IMAGE):
        self.calls = 0
        self.result = result

    def __call__(self):
        self.calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def clock(monkeypatch):
    saq.phishkit._reset_scanner_version_cache_for_tests()
    fake = FakeClock()
    monkeypatch.setattr("saq.phishkit._now", fake)
    yield fake
    saq.phishkit._reset_scanner_version_cache_for_tests()


@pytest.mark.unit
def test_scanner_version_success_is_cached_for_success_ttl(clock, monkeypatch):
    probe = FakeProbe()
    monkeypatch.setattr("saq.phishkit.get_phishkit_scanner_image", probe)

    assert get_phishkit_scanner_version() == IMAGE
    clock.now += SCANNER_VERSION_SUCCESS_TTL_SECONDS - 1
    assert get_phishkit_scanner_version() == IMAGE
    assert probe.calls == 1

    clock.now += 1
    assert get_phishkit_scanner_version() == IMAGE
    assert probe.calls == 2


@pytest.mark.unit
def test_scanner_version_failure_is_cached_for_failure_ttl(clock, monkeypatch, caplog):
    """A failed probe costs the caller the full celery timeout, so it is not repeated on every
    call, and the warning is logged once per real probe, not once per cached answer."""
    probe = FakeProbe(TimeoutError("The operation timed out."))
    monkeypatch.setattr("saq.phishkit.get_phishkit_scanner_image", probe)

    assert get_phishkit_scanner_version() == {}
    clock.now += SCANNER_VERSION_FAILURE_TTL_SECONDS - 1
    assert get_phishkit_scanner_version() == {}
    assert probe.calls == 1
    assert caplog.text.count("phishkit scanner image query failed") == 1

    # the worker recovers: the next probe after the failure TTL picks it up
    probe.result = IMAGE
    clock.now += 1
    assert get_phishkit_scanner_version() == IMAGE
    assert probe.calls == 2
    assert caplog.text.count("phishkit scanner image query failed") == 1


@pytest.mark.unit
@pytest.mark.parametrize("result", [
    {"image_url": "phishkit:latest", "image_id": None},  # the worker could not docker inspect
    "not a dict",
])
def test_scanner_version_without_image_id_uses_failure_ttl(clock, monkeypatch, result):
    probe = FakeProbe(result)
    monkeypatch.setattr("saq.phishkit.get_phishkit_scanner_image", probe)

    first = get_phishkit_scanner_version()
    assert not first.get("image_id")
    clock.now += SCANNER_VERSION_FAILURE_TTL_SECONDS
    get_phishkit_scanner_version()
    assert probe.calls == 2


@pytest.mark.unit
@pytest.mark.parametrize("task_name", ["phishkit.phishkit.ping", "phishkit.phishkit.scanner_image_id"])
def test_phishkit_probe_tasks_route_to_control_queue(task_name):
    """The probes must not share a queue with scans: a scan worker with every slot busy holds a
    reserved probe until a scan finishes, far past the client's 5 second timeout."""
    from phishkit.phishkit import CONTROL_QUEUE, app

    assert app.amqp.router.route({}, task_name)["queue"].name == CONTROL_QUEUE


@pytest.mark.unit
@pytest.mark.parametrize("task_name", ["phishkit.phishkit.scan_url", "phishkit.phishkit.scan_file", "phishkit.phishkit.maintain_files"])
def test_phishkit_work_tasks_stay_on_default_queue(task_name):
    from phishkit.phishkit import CONTROL_QUEUE, app

    assert app.amqp.router.route({}, task_name)["queue"].name != CONTROL_QUEUE
