"""The alert router registry (saq/alert_routing/registry.py)."""

import importlib.util
import logging
import os
import sys
import threading

import pytest
import yaml

from saq.alert_routing import (
    AlertRouter,
    RouteDecision,
    RouteStage,
    clear_alert_routers,
    get_alert_router_load_errors,
    get_alert_routers,
    load_alert_routers,
    register_alert_router,
    route_alert,
)
from saq.alert_routing.detection_queue import DetectionQueueRouter
from saq.configuration.config import get_config
from saq.configuration.schema import AlertRouterConfig
from saq.environment import get_base_dir
from tests.saq.helpers import create_root_analysis

pytestmark = pytest.mark.unit


class FixedRouter(AlertRouter):
    """Routes everything to one queue (configured), at PRE_INSERT only unless told otherwise."""

    def __init__(self, name: str, priority: int, queue: str = "fixed", stages=("pre_insert",)):
        super().__init__(name=name, priority=priority)
        self.queue = queue
        self.stages = set(stages)
        self.calls = 0

    def route(self, root, stage):
        self.calls += 1
        if stage.value not in self.stages:
            return None
        return RouteDecision(queue=self.queue, reason=f"{self.name} says so", router="ignored")


class NeverRouter(AlertRouter):
    def route(self, root, stage):
        return None


class RaisingRouter(AlertRouter):
    def route(self, root, stage):
        raise RuntimeError("router is broken")


class BadReturnRouter(AlertRouter):
    def route(self, root, stage):
        return "a queue name instead of a decision"


class FailingConstructorRouter(AlertRouter):
    def __init__(self, name, priority, **kwargs):
        raise RuntimeError("cannot build")


def _config(name, python_class, priority, **kwargs) -> AlertRouterConfig:
    return AlertRouterConfig(name=name, python_module=__name__, python_class=python_class,
                             priority=priority, kwargs=kwargs)


@pytest.fixture
def configured(monkeypatch):
    """Sets alert_routers: in the running configuration."""
    def _set(*router_configs):
        monkeypatch.setattr(get_config(), "alert_routers", list(router_configs))
        load_alert_routers(force=True)
    return _set


class TestOrder:
    def test_the_built_in_router_is_always_present(self):
        assert any(isinstance(r, DetectionQueueRouter) for r in get_alert_routers())
        clear_alert_routers()
        assert any(isinstance(r, DetectionQueueRouter) for r in get_alert_routers())

    def test_lowest_priority_runs_first_and_the_first_decision_wins(self):
        late = FixedRouter("late", 300, queue="late")
        early = FixedRouter("early", 100, queue="early")
        register_alert_router(late)
        register_alert_router(early)

        decision = route_alert(create_root_analysis(), RouteStage.PRE_INSERT)
        assert decision.queue == "early"
        # the registry names the router that decided, whatever the router put there
        assert decision.router == "early"
        assert late.calls == 0

    def test_ahead_of_the_detection_queue_router(self):
        """A router with a lower priority than 500 decides before a detection's queue meta does
        (FR-2: the SVS marker router must see an alert before a yara `queue` meta takes it)."""
        root = create_root_analysis()
        root.add_detection_point("yara hit", queue="experimental")
        register_alert_router(FixedRouter("marker", 100, queue="svs"))

        assert route_alert(root, RouteStage.PRE_INSERT).queue == "svs"

    def test_no_decision(self):
        register_alert_router(NeverRouter("never", 100))
        assert route_alert(create_root_analysis(), RouteStage.PRE_INSERT) is None

    def test_stages_are_passed_through(self):
        register_alert_router(FixedRouter("post_only", 100, queue="moved", stages=("post_analysis",)))
        root = create_root_analysis()
        assert route_alert(root, RouteStage.PRE_INSERT) is None
        assert route_alert(root, RouteStage.POST_ANALYSIS).queue == "moved"

    def test_names_are_unique(self):
        register_alert_router(NeverRouter("twice", 100))
        with pytest.raises(ValueError):
            register_alert_router(NeverRouter("twice", 200))
        with pytest.raises(ValueError):
            register_alert_router(NeverRouter("detection_queue", 200))

    def test_the_decision_is_logged(self, caplog):
        register_alert_router(FixedRouter("logged", 100, queue="logged_queue"))
        root = create_root_analysis()
        with caplog.at_level(logging.INFO):
            route_alert(root, RouteStage.PRE_INSERT)

        (record,) = [r for r in caplog.records if r.getMessage() == "alert router decided a queue"]
        assert (record.alert_uuid, record.stage, record.router, record.queue) == (
            root.uuid, "pre_insert", "logged", "logged_queue")


class TestFailures:
    def test_a_raising_router_is_reported_and_skipped(self, monkeypatch):
        """A router never breaks the alert insert or the analysis pass it runs inside."""
        reported = []
        monkeypatch.setattr("saq.alert_routing.registry.report_exception", lambda *a, **k: reported.append(1))
        register_alert_router(RaisingRouter("broken", 100))
        register_alert_router(FixedRouter("fallback", 200, queue="fallback"))

        assert route_alert(create_root_analysis(), RouteStage.PRE_INSERT).queue == "fallback"
        assert reported == [1]

    def test_a_router_returning_something_else_is_skipped(self, monkeypatch):
        monkeypatch.setattr("saq.alert_routing.registry.report_exception", lambda *a, **k: None)
        register_alert_router(BadReturnRouter("bad", 100))
        assert route_alert(create_root_analysis(), RouteStage.PRE_INSERT) is None

    @pytest.mark.parametrize("queue", ["", "   ", "q" * 65, None])
    def test_a_decision_needs_a_usable_queue(self, queue):
        with pytest.raises(ValueError):
            RouteDecision(queue=queue, reason="x")


class TestConfiguration:
    def test_configured_routers_are_loaded(self, configured):
        configured(_config("from_config", "FixedRouter", 150, queue="configured"))

        assert [r.name for r in get_alert_routers()] == ["from_config", "detection_queue"]
        assert route_alert(create_root_analysis(), RouteStage.PRE_INSERT).queue == "configured"

    def test_one_broken_entry_does_not_stop_the_others(self, configured):
        configured(
            _config("cannot_build", "FailingConstructorRouter", 100),
            _config("missing_class", "NoSuchRouter", 110),
            AlertRouterConfig(name="missing_module", python_module="no.such.module", python_class="X", priority=120),
            _config("not_a_router", "_config", 130),
            _config("detection_queue", "NeverRouter", 140),  # a built-in's name
            _config("works", "FixedRouter", 200, queue="works"),
        )

        assert [r.name for r in get_alert_routers()] == ["works", "detection_queue"]
        assert set(get_alert_router_load_errors()) == {
            "cannot_build", "missing_class", "missing_module", "not_a_router", "detection_queue"}
        assert route_alert(create_root_analysis(), RouteStage.PRE_INSERT).queue == "works"

    def test_unknown_kwargs_are_a_load_error(self, configured):
        configured(_config("typo", "NeverRouter", 100, colour="red"))
        assert "typo" in get_alert_router_load_errors()

    def test_loading_never_leaves_an_empty_registry(self, configured, monkeypatch):
        """route_alert runs on many threads in the GUI and API; a reload must swap the routers in
        whole, never clear them first."""
        configured(_config("steady", "FixedRouter", 100, queue="steady"))
        stop = threading.Event()
        seen = []

        def reader():
            root = create_root_analysis()
            while not stop.is_set():
                names = [r.name for r in get_alert_routers()]
                seen.append(("detection_queue" in names, "steady" in names))
                route_alert(root, RouteStage.PRE_INSERT)

        threads = [threading.Thread(target=reader) for _ in range(4)]
        for thread in threads:
            thread.start()
        try:
            for _ in range(200):
                load_alert_routers(force=True)
        finally:
            stop.set()
            for thread in threads:
                thread.join()

        assert seen
        assert all(builtin and steady for builtin, steady in seen)


class TestExampleIntegration:
    def test_the_example_router_loads_and_routes_only_tagged_alerts(self, monkeypatch, configured):
        """The example integration's router (integrations.example/example) is loaded the way an
        integration's config entry loads it, and does nothing to an alert without its tag.

        The module is loaded from its file under a name of its own: importing the `example`
        package would run its __init__, which registers blueprints and observable actions for
        the whole process."""
        path = os.path.join(get_base_dir(), "integrations.example", "example", "src", "example", "routing.py")
        spec = importlib.util.spec_from_file_location("example_routing_under_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        monkeypatch.setitem(sys.modules, "example_routing_under_test", module)

        # the same entry the example's etc/saq.integration.yaml declares
        with open(os.path.join(get_base_dir(), "integrations.example", "example", "etc", "saq.integration.yaml")) as fp:
            (entry,) = yaml.safe_load(fp)["alert_routers"]
        entry = dict(entry, python_module="example_routing_under_test")
        configured(AlertRouterConfig(**entry))
        assert get_alert_router_load_errors() == {}

        untagged = create_root_analysis()
        assert route_alert(untagged, RouteStage.PRE_INSERT) is None

        tagged = create_root_analysis()
        tagged.add_tag("example_route")
        decision = route_alert(tagged, RouteStage.PRE_INSERT)
        assert (decision.queue, decision.router) == ("example", "example_tag_router")
