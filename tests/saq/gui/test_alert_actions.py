import pytest

from saq.gui import alert_actions
from saq.gui.alert_actions import AlertAction, get_alert_actions, register_alert_action

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def empty_registry(monkeypatch):
    monkeypatch.setattr(alert_actions, "_ALERT_ACTION_REGISTRY", [])


class FakeAlert:
    def __init__(self, tags=()):
        self.tags = set(tags)


class Always(AlertAction):
    name = "always"
    description = "Always"


class OnlyTagged(AlertAction):
    name = "only_tagged"
    description = "Only tagged"

    def is_available(self, alert) -> bool:
        return "marked" in alert.tags


class NeedsPermission(AlertAction):
    name = "needs_permission"
    description = "Needs permission"
    permission = ("alert", "write")


class Broken(AlertAction):
    name = "broken"
    description = "Broken"

    def is_available(self, alert) -> bool:
        raise RuntimeError("bug in an integration")


def allow_all(major, minor):
    return True


def names(actions):
    return [action.name for action in actions]


def test_nothing_registered():
    assert get_alert_actions(FakeAlert(), allow_all) == []


def test_actions_appear_in_registration_order():
    register_alert_action(OnlyTagged)
    register_alert_action(Always)
    assert names(get_alert_actions(FakeAlert({"marked"}), allow_all)) == ["only_tagged", "always"]


def test_unavailable_action_is_left_out():
    register_alert_action(OnlyTagged)
    register_alert_action(Always)
    assert names(get_alert_actions(FakeAlert(), allow_all)) == ["always"]


def test_permission_is_checked():
    register_alert_action(NeedsPermission)
    asked = []

    def deny(major, minor):
        asked.append((major, minor))
        return False

    assert get_alert_actions(FakeAlert(), deny) == []
    assert asked == [("alert", "write")]
    assert names(get_alert_actions(FakeAlert(), allow_all)) == ["needs_permission"]


def test_a_failing_action_does_not_break_the_others(caplog):
    register_alert_action(Broken)
    register_alert_action(Always)
    assert names(get_alert_actions(FakeAlert(), allow_all)) == ["always"]
    assert any(getattr(record, "alert_action", None) == "broken" for record in caplog.records)


def test_registering_twice_is_harmless():
    register_alert_action(Always)
    register_alert_action(Always)
    assert names(get_alert_actions(FakeAlert(), allow_all)) == ["always"]


def test_names_must_be_unique():
    class AlsoAlways(AlertAction):
        name = "always"

    register_alert_action(Always)
    with pytest.raises(ValueError, match="already registered"):
        register_alert_action(AlsoAlways)


@pytest.mark.parametrize("name", ["", "Has-Dash", "space here", "quote'"])
def test_names_must_be_safe_in_an_element_id(name):
    class Bad(AlertAction):
        pass

    Bad.name = name
    with pytest.raises(ValueError):
        register_alert_action(Bad)


def test_only_alert_actions_can_be_registered():
    with pytest.raises(TypeError):
        register_alert_action(object)
    with pytest.raises(TypeError):
        register_alert_action(Always())
