import importlib
import pkgutil

import pytest
from pydantic import ValidationError

import saq.observables
from saq.analysis.observable import Observable
from saq.configuration.config import get_config
from saq.configuration.schema import ObservableTypesConfig
from saq.constants import (F_AWS_ACCOUNT_ID, F_EMAIL_ADDRESS, F_EMAIL_DELIVERY, F_EMAIL_FIRST_HOP_IP, F_FILE_LOCATION, F_FQDN,
                           F_IP, F_IP_CONVERSATION, F_IP_FULL_CONVERSATION, F_IPV4, F_IPV4_CONVERSATION,
                           F_IPV4_FULL_CONVERSATION, F_MAC_ADDRESS, F_MESSAGE_ID, F_TEST, F_URL, F_YARA_STRING)
from saq.observables.base import CaselessObservable, DefaultObservable
from saq.observables.file import FileObservable
from saq.observables.generator import create_observable, create_observable_from_dict, get_observable_class
from saq.observables.network.http import URLObservable
from saq.observables.testing import TestObservable


@pytest.mark.unit
def test_create_observable_from_dict():
    observable = create_observable_from_dict(create_observable(F_TEST, "test").json)
    assert type(observable) is TestObservable
    assert observable.value == "test"


@pytest.mark.unit
def test_a_type_is_built_with_its_configured_class():
    assert type(create_observable(F_URL, "https://example.com/")) is URLObservable


@pytest.mark.unit
def test_a_type_without_a_class_is_a_default_observable():
    observable = create_observable("__pytest_no_class__", "value")
    assert type(observable) is DefaultObservable
    assert observable.type == "__pytest_no_class__"
    assert type(create_observable_from_dict(observable.json)) is DefaultObservable


@pytest.mark.unit
def test_a_type_mapped_to_another_class_is_built_with_it(monkeypatch):
    # the loaded classes are cached by module:Class, so a changed mapping is never answered from the cache
    assert get_observable_class(F_TEST) is TestObservable
    monkeypatch.setitem(get_config().observable_types.classes, F_TEST, "saq.observables.network.http:URLObservable")
    assert get_observable_class(F_TEST) is URLObservable


@pytest.mark.unit
@pytest.mark.parametrize("target", ["saq.observables.no_such_module:TestObservable",
                                    "saq.observables.testing:NoSuchClass"])
def test_a_class_that_cannot_be_loaded_raises(monkeypatch, target):
    # a DefaultObservable would drop what the class keeps when the root is saved again
    saved = DefaultObservable("__pytest_broken__", "value").json
    monkeypatch.setitem(get_config().observable_types.classes, "__pytest_broken__", target)

    with pytest.raises(ImportError, match=f"observable_types.classes.__pytest_broken__: cannot load {target}"):
        create_observable("__pytest_broken__", "value")

    with pytest.raises(ImportError, match=f"observable_types.classes.__pytest_broken__: cannot load {target}"):
        create_observable_from_dict(saved)


@pytest.mark.unit
@pytest.mark.parametrize("target", ["saq.observables.testing", "saq.observables.testing.TestObservable",
                                    "saq.observables.testing:Test:Observable", ":TestObservable",
                                    "saq.observables.testing:", "saq..observables:TestObservable"])
def test_a_class_not_named_as_module_class_fails_validation(target):
    with pytest.raises(ValidationError, match="observable_types.classes.test: .* is not module:Class"):
        ObservableTypesConfig(classes={F_TEST: target})


def _subclasses(cls: type) -> set[type]:
    found = set()
    for subclass in cls.__subclasses__():
        found.add(subclass)
        found |= _subclasses(subclass)
    return found


@pytest.mark.unit
def test_every_observable_class_is_configured():
    # nothing imports a class left out of observable_types.classes, so its type is built as a DefaultObservable
    for module in pkgutil.walk_packages(saq.observables.__path__, "saq.observables."):
        importlib.import_module(module.name)

    configured = set(get_config().observable_types.classes.values())
    unconfigured = sorted(f"{cls.__module__}:{cls.__qualname__}" for cls in _subclasses(Observable)
                          if cls.__module__.startswith("saq.observables.")
                          and cls not in (DefaultObservable, CaselessObservable)
                          and f"{cls.__module__}:{cls.__qualname__}" not in configured)
    assert not unconfigured


# a value each of these types' class accepts; the class of every other type accepts "value"
_SAMPLE_VALUES = {
    F_AWS_ACCOUNT_ID: "123456789012",
    F_EMAIL_ADDRESS: "user@example.com",
    F_EMAIL_DELIVERY: "<message@example.com>|user@example.com",
    F_EMAIL_FIRST_HOP_IP: "192.0.2.1",
    F_FILE_LOCATION: "host@/tmp/sample",
    F_FQDN: "www.example.com",
    F_IP: "192.0.2.1",
    F_IP_CONVERSATION: "192.0.2.1_192.0.2.2",
    F_IP_FULL_CONVERSATION: "192.0.2.1!1234!192.0.2.2!443",
    F_IPV4: "192.0.2.1",
    F_IPV4_CONVERSATION: "192.0.2.1_192.0.2.2",
    F_IPV4_FULL_CONVERSATION: "192.0.2.1:1234:192.0.2.2:443",
    F_MAC_ADDRESS: "00:11:22:33:44:55",
    F_MESSAGE_ID: "<message@example.com>",
    F_YARA_STRING: "rule:$string",
}


@pytest.mark.unit
def test_every_configured_class_builds_its_own_type():
    # each class sets its own type, so an entry naming another type's class would build every observable
    # of the type as that other type. Only core's classes: an integration's may reject the sample value.
    for o_type, target in get_config().observable_types.classes.items():
        if not target.startswith("saq."):
            continue

        o_class = get_observable_class(o_type)
        assert issubclass(o_class, Observable), o_type
        if o_class is FileObservable:
            # a file observable is built from the file it is the sha256 of, never from a value alone
            observable = o_class("0" * 64, file_path="sample")
        else:
            observable = create_observable(o_type, _SAMPLE_VALUES.get(o_type, "value"))

        assert observable is not None, o_type
        assert observable.type == o_type, f"{o_type} is built as {observable.type}"
