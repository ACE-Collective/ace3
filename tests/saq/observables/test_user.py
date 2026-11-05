import pytest

from saq.analysis import RootAnalysis
from saq.constants import F_USER
from saq.observables.user import UserObservable


# UserObservable domain/host stripping
#
# The value setter drops the domain/host portion of a username, keeping the
# bare account name (the segment after the last backslash). Historically it
# used split('\\')[1], which returned the empty inter-backslash segment for
# double-backslash separators (DOMAIN\\user) — producing an empty observable
# value that was then rejected, dropping the observable entirely.

@pytest.mark.parametrize("value,expected", [
    # double backslash: the reported bug — used to yield "" at index [1]
    ("DOMAIN\\\\user", "user"),
    # multi-segment host\DOMAIN\user — keep the real account, not the middle
    ("host\\DOMAIN\\user", "user"),
    # UPN style has no backslash: untouched
    ("user@example.com", "user@example.com"),
    # single backslash (classic DOMAIN\user), with surrounding whitespace stripped
    ("  DOMAIN\\user  ", "user"),
])
@pytest.mark.unit
def test_user_observable_domain_stripping(value, expected):
    o = UserObservable(value)
    assert o.value == expected


@pytest.mark.unit
def test_user_observable_via_root():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_USER, "DOMAIN\\\\user")
    assert o is not None
    assert isinstance(o, UserObservable)
    assert o.value == "user"


@pytest.mark.unit
def test_user_observable_caseless_match():
    """The user observable compares case-insensitively after stripping the domain."""
    o = UserObservable("DOMAIN\\User")
    assert o._compare_value("user")
    assert o._compare_value("USER")
    assert not o._compare_value("someone-else")
