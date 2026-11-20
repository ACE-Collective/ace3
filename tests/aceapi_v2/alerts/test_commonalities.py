"""POST /api/v2/alerts/commonalities: groups a page of alerts by the observables they share."""

import hashlib
import time
import uuid

import pytest
from httpx import AsyncClient

from aceapi_v2.alerts.schemas import COMMONALITIES_MAX_ALERTS
from aceapi_v2.alerts.service import _group_alerts, _measure_groups
from saq.configuration.config import get_config
from saq.database.model import load_alert
from saq.database.util.alert import ALERT
from tests.saq.helpers import create_root_analysis

pytestmark = pytest.mark.integration

PATH = "/alerts/commonalities"


def _alert(*observables: str, files: tuple[bytes, ...] = (), tmp_path=None) -> str:
    """An alert carrying the observables (`type:value`) and a file observable for each of `files`;
    returns its uuid."""
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    for spec in observables:
        o_type, value = spec.split(":", 1)
        root.add_observable_by_spec(o_type, value)
    for n, content in enumerate(files):
        path = tmp_path / f"{root.uuid}-{n}.bin"
        path.write_bytes(content)
        root.add_file_observable(str(path))
    root.save()
    ALERT(root)
    return load_alert(root.uuid).uuid


async def _post(client: AsyncClient, uuids: list[str], ignore: list[str] | None = None) -> dict:
    response = await client.post(PATH, json={"alert_uuids": uuids, "ignore": ignore or []})
    assert response.status_code == 200, response.text
    return response.json()


def _groups(result: dict) -> list[set[str]]:
    return [set(group["alert_uuids"]) for group in result["groups"]]


def _observable(result: dict, spec: str) -> dict:
    o_type, value = spec.split(":", 1)
    return next(o for o in result["observables"] if o["type"] == o_type and o["value"] == value)


@pytest.mark.asyncio
async def test_requires_auth(unauth_client: AsyncClient):
    assert (await unauth_client.post(PATH, json={"alert_uuids": ["x"]})).status_code == 401


@pytest.mark.asyncio
async def test_requires_alert_read(noperm_client: AsyncClient):
    assert (await noperm_client.post(PATH, json={"alert_uuids": ["x"]})).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [0, COMMONALITIES_MAX_ALERTS + 1])
async def test_rejects_an_empty_or_oversized_request(client: AsyncClient, count):
    assert (await client.post(PATH, json={"alert_uuids": ["x"] * count})).status_code == 422


@pytest.mark.asyncio
async def test_groups_alerts_by_what_they_share(client: AsyncClient):
    # three alerts about one user on one host, a pair sharing one sender, and one alert sharing nothing
    a = _alert("user:jdoe", "hostname:wks-1", "ipv4:192.0.2.10")
    b = _alert("user:jdoe", "hostname:wks-1", "ipv4:192.0.2.10")
    c = _alert("user:jdoe", "hostname:wks-1")
    d = _alert("email_address:sender@example.com")
    e = _alert("email_address:sender@example.com")
    alone = _alert("user:someone-else")

    result = await _post(client, [d, a, e, b, alone, c])

    assert _groups(result) == [{a, b, c}, {d, e}]
    # the group with more in common comes first, its most strongly linked alerts first
    assert result["groups"][0]["intensity"] > result["groups"][1]["intensity"]
    assert result["groups"][0]["alert_uuids"][-1] == c
    assert result["related"] == {a: 2, b: 2, c: 2, d: 1, e: 1}
    assert result["unrelated"] == 1
    assert [(o["type"], o["value"]) for o in result["observables"]] == [
        ("user", "jdoe"), ("hostname", "wks-1"), ("ipv4", "192.0.2.10"), ("email_address", "sender@example.com")]
    assert _observable(result, "ipv4:192.0.2.10") == {
        "type": "ipv4", "types": ["ipv4"], "value": "192.0.2.10", "alert_uuids": [a, b], "group": 0, "groups": [0]}


@pytest.mark.asyncio
async def test_one_shared_observable_does_not_merge_two_groups(client: AsyncClient):
    a = _alert("user:jdoe", "hostname:wks-1", "user:anguyen")
    b = _alert("user:jdoe", "hostname:wks-1")
    c = _alert("user:anguyen")
    d = _alert("user:anguyen")

    result = await _post(client, [a, b, c, d])

    assert _groups(result) == [{a, b}, {c, d}]
    assert _observable(result, "user:anguyen")["groups"] == [0, 1]
    assert result["related"][a] == 3


@pytest.mark.asyncio
async def test_an_alert_linked_only_to_a_group_joins_it(client: AsyncClient):
    a = _alert("user:jdoe", "hostname:wks-1")
    b = _alert("user:jdoe", "hostname:wks-1")
    c = _alert("user:jdoe")

    result = await _post(client, [a, b, c])

    assert _groups(result) == [{a, b, c}]
    assert result["unrelated"] == 0


@pytest.mark.asyncio
async def test_ignored_observables_do_not_group(client: AsyncClient):
    a = _alert("ipv4:192.0.2.53", "user:jdoe")
    b = _alert("ipv4:192.0.2.53", "user:jdoe")
    c = _alert("ipv4:192.0.2.53")

    result = await _post(client, [a, b, c], ignore=["ipv4:192.0.2.53"])

    assert _groups(result) == [{a, b}]
    assert [o["value"] for o in result["observables"]] == ["jdoe"]
    assert result["unrelated"] == 1


@pytest.mark.asyncio
async def test_only_alerts_this_node_shows_are_compared(client: AsyncClient, monkeypatch):
    a = _alert("user:jdoe")
    b = _alert("user:jdoe")
    monkeypatch.setattr(get_config().gui, "local_node_only", False)
    monkeypatch.setattr(get_config().gui, "display_node_list", ["another-node"])

    result = await _post(client, [a, b, str(uuid.uuid4())])

    assert result == {"groups": [], "observables": [], "related": {}, "unrelated": 0, "type_ancestors": {}}


@pytest.mark.asyncio
async def test_a_value_under_two_types_is_one_column(client: AsyncClient):
    a = _alert("email_from:sender@example.com", "user:jdoe")
    b = _alert("email_address:sender@example.com", "user:jdoe")

    result = await _post(client, [a, b])

    # two values in common, so the alerts are a group, and the address is one column with both types
    assert _groups(result) == [{a, b}]
    sender = next(o for o in result["observables"] if o["value"] == "sender@example.com")
    assert sender["types"] == ["email_address", "email_from"]
    assert sender["type"] == "email_address"
    assert len(result["observables"]) == 2
    assert result["type_ancestors"] == {"email_address": [], "email_from": ["email_address"], "user": []}


@pytest.mark.asyncio
async def test_near_identical_groups(client: AsyncClient):
    same = ["user:jdoe", "hostname:wks-1", "ipv4:192.0.2.10", "email_subject:invoice", "file_name:invoice.html"]
    a = _alert(*same)
    b = _alert(*same)
    c = _alert("user:other", "hostname:wks-9", "email_subject:hello")
    d = _alert("user:other", "hostname:wks-9", "email_subject:goodbye")

    result = await _post(client, [a, b, c, d])

    copies, others = result["groups"]
    assert set(copies["alert_uuids"]) == {a, b}
    assert (copies["near_identical"], copies["shared"], copies["total"]) == (True, 5, 5)
    assert (others["near_identical"], others["shared"], others["total"]) == (False, 2, 3)

    # an ignored value no longer counts toward the alerts' size either
    result = await _post(client, [a, b], ignore=["ipv4:192.0.2.10"])
    assert (result["groups"][0]["shared"], result["groups"][0]["total"]) == (4, 4)


@pytest.mark.asyncio
async def test_columns_link_first_then_by_type(client: AsyncClient, monkeypatch):
    a = _alert("file_name:report.pdf", "email_from:sender@example.com", "hostname:wks-1", "ipv4:192.0.2.77")
    b = _alert("file_name:report.pdf", "email_from:sender@example.com", "hostname:wks-1")
    c = _alert("ipv4:192.0.2.77", "user:z")
    d = _alert("ipv4:192.0.2.77", "user:z")

    result = await _post(client, [a, b, c, d])

    assert _groups(result) == [{a, b}, {c, d}]
    # the value linking the groups, then hostname before email_from (ranked as email_address), file names last
    assert [o["value"] for o in result["observables"]] == [
        "192.0.2.77", "wks-1", "sender@example.com", "report.pdf", "z"]

    monkeypatch.setattr(get_config().gui, "commonalities_priority_types", ["file_name"])
    result = await _post(client, [a, b, c, d])
    assert [o["value"] for o in result["observables"]] == [
        "192.0.2.77", "report.pdf", "sender@example.com", "wks-1", "z"]


@pytest.mark.asyncio
async def test_a_file_is_one_value_with_its_sha256(client: AsyncClient, tmp_path):
    attachment = b"invoice attachment"
    digest = hashlib.sha256(attachment).hexdigest()
    # the same email twice: the same file, and the sha256 observable the hash analyzer adds for it
    a = _alert("user:jdoe", f"sha256:{digest}", files=(attachment,), tmp_path=tmp_path)
    b = _alert("user:jdoe", f"sha256:{digest}", files=(attachment,), tmp_path=tmp_path)
    # an alert that only has the hash, from a hunt
    c = _alert(f"sha256:{digest}", "user:other")
    d = _alert("user:other", "hostname:wks-2")

    result = await _post(client, [a, b, c, d])

    copies = next(g for g in result["groups"] if a in g["alert_uuids"])
    # two values each: the user, and the file whose sha256 is the same value
    assert (copies["shared"], copies["total"], copies["near_identical"]) == (2, 2, True)
    attachment_column = next(o for o in result["observables"] if o["value"] == digest)
    assert sorted(attachment_column["types"]) == ["file", "sha256"]
    assert set(attachment_column["alert_uuids"]) == {a, b, c}


@pytest.mark.unit
def test_grouping_a_full_page_that_shares_one_value_is_fast():
    # the largest page the endpoint takes, every alert sharing one value (a common host or recipient):
    # the grouping is linear in the pairs, so it is far below what an analyst would wait for
    uuids = [str(uuid.uuid4()) for _ in range(COMMONALITIES_MAX_ALERTS)]
    started = time.monotonic()
    groups, group_of, partners, weight = _group_alerts({"wks-1": uuids, "jdoe": uuids[:10]},
                                                       {u: i for i, u in enumerate(uuids)})
    assert time.monotonic() - started < 2
    # the ten alerts sharing two values are a group; the rest, linked by one value only, are another
    assert [set(group.alert_uuids) for group in groups] == [set(uuids[:10]), set(uuids[10:])]
    assert len(weight) == COMMONALITIES_MAX_ALERTS * (COMMONALITIES_MAX_ALERTS - 1) // 2


@pytest.mark.unit
def test_measuring_many_groups_is_fast():
    # a full page of 250 pairs, each pair sharing two values, and one value all 500 alerts share
    uuids = [str(uuid.uuid4()) for _ in range(COMMONALITIES_MAX_ALERTS)]
    alerts_of = {"dns": uuids}
    for n in range(0, len(uuids), 2):
        alerts_of[f"user-{n}"] = alerts_of[f"host-{n}"] = uuids[n:n + 2]
    groups, group_of, _, weight = _group_alerts(alerts_of, {u: i for i, u in enumerate(uuids)})
    assert len(groups) == COMMONALITIES_MAX_ALERTS // 2

    started = time.monotonic()
    _measure_groups(groups, group_of, alerts_of, weight, {u: 3 for u in uuids})
    # one pass over the values and one over the pairs; measuring each group by scanning every pair
    # again takes seconds on this page
    assert time.monotonic() - started < 0.5
    assert all((g.shared, g.total, g.near_identical) == (3, 3, True) for g in groups)
