import pytest
from fastapi import HTTPException
from pydantic import BaseModel

from aceapi_v2.common.listing import InvalidCursor, decode_cursor, encode_cursor, parse_timezone, rows_to_csv


# cursors already handed out must keep working, so the encoding of each listing's cursor is pinned
@pytest.mark.unit
@pytest.mark.parametrize("fields, expected", [
    # alerts, by id and by (updated_at, id)
    ({"o": "id", "k": [42]}, "eyJ2IjoxLCJvIjoiaWQiLCJrIjpbNDJdfQ"),
    ({"o": "updated_at", "k": ["2026-10-13T12:00:00", 42]},
     "eyJ2IjoxLCJvIjoidXBkYXRlZF9hdCIsImsiOlsiMjAyNi0xMC0xM1QxMjowMDowMCIsNDJdfQ"),
    # samples, with their sort and direction
    ({"o": "last_captured", "d": True, "k": ["2026-10-13T12:00:00", "ab", "cd"]},
     "eyJ2IjoxLCJvIjoibGFzdF9jYXB0dXJlZCIsImQiOnRydWUsImsiOlsiMjAyNi0xMC0xM1QxMjowMDowMCIsImFiIiwiY2QiXX0"),
    # detection points
    ({"k": 7}, "eyJ2IjoxLCJrIjo3fQ"),
])
def test_cursor_encoding_is_stable(fields, expected):
    assert encode_cursor(**fields) == expected
    assert decode_cursor(expected, lambda payload: payload) == {"v": 1, **fields}


@pytest.mark.unit
def test_decode_cursor_returns_what_parse_returns():
    assert decode_cursor(encode_cursor(k=[3, "x"]), lambda payload: tuple(payload["k"])) == (3, "x")


@pytest.mark.unit
@pytest.mark.parametrize("cursor, message", [
    ("not base64 at all!", "malformed cursor"),
    ("eyJ2IjoyLCJrIjo3fQ", "unsupported cursor version 2"),  # {"v":2,"k":7}
    ("eyJrIjo3fQ", "malformed cursor"),  # {"k":7}, no version
])
def test_decode_cursor_rejects_a_bad_cursor(cursor, message):
    with pytest.raises(InvalidCursor, match=message):
        decode_cursor(cursor, lambda payload: payload)


@pytest.mark.unit
def test_whatever_parse_raises_is_an_invalid_cursor():
    cursor = encode_cursor(k=["not a number"])
    with pytest.raises(InvalidCursor, match="malformed cursor"):
        decode_cursor(cursor, lambda payload: int(payload["k"][0]))
    with pytest.raises(InvalidCursor, match="malformed cursor"):
        decode_cursor(cursor, lambda payload: payload["o"])


@pytest.mark.unit
def test_an_invalid_cursor_from_parse_keeps_its_message():
    def parse(payload):
        raise InvalidCursor("this cursor pages another order")

    with pytest.raises(InvalidCursor, match="^this cursor pages another order$"):
        decode_cursor(encode_cursor(k=1), parse)


class _Row(BaseModel):
    name: str
    count: int | None
    tags: list[str]


@pytest.mark.unit
def test_rows_to_csv():
    rows = [_Row(name="a", count=1, tags=["x", "y"]), _Row(name="b, c", count=None, tags=[])]

    def flatten(values: dict) -> None:
        values["tags"] = ",".join(values["tags"])

    assert rows_to_csv(rows, ("name", "count", "tags"), header=True, flatten=flatten) == (
        'name,count,tags\r\na,1,"x,y"\r\n"b, c",,\r\n')
    assert rows_to_csv(rows[:1], ("count", "name"), header=False, flatten=flatten) == "1,a\r\n"


@pytest.mark.unit
def test_parse_timezone():
    assert parse_timezone("America/New_York").zone == "America/New_York"
    with pytest.raises(HTTPException) as e:
        parse_timezone("Mars/Olympus_Mons")
    assert e.value.status_code == 422
