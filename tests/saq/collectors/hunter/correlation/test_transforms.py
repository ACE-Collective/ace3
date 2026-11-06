import json

import pytest

from saq.collectors.hunter.correlation.schema import (
    CommandConfig,
    MergeTimeSpecConfig,
    TransformConfig,
)
from saq.collectors.hunter.correlation.transforms import apply_transform


@pytest.mark.unit
class TestPropertyTransform:

    def test_str_type(self):
        transform = TransformConfig(
            type="event", method="property", property_name="result",
            property_type="str",
            command=CommandConfig(type="defined", name="test"),
        )
        event = {"field1": "value1"}
        updated, stream, merge_dropped = apply_transform(transform, "hello world\n", event, [event])
        assert updated["result"] == "hello world"
        assert stream is None
        assert merge_dropped is None

    def test_int_type(self):
        transform = TransformConfig(
            type="event", method="property", property_name="count",
            property_type="int",
            command=CommandConfig(type="defined", name="test"),
        )
        event = {}
        updated, _, _ = apply_transform(transform, "42\n", event, [event])
        assert updated["count"] == 42

    def test_float_type(self):
        transform = TransformConfig(
            type="event", method="property", property_name="score",
            property_type="float",
            command=CommandConfig(type="defined", name="test"),
        )
        event = {}
        updated, _, _ = apply_transform(transform, "3.14\n", event, [event])
        assert updated["score"] == pytest.approx(3.14)

    def test_bool_type(self):
        transform = TransformConfig(
            type="event", method="property", property_name="active",
            property_type="bool",
            command=CommandConfig(type="defined", name="test"),
        )
        event = {}
        updated, _, _ = apply_transform(transform, "true\n", event, [event])
        assert updated["active"] is True
        updated, _, _ = apply_transform(transform, "false\n", event, [event])
        assert updated["active"] is False

    def test_list_type(self):
        transform = TransformConfig(
            type="event", method="property", property_name="items",
            property_type="list",
            command=CommandConfig(type="defined", name="test"),
        )
        output = json.dumps({"a": 1}) + "\n" + json.dumps({"b": 2}) + "\n"
        event = {}
        updated, _, _ = apply_transform(transform, output, event, [event])
        assert updated["items"] == [{"a": 1}, {"b": 2}]

    def test_dict_type(self):
        transform = TransformConfig(
            type="event", method="property", property_name="data",
            property_type="dict",
            command=CommandConfig(type="defined", name="test"),
        )
        output = json.dumps({"key": "value"})
        event = {}
        updated, _, _ = apply_transform(transform, output, event, [event])
        assert updated["data"] == {"key": "value"}


@pytest.mark.unit
class TestMutateTransform:

    def test_replaces_stream(self):
        transform = TransformConfig(
            type="stream", method="mutate",
            command=CommandConfig(type="defined", name="test"),
        )
        output = json.dumps({"new": 1}) + "\n" + json.dumps({"new": 2}) + "\n"
        old_events = [{"old": 1}, {"old": 2}, {"old": 3}]
        _, new_stream, merge_dropped = apply_transform(transform, output, old_events[0], old_events)
        assert new_stream == [{"new": 1}, {"new": 2}]
        # mutate does not drop events by timestamp
        assert merge_dropped is None


@pytest.mark.unit
class TestMergeTransform:

    def test_merge_by_time(self):
        transform = TransformConfig(
            type="stream", method="merge",
            merge_time_spec=MergeTimeSpecConfig(
                l_field="time", l_format="epoch",
                r_field="time", r_format="epoch",
            ),
            command=CommandConfig(type="defined", name="test"),
        )
        existing = [
            {"time": "1000", "src": "existing1"},
            {"time": "3000", "src": "existing2"},
        ]
        new_data = json.dumps({"time": "2000", "src": "new1"}) + "\n"
        _, merged, merge_dropped = apply_transform(transform, new_data, existing[0], existing)

        # Should be: existing1 (1000), new1 (2000), existing2 (3000)
        assert len(merged) == 3
        assert merged[0]["src"] == "existing1"
        assert merged[1]["src"] == "new1"
        assert merged[2]["src"] == "existing2"
        assert merge_dropped == 0

    def test_merge_same_timestamp_existing_first(self):
        transform = TransformConfig(
            type="stream", method="merge",
            merge_time_spec=MergeTimeSpecConfig(
                l_field="time", l_format="epoch",
                r_field="time", r_format="epoch",
            ),
            command=CommandConfig(type="defined", name="test"),
        )
        existing = [{"time": "1000", "src": "existing"}]
        new_data = json.dumps({"time": "1000", "src": "new"}) + "\n"
        _, merged, _ = apply_transform(transform, new_data, existing[0], existing)

        assert merged[0]["src"] == "existing"
        assert merged[1]["src"] == "new"

    def test_merge_drops_missing_timestamps(self):
        transform = TransformConfig(
            type="stream", method="merge",
            merge_time_spec=MergeTimeSpecConfig(
                l_field="time", l_format="epoch",
                r_field="time", r_format="epoch",
            ),
            command=CommandConfig(type="defined", name="test"),
        )
        existing = [{"time": "1000", "src": "existing"}]
        new_data = json.dumps({"src": "no_time"}) + "\n" + json.dumps({"time": "2000", "src": "with_time"}) + "\n"
        _, merged, merge_dropped = apply_transform(transform, new_data, existing[0], existing)

        # The event without time field should be dropped
        sources = [e["src"] for e in merged]
        assert "no_time" not in sources
        assert "with_time" in sources
        # the dropped count is surfaced so the trace can show it
        assert merge_dropped == 1

    def test_merge_drops_unparseable_timestamps(self):
        transform = TransformConfig(
            type="stream", method="merge",
            merge_time_spec=MergeTimeSpecConfig(
                l_field="time", l_format="epoch",
                r_field="time", r_format="epoch",
            ),
            command=CommandConfig(type="defined", name="test"),
        )
        existing = [{"time": "1000", "src": "existing"}]
        new_data = (
            json.dumps({"time": "not-a-timestamp", "src": "bad_time"}) + "\n"
            + json.dumps({"time": "2000", "src": "with_time"}) + "\n"
        )
        _, merged, merge_dropped = apply_transform(transform, new_data, existing[0], existing)

        sources = [e["src"] for e in merged]
        assert "bad_time" not in sources
        assert "with_time" in sources
        assert merge_dropped == 1
