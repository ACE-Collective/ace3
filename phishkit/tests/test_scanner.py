import asyncio
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml


# ---------------------------------------------------------------------------
# _load_config
# ---------------------------------------------------------------------------

class TestLoadConfig:

    @pytest.mark.unit
    def test_load_config_valid(self, config_file, sample_config_data):
        from scanner import _load_config

        config = _load_config(config_file)
        assert config.skip_body_ext == sample_config_data["skip_body_extensions"]
        assert config.skip_body_url_patterns == sample_config_data["skip_body_url_patterns"]
        assert config.handlers == sample_config_data["handlers"]
        assert len(config.bypasses) == len(sample_config_data["bypasses"])

    @pytest.mark.unit
    def test_load_config_content_type_lists(self, config_file, sample_config_data):
        from scanner import _load_config

        config = _load_config(config_file)
        assert config.non_rendered_content_types == sample_config_data["non_rendered_content_types"]
        assert config.script_content_types == sample_config_data["script_content_types"]

    @pytest.mark.unit
    def test_load_config_content_type_defaults_when_absent(self, tmpdir, sample_config_data):
        """A config predating these keys must keep the built-in defaults rather
        than silently disabling the gates."""
        from scanner import (
            _load_config,
            DEFAULT_NON_RENDERED_CONTENT_TYPES,
            DEFAULT_SCRIPT_CONTENT_TYPES,
        )

        data = dict(sample_config_data)
        del data["non_rendered_content_types"]
        del data["script_content_types"]
        path = str(tmpdir.join("no_content_types.yaml"))
        with open(path, "w") as f:
            yaml.dump(data, f)

        config = _load_config(path)
        assert config.non_rendered_content_types == DEFAULT_NON_RENDERED_CONTENT_TYPES
        assert config.script_content_types == DEFAULT_SCRIPT_CONTENT_TYPES

    @pytest.mark.unit
    def test_load_config_content_types_are_lowercased(self, tmpdir, sample_config_data):
        """Comparison is against a lowercased header value, so the config side
        must be normalized too or a capitalized entry silently never matches."""
        from scanner import _load_config

        data = dict(sample_config_data)
        data["script_content_types"] = ["Application/JavaScript"]
        path = str(tmpdir.join("mixed_case.yaml"))
        with open(path, "w") as f:
            yaml.dump(data, f)

        config = _load_config(path)
        assert config.script_content_types == ["application/javascript"]

    @pytest.mark.unit
    def test_load_config_missing_file(self):
        from scanner import _load_config

        with pytest.raises(FileNotFoundError):
            _load_config("/nonexistent/config.yaml")

    @pytest.mark.unit
    def test_load_config_not_a_dict(self, tmpdir):
        from scanner import _load_config

        path = str(tmpdir.join("bad.yaml"))
        with open(path, "w") as f:
            yaml.dump(["a", "b"], f)

        with pytest.raises(ValueError, match="not a YAML mapping"):
            _load_config(path)

    @pytest.mark.unit
    def test_load_config_empty_file(self, tmpdir):
        from scanner import _load_config

        path = str(tmpdir.join("empty.yaml"))
        with open(path, "w") as f:
            f.write("")

        with pytest.raises(ValueError, match="not a YAML mapping"):
            _load_config(path)

    @pytest.mark.unit
    def test_load_config_missing_keys_uses_defaults(self, tmpdir):
        from scanner import _load_config

        path = str(tmpdir.join("minimal.yaml"))
        with open(path, "w") as f:
            yaml.dump({}, f)

        config = _load_config(path)
        assert config.skip_body_ext == []
        assert config.skip_body_url_patterns == []
        assert config.handlers == {}
        assert config.bypasses == []


# ---------------------------------------------------------------------------
# Scanner.__init__
# ---------------------------------------------------------------------------

class TestScannerInit:

    @pytest.mark.unit
    def test_scanner_init_populates_attributes(self, scanner, sample_config_data):
        assert scanner.SKIP_BODY_EXT == sample_config_data["skip_body_extensions"]
        assert scanner.SKIP_BODY_URL_PATTERNS == sample_config_data["skip_body_url_patterns"]
        assert scanner.HANDLERS == sample_config_data["handlers"]
        assert len(scanner.BYPASSES) == len(sample_config_data["bypasses"])
        assert scanner.requests == []
        assert scanner.bytes_downloaded == 0
        assert scanner.domain_stats == {}

    @pytest.mark.unit
    def test_scanner_init_bypass_handlers_map(self, scanner):
        assert "visual_checkbox_bypass" in scanner._bypass_handlers
        assert callable(scanner._bypass_handlers["visual_checkbox_bypass"])


# ---------------------------------------------------------------------------
# Scanner._get_domain_stats
# ---------------------------------------------------------------------------

class TestGetDomainStats:

    @pytest.mark.unit
    def test_get_domain_stats_new_domain(self, scanner):
        stats = scanner._get_domain_stats("example.com")
        assert stats["bytes_downloaded"] == 0
        assert stats["request_count"] == 0
        assert stats["response_count"] == 0
        assert stats["first_request_time"] is None
        assert stats["last_finished_time"] is None

    @pytest.mark.unit
    def test_get_domain_stats_existing_domain(self, scanner):
        first = scanner._get_domain_stats("example.com")
        first["request_count"] = 5
        second = scanner._get_domain_stats("example.com")
        assert first is second
        assert second["request_count"] == 5

    @pytest.mark.unit
    def test_get_domain_stats_multiple_domains(self, scanner):
        a = scanner._get_domain_stats("a.com")
        b = scanner._get_domain_stats("b.com")
        assert a is not b
        assert len(scanner.domain_stats) == 2


# ---------------------------------------------------------------------------
# Scanner._compute_metrics
# ---------------------------------------------------------------------------

class TestComputeMetrics:

    @pytest.mark.unit
    def test_compute_metrics_empty_stats(self, scanner):
        metrics = scanner._compute_metrics("https://example.com", 1.5)
        assert metrics["url_scanned"] == "https://example.com"
        assert metrics["total_bytes_downloaded"] == 0
        assert metrics["scan_duration_seconds"] == 1.5
        assert metrics["domain_stats"] == {}

    @pytest.mark.unit
    def test_compute_metrics_with_timing(self, scanner):
        scanner.domain_stats["example.com"] = {
            "bytes_downloaded": 1024,
            "request_count": 3,
            "response_count": 3,
            "first_request_time": 100.0,
            "last_finished_time": 102.5,
        }
        scanner.bytes_downloaded = 1024

        metrics = scanner._compute_metrics("https://example.com", 5.0)
        domain = metrics["domain_stats"]["example.com"]
        assert domain["bytes_downloaded"] == 1024
        assert domain["request_count"] == 3
        assert domain["duration_seconds"] == 2.5

    @pytest.mark.unit
    def test_compute_metrics_missing_timing(self, scanner):
        scanner.domain_stats["example.com"] = {
            "bytes_downloaded": 0,
            "request_count": 1,
            "response_count": 0,
            "first_request_time": None,
            "last_finished_time": None,
        }

        metrics = scanner._compute_metrics("https://example.com", 1.0)
        assert metrics["domain_stats"]["example.com"]["duration_seconds"] == 0

    @pytest.mark.unit
    def test_compute_metrics_timestamp_format(self, scanner):
        metrics = scanner._compute_metrics("https://example.com", 0.0)
        ts = datetime.fromisoformat(metrics["timestamp"])
        assert ts.tzinfo is not None


# ---------------------------------------------------------------------------
# Scanner.check_dom_filter
# ---------------------------------------------------------------------------

class TestCheckDomFilter:

    @pytest.mark.unit
    def test_check_dom_filter_matching_url_pattern(self, scanner):
        assert scanner.check_dom_filter("https://fonts.googleapis.com/css?family=Roboto") is True

    @pytest.mark.unit
    def test_check_dom_filter_matching_extension(self, scanner):
        assert scanner.check_dom_filter("https://example.com/image.png") is True

    @pytest.mark.unit
    def test_check_dom_filter_data_url(self, scanner):
        assert scanner.check_dom_filter("data:image/png;base64,abc") is True

    @pytest.mark.unit
    def test_check_dom_filter_blob_url(self, scanner):
        assert scanner.check_dom_filter("blob:https://example.com/abc") is True

    @pytest.mark.unit
    def test_check_dom_filter_non_matching(self, scanner):
        assert scanner.check_dom_filter("https://example.com/page.html") is False


# ---------------------------------------------------------------------------
# Scanner.top_level_response / top_level_content_type
# ---------------------------------------------------------------------------

def _response(url, content_type=None, status_code=200, resource_type=None, request_id="1"):
    """Builds a requests.json-shaped response entry."""
    entry = {
        "type": "response",
        "url": url,
        "requestId": request_id,
        "status_code": status_code,
        "headers": {} if content_type is None else {"Content-Type": content_type},
    }
    if resource_type is not None:
        entry["resource_type"] = resource_type
    return entry


class TestTopLevelResponse:

    @pytest.mark.unit
    def test_resource_type_document_wins_over_ordering(self, scanner):
        """An explicit Document marker beats position. Subresources can be
        logged first, so ordering alone is not authoritative."""
        scanner.requests = [
            _response("https://example.com/app.css", "text/css", resource_type="Stylesheet", request_id="a"),
            _response("https://example.com/", "text/html", resource_type="Document", request_id="b"),
        ]
        assert scanner.top_level_response()["requestId"] == "b"
        assert scanner.top_level_content_type() == "text/html"

    @pytest.mark.unit
    def test_falls_back_to_first_non_redirect_without_resource_type(self, scanner):
        """Responses logged before resource_type was captured must still work."""
        scanner.requests = [
            _response("https://example.com/", "text/html", request_id="a"),
            _response("https://example.com/app.js", "application/javascript", request_id="b"),
        ]
        assert scanner.top_level_response()["requestId"] == "a"
        assert scanner.top_level_content_type() == "text/html"

    @pytest.mark.unit
    def test_redirect_hops_are_skipped(self, scanner):
        """The document is the response a redirect chain lands on."""
        scanner.requests = [
            _response("https://example.com/", None, status_code=301, request_id="a"),
            _response("https://example.com/final.js", "application/javascript", request_id="b"),
        ]
        assert scanner.top_level_response()["requestId"] == "b"
        assert scanner.top_level_content_type() == "application/javascript"

    @pytest.mark.unit
    def test_header_casing_and_charset_param(self, scanner):
        scanner.requests = [{
            "type": "response",
            "url": "https://example.com/app.js",
            "requestId": "a",
            "status_code": 200,
            "headers": {"content-type": "Application/JavaScript; charset=utf-8"},
        }]
        assert scanner.top_level_content_type() == "application/javascript"

    @pytest.mark.unit
    def test_unknown_content_type_is_none(self, scanner):
        """No content-type header -> None -> both gates fail open."""
        scanner.requests = [_response("https://example.com/", None)]
        assert scanner.top_level_content_type() is None
        assert scanner.top_level_content_type() not in scanner.NON_RENDERED_CONTENT_TYPES
        assert scanner.top_level_content_type() not in scanner.SCRIPT_CONTENT_TYPES

    @pytest.mark.unit
    def test_no_responses_is_none(self, scanner):
        scanner.requests = [{"type": "request", "url": "https://example.com/", "requestId": "a"}]
        assert scanner.top_level_response() is None
        assert scanner.top_level_content_type() is None

    @pytest.mark.unit
    def test_javascript_document_skips_screenshot_and_is_a_script(self, scanner):
        """The case this all exists for: a scanned URL that serves JS."""
        scanner.requests = [
            _response("https://example.com/stage.js", "application/javascript", resource_type="Document")
        ]
        assert scanner.top_level_content_type() in scanner.NON_RENDERED_CONTENT_TYPES
        assert scanner.top_level_content_type() in scanner.SCRIPT_CONTENT_TYPES

    @pytest.mark.unit
    def test_html_document_keeps_screenshot_and_is_not_a_script(self, scanner):
        scanner.requests = [
            _response("https://example.com/", "text/html", resource_type="Document")
        ]
        assert scanner.top_level_content_type() not in scanner.NON_RENDERED_CONTENT_TYPES
        assert scanner.top_level_content_type() not in scanner.SCRIPT_CONTENT_TYPES

    @pytest.mark.unit
    def test_script_document_is_not_a_rendered_page(self, scanner):
        """Drives both the screenshot skip and the bypass skip."""
        scanner.requests = [
            _response("https://example.com/stage.js", "application/javascript", resource_type="Document")
        ]
        assert scanner.top_level_is_rendered_page() is False

    @pytest.mark.unit
    def test_html_document_is_a_rendered_page(self, scanner):
        scanner.requests = [
            _response("https://example.com/", "text/html", resource_type="Document")
        ]
        assert scanner.top_level_is_rendered_page() is True

    @pytest.mark.unit
    def test_unknown_content_type_is_treated_as_a_rendered_page(self, scanner):
        """Fail open: never skip a screenshot or a bypass on a guess."""
        scanner.requests = [_response("https://example.com/", None)]
        assert scanner.top_level_is_rendered_page() is True

    @pytest.mark.unit
    def test_no_responses_is_treated_as_a_rendered_page(self, scanner):
        scanner.requests = []
        assert scanner.top_level_is_rendered_page() is True

    @pytest.mark.unit
    @pytest.mark.parametrize("content_type,rendered", [
        ("text/html", True),
        ("application/xhtml+xml", True),
        (None, True),                       # unknown -> fail open
        ("application/javascript", False),
        ("application/json", False),
        ("text/css", False),
        ("text/plain", False),
    ])
    def test_screenshot_dom_and_bypasses_share_one_predicate(self, scanner, content_type, rendered):
        """The screenshot, the DOM capture and the bypass attempts must agree.

        All three record or interrogate what Chrome rendered, so all three are
        meaningless on a plain-text viewer -- and all three read
        top_level_is_rendered_page(). Pinning them together keeps the consumers
        from drifting apart as content types are added: it should not be possible
        to skip the screenshot for a type while still capturing its DOM.
        """
        scanner.requests = [
            _response("https://example.com/x", content_type, resource_type="Document")
        ]
        assert scanner.top_level_is_rendered_page() is rendered
        # the screenshot/dom gate and the bypass gate are the same call, so a
        # divergence here means one consumer grew its own rule
        assert (scanner.top_level_content_type() not in scanner.NON_RENDERED_CONTENT_TYPES) is rendered

    @pytest.mark.unit
    def test_json_skips_screenshot_but_is_not_diverted_as_script(self, scanner):
        """The two lists are deliberately different widths: JSON renders as
        plain text (no useful screenshot) but is not JavaScript, so it must not
        be handed to the deobfuscator."""
        scanner.requests = [
            _response("https://example.com/api", "application/json", resource_type="Document")
        ]
        assert scanner.top_level_content_type() in scanner.NON_RENDERED_CONTENT_TYPES
        assert scanner.top_level_content_type() not in scanner.SCRIPT_CONTENT_TYPES


# ---------------------------------------------------------------------------
# Async event handlers
# ---------------------------------------------------------------------------

def _make_response_event(url="https://example.com/page", request_id="req-1",
                         status=200, headers=None, encoded_data_length=100,
                         resource_type="Document"):
    event = MagicMock()
    event.response.url = url
    event.request_id = request_id
    event.response.headers = headers or {}
    event.response.status = status
    event.response.encoded_data_length = encoded_data_length
    event.response.to_json.return_value = "{}"
    # CDP ResourceType lives on the event, not event.response
    event.type_ = resource_type
    return event


def _make_request_event(url="https://example.com/page", request_id="req-1", method="GET", headers=None):
    event = MagicMock()
    event.request.url = url
    event.request_id = request_id
    event.request.method = method
    event.request.headers = headers or {}
    event.request.to_json.return_value = "{}"
    return event


def _make_loading_finished_event(request_id="req-1", encoded_data_length=500):
    event = MagicMock()
    event.request_id = request_id
    event.encoded_data_length = encoded_data_length
    return event


def _make_loading_failed_event(request_id="req-1", error_text="net::ERR_FAILED",
                               canceled=False, blocked_reason=None):
    event = MagicMock()
    event.request_id = request_id
    event.error_text = error_text
    event.canceled = canceled
    event.blocked_reason = blocked_reason
    return event


def _make_attached_event(target_type="worker", session_id="sess-1"):
    event = MagicMock()
    event.target_info.type_ = target_type
    event.session_id = session_id
    return event


class TestReceiveHandler:

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_receive_handler_appends_response(self, scanner):
        event = _make_response_event()
        await scanner.receive_handler(event)
        assert len(scanner.requests) == 1
        assert scanner.requests[0]["type"] == "response"
        assert scanner.requests[0]["url"] == "https://example.com/page"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_receive_handler_updates_domain_stats(self, scanner):
        event = _make_response_event(url="https://test.org/resource")
        await scanner.receive_handler(event)
        assert scanner.domain_stats["test.org"]["response_count"] == 1

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_receive_handler_captures_resource_type(self, scanner):
        """resource_type is what identifies the top-level document. It lives on
        the event rather than event.response, so it is absent from the "raw"
        dump and has to be captured explicitly."""
        event = _make_response_event(
            headers={"Content-Type": "application/javascript"},
            resource_type="Document",
        )
        await scanner.receive_handler(event)
        assert scanner.requests[0]["resource_type"] == "Document"
        assert scanner.top_level_content_type() == "application/javascript"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_receive_handler_marks_subresources(self, scanner):
        event = _make_response_event(url="https://example.com/a.js", resource_type="Script")
        await scanner.receive_handler(event)
        assert scanner.requests[0]["resource_type"] == "Script"


class TestAppendableResponseEntries:

    @pytest.mark.unit
    def test_one_entry_per_exchange_not_two(self, scanner):
        """A request and a response entry share one requestId -- take only one.

        Network.getResponseBody is keyed by requestId and both entries carry it,
        so selecting everything with a requestId fetches and appends every body
        twice. Only the response has a body, which makes type == "response" both
        the correct filter and the deduplicating one.
        """
        scanner.requests = [
            {"type": "request", "url": "https://example.com/a.js", "requestId": "1"},
            {"type": "response", "url": "https://example.com/a.js", "requestId": "1"},
        ]
        entries = scanner.appendable_response_entries()
        assert len(entries) == 1
        assert entries[0]["type"] == "response"

    @pytest.mark.unit
    def test_websocket_entries_are_excluded(self, scanner):
        """websocket_* entries carry a requestId but aren't fetchable this way;
        they have their own pass."""
        scanner.requests = [
            {"type": "websocket_created", "url": "wss://example.com/s", "requestId": "1"},
            {"type": "websocket_frame_sent", "url": "wss://example.com/s", "requestId": "1"},
            {"type": "response", "url": "https://example.com/a.js", "requestId": "2"},
        ]
        entries = scanner.appendable_response_entries()
        assert [e["requestId"] for e in entries] == ["2"]

    @pytest.mark.unit
    def test_entries_missing_ids_are_excluded(self, scanner):
        scanner.requests = [
            {"type": "response", "url": "https://example.com/a.js"},   # no requestId
            {"type": "response", "requestId": "2"},                    # no url
            {"type": "response", "url": "https://example.com/b.js", "requestId": "3"},
        ]
        assert [e["requestId"] for e in scanner.appendable_response_entries()] == ["3"]

    @pytest.mark.unit
    def test_multiple_exchanges_each_appear_once(self, scanner):
        scanner.requests = [
            {"type": "request", "url": "https://example.com/a.js", "requestId": "1"},
            {"type": "response", "url": "https://example.com/a.js", "requestId": "1"},
            {"type": "request", "url": "https://example.com/b.js", "requestId": "2"},
            {"type": "response", "url": "https://example.com/b.js", "requestId": "2"},
        ]
        assert [e["requestId"] for e in scanner.appendable_response_entries()] == ["1", "2"]


class TestRawSerializationIsBestEffort:

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_request_entry_survives_broken_to_json(self, scanner):
        """A request must still be recorded when its raw dump can't serialize.

        mycdp's Request.to_json() reads a field Request doesn't have, so it
        raises on every call. That used to take the whole entry down, leaving
        requests.json with only type="response" rows -- which silently disabled
        PhishkitAnalyzer's promotion pass over type="request" entries. Nothing
        reads "raw"; it must never be able to drop the entry around it.
        """
        event = _make_request_event(url="https://example.com/staged.js")
        event.request.to_json.side_effect = AttributeError(
            "'Request' object has no attribute 'is_ad_related'")

        await scanner.send_handler(event)

        assert len(scanner.requests) == 1, "request entry must survive a broken raw dump"
        entry = scanner.requests[0]
        assert entry["type"] == "request"
        assert entry["url"] == "https://example.com/staged.js"
        assert entry["raw"] is None

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_response_entry_survives_broken_to_json(self, scanner):
        """Same guarantee on the response side, which works today but is one
        upstream CDP field away from the identical failure."""
        event = _make_response_event(headers={"Content-Type": "text/html"})
        event.response.to_json.side_effect = AttributeError("boom")

        await scanner.receive_handler(event)

        assert len(scanner.requests) == 1
        assert scanner.requests[0]["raw"] is None
        # the fields that actually matter are still usable
        assert scanner.top_level_content_type() == "text/html"


class TestSendHandler:

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_send_handler_appends_request(self, scanner):
        event = _make_request_event(method="POST")
        await scanner.send_handler(event)
        assert len(scanner.requests) == 1
        assert scanner.requests[0]["type"] == "request"
        assert scanner.requests[0]["method"] == "POST"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_send_handler_sets_first_request_time(self, scanner):
        event = _make_request_event()
        await scanner.send_handler(event)
        first_time = scanner.domain_stats["example.com"]["first_request_time"]
        assert first_time is not None

        # second call should not overwrite
        await scanner.send_handler(_make_request_event())
        assert scanner.domain_stats["example.com"]["first_request_time"] == first_time


class TestLoadingFinishedHandler:

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_loading_finished_handler_updates_bytes(self, scanner):
        # pre-populate a matching response entry
        scanner.requests.append({
            "requestId": "req-1",
            "type": "response",
            "url": "https://example.com/page",
        })
        event = _make_loading_finished_event(request_id="req-1", encoded_data_length=500)
        await scanner.loading_finished_handler(event)
        assert scanner.bytes_downloaded == 500
        assert scanner.domain_stats["example.com"]["bytes_downloaded"] == 500

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_loading_finished_handler_updates_last_finished_time(self, scanner):
        scanner.requests.append({
            "requestId": "req-1",
            "type": "response",
            "url": "https://example.com/page",
        })
        event = _make_loading_finished_event(request_id="req-1", encoded_data_length=100)
        await scanner.loading_finished_handler(event)
        assert scanner.domain_stats["example.com"]["last_finished_time"] is not None


class TestLoadingFailedHandler:

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_loading_failed_handler_appends_error(self, scanner):
        event = _make_loading_failed_event()
        await scanner.loading_failed_handler(event)
        assert len(scanner.requests) == 1
        assert scanner.requests[0]["type"] == "error"
        assert scanner.requests[0]["error_text"] == "net::ERR_FAILED"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_loading_failed_handler_includes_url_from_request(self, scanner):
        scanner.requests.append({
            "requestId": "req-1",
            "type": "request",
            "url": "https://example.com/page",
        })
        event = _make_loading_failed_event(request_id="req-1")
        await scanner.loading_failed_handler(event)
        error_entry = scanner.requests[-1]
        assert error_entry["type"] == "error"
        assert error_entry["url"] == "https://example.com/page"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_loading_failed_handler_with_blocked_reason(self, scanner):
        event = _make_loading_failed_event(blocked_reason="inspector")
        await scanner.loading_failed_handler(event)
        assert scanner.requests[-1]["blocked_reason"] == "inspector"


class TestTargetAttachedHandler:

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_target_attached_handler_worker(self, scanner):
        scanner._cdp_tab = MagicMock()
        scanner._cdp_tab.send = AsyncMock()
        event = _make_attached_event(target_type="worker")
        await scanner.target_attached_handler(event)
        # stealth inject + resume = 2 calls
        assert scanner._cdp_tab.send.call_count == 2

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_target_attached_handler_non_worker(self, scanner):
        scanner._cdp_tab = MagicMock()
        scanner._cdp_tab.send = AsyncMock()
        event = _make_attached_event(target_type="iframe")
        await scanner.target_attached_handler(event)
        # only resume, no stealth inject
        assert scanner._cdp_tab.send.call_count == 1

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_target_attached_handler_inject_failure_still_resumes(self, scanner):
        scanner._cdp_tab = MagicMock()
        call_count = 0

        async def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("inject failed")

        scanner._cdp_tab.send = AsyncMock(side_effect=side_effect)
        event = _make_attached_event(target_type="service_worker")
        await scanner.target_attached_handler(event)
        # should still attempt both calls even if first fails
        assert call_count == 2


# ---------------------------------------------------------------------------
# Scanner.bypass_warnings
# ---------------------------------------------------------------------------

class TestBypassWarnings:

    @pytest.mark.unit
    def test_bypass_warnings_no_match(self, scanner):
        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "nothing interesting here"
        assert scanner.bypass_warnings(sb) is False

    @pytest.mark.unit
    def test_bypass_warnings_selector_success(self, scanner):
        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "This site has been flagged as phishing by CloudFlare"
        sb.driver.uc_click.return_value = None
        assert scanner.bypass_warnings(sb) is True
        sb.driver.uc_click.assert_called()

    @pytest.mark.unit
    def test_bypass_warnings_selector_failure(self, scanner):
        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "This site has been flagged as phishing by CloudFlare"
        sb.driver.uc_click.side_effect = Exception("element not found")
        assert scanner.bypass_warnings(sb) is False

    @pytest.mark.unit
    def test_bypass_warnings_handler_match(self, scanner):
        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "Verify you are human"
        scanner._bypass_handlers["visual_checkbox_bypass"] = MagicMock()
        assert scanner.bypass_warnings(sb) is True
        scanner._bypass_handlers["visual_checkbox_bypass"].assert_called_once()

    @pytest.mark.unit
    def test_bypass_warnings_case_insensitive_match(self, scanner):
        # config search string is "Verify you are human"; page renders it lowercased
        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "please verify you are human to continue"
        scanner._bypass_handlers["visual_checkbox_bypass"] = MagicMock()
        assert scanner.bypass_warnings(sb) is True
        scanner._bypass_handlers["visual_checkbox_bypass"].assert_called_once()

    @pytest.mark.unit
    def test_bypass_warnings_unknown_handler(self, config_file):
        from scanner import Scanner

        scanner = Scanner(config_path=config_file)
        # replace the antibot bypass handler name with something unknown
        for bypass in scanner.BYPASSES:
            if bypass.get("handler"):
                bypass["handler"] = "nonexistent_handler"

        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "Verify you are human"
        assert scanner.bypass_warnings(sb) is False

    @pytest.mark.unit
    def test_bypass_warnings_invalid_bypass_skipped(self, scanner):
        # add an invalid bypass with missing keys
        scanner.BYPASSES.insert(0, {"type": None, "searches": None})
        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "flagged as phishing"
        # should skip the invalid bypass and still find the valid one
        assert scanner.bypass_warnings(sb) is True

    @pytest.mark.unit
    def test_bypass_warnings_no_selectors_or_handler(self, scanner):
        # replace all bypasses with one that has searches but no selectors/handler
        scanner.BYPASSES = [{"type": "bare", "searches": ["match me"]}]
        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "match me"
        assert scanner.bypass_warnings(sb) is False


# ---------------------------------------------------------------------------
# Scanner.bypass_recaptcha
# ---------------------------------------------------------------------------

class TestBypassRecaptcha:

    @pytest.mark.unit
    def test_bypass_recaptcha_not_detected(self, scanner):
        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "no captcha here"
        scanner.bypass_recaptcha(sb)
        # solver should never be instantiated

    @pytest.mark.unit
    @patch("scanner.RecaptchaSolver")
    def test_bypass_recaptcha_detected(self, mock_solver_cls, scanner):
        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "Please complete the security check to access the website."
        mock_solver = MagicMock()
        mock_solver_cls.return_value = mock_solver

        scanner.bypass_recaptcha(sb)
        mock_solver_cls.assert_called_once_with(driver=sb.driver)
        mock_solver.click_recaptcha_v2.assert_called_once()
        sb.driver.click.assert_called_once_with("#btn")


# ---------------------------------------------------------------------------
# Scanner.visual_checkbox_bypass
# ---------------------------------------------------------------------------

class TestVisualCheckboxBypass:

    @pytest.mark.unit
    @patch("scanner.cv2")
    @patch("scanner.Image.open")
    def test_visual_checkbox_bypass_found(self, mock_image_open, mock_cv2, scanner, tmpdir):
        # create a fake screenshot image with a known size
        fake_screenshot = MagicMock()
        fake_screenshot.size = (800, 600)
        fake_checkbox = MagicMock()
        fake_checkbox.mode = "RGB"

        mock_image_open.side_effect = [fake_checkbox, fake_screenshot]

        # mock numpy array conversion and template matching
        screenshot_gray = MagicMock()
        screenshot_gray.shape = [600, 800]
        needle_gray = MagicMock()
        needle_gray.shape = [30, 30]
        mock_cv2.cvtColor.side_effect = [screenshot_gray, needle_gray]
        mock_cv2.TM_CCOEFF_NORMED = 5
        mock_cv2.matchTemplate.return_value = MagicMock()
        # return a high confidence match at (100, 200)
        mock_cv2.minMaxLoc.return_value = (0, 0.95, (0, 0), (100, 200))

        sb = MagicMock()
        sb.execute_cdp_cmd.return_value = {"data": "AAAA"}
        scanner._output_dir = str(tmpdir)
        config = {"checkbox_pngs": ["iVBORw0KGgo="]}

        scanner.visual_checkbox_bypass(sb, config)

        # should click at center of matched region: (100 + 15, 200 + 15)
        click_calls = [
            c for c in sb.execute_cdp_cmd.call_args_list
            if c[0][0] == "Input.dispatchMouseEvent" and c[0][1].get("type") == "mousePressed"
        ]
        assert len(click_calls) == 1
        assert click_calls[0][0][1]["x"] == 115
        assert click_calls[0][0][1]["y"] == 215

    @pytest.mark.unit
    @patch("scanner.cv2")
    @patch("scanner.Image.open")
    def test_visual_checkbox_bypass_uses_selector_first(
        self, mock_image_open, mock_cv2, scanner, tmpdir
    ):
        # When a structural selector matches a visible element, the handler
        # human-clicks its rendered center (from getBoundingClientRect) and never
        # reaches image template matching. This is the primary path for
        # polymorphic kits that randomize text/scale but keep role=button.
        fake_screenshot = MagicMock()
        fake_screenshot.size = (800, 600)
        fake_checkbox = MagicMock()
        fake_checkbox.mode = "RGB"
        mock_image_open.side_effect = [fake_checkbox, fake_screenshot]

        def cdp(cmd, params=None):
            if cmd == "Page.captureScreenshot":
                return {"data": "AAAA"}
            if cmd == "Runtime.evaluate":
                return {"result": {"value": {
                    "x": 115, "y": 215, "w": 30, "h": 30,
                    "sel": '[role="button"][tabindex="0"]',
                }}}
            return {}

        sb = MagicMock()
        sb.execute_cdp_cmd.side_effect = cdp
        scanner._output_dir = str(tmpdir)
        scanner._human_click_at = MagicMock(return_value=True)
        config = {"checkbox_pngs": ["iVBORw0KGgo="]}

        scanner.visual_checkbox_bypass(sb, config)

        # clicked the element's center via the shared human-click path...
        scanner._human_click_at.assert_called_once_with(sb, 115, 215)
        # ...and the image-matching fallback was never reached.
        mock_cv2.matchTemplate.assert_not_called()

    @pytest.mark.unit
    @patch("scanner.cv2")
    @patch("scanner.Image.open")
    def test_visual_checkbox_bypass_palette_mode_converts_to_rgb(
        self, mock_image_open, mock_cv2, scanner, tmpdir
    ):
        # Palette-mode PNGs (mode='P') must be converted to RGB before
        # cv2.cvtColor, otherwise OpenCV raises "Bad number of channels"
        # and aborts the whole bypass (regression from 2026-04-21).
        fake_screenshot = MagicMock()
        fake_screenshot.size = (800, 600)
        fake_checkbox = MagicMock()
        fake_checkbox.mode = "P"
        converted = MagicMock()
        fake_checkbox.convert.return_value = converted

        mock_image_open.side_effect = [fake_checkbox, fake_screenshot]

        screenshot_gray = MagicMock()
        screenshot_gray.shape = [600, 800]
        needle_gray = MagicMock()
        needle_gray.shape = [30, 30]
        mock_cv2.cvtColor.side_effect = [screenshot_gray, needle_gray]
        mock_cv2.TM_CCOEFF_NORMED = 5
        mock_cv2.matchTemplate.return_value = MagicMock()
        mock_cv2.minMaxLoc.return_value = (0, 0.5, (0, 0), (0, 0))

        sb = MagicMock()
        sb.execute_cdp_cmd.return_value = {"data": "AAAA"}
        scanner._output_dir = str(tmpdir)
        config = {"checkbox_pngs": ["iVBORw0KGgo="]}

        # must not raise
        scanner.visual_checkbox_bypass(sb, config)

        fake_checkbox.convert.assert_called_with("RGB")

    @pytest.mark.unit
    @patch("scanner.cv2")
    @patch("scanner.Image.open")
    def test_visual_checkbox_bypass_not_found(self, mock_image_open, mock_cv2, scanner, tmpdir, capsys):
        fake_screenshot = MagicMock()
        fake_screenshot.size = (800, 600)
        fake_checkbox = MagicMock()
        fake_checkbox.mode = "RGB"

        mock_image_open.side_effect = [fake_checkbox, fake_screenshot]

        screenshot_gray = MagicMock()
        screenshot_gray.shape = [600, 800]
        needle_gray = MagicMock()
        needle_gray.shape = [30, 30]
        mock_cv2.cvtColor.side_effect = [screenshot_gray, needle_gray]
        mock_cv2.TM_CCOEFF_NORMED = 5
        mock_cv2.matchTemplate.return_value = MagicMock()
        # return a low confidence score — no match
        mock_cv2.minMaxLoc.return_value = (0, 0.5, (0, 0), (0, 0))

        sb = MagicMock()
        sb.execute_cdp_cmd.return_value = {"data": "AAAA"}
        scanner._output_dir = str(tmpdir)
        config = {"checkbox_pngs": ["iVBORw0KGgo="]}

        scanner.visual_checkbox_bypass(sb, config)

        click_calls = [
            c for c in sb.execute_cdp_cmd.call_args_list
            if c[0][0] == "Input.dispatchMouseEvent"
        ]
        assert len(click_calls) == 0
        captured = capsys.readouterr()
        assert "Failed to find checkbox visually" in captured.out

    @pytest.mark.unit
    @patch("scanner.time.sleep")
    @patch("scanner.cv2")
    @patch("scanner.Image.open")
    def test_visual_checkbox_bypass_multi_click_disabled_default(
        self, mock_image_open, mock_cv2, _mock_sleep, scanner, tmpdir
    ):
        # Without enable_multi_click, the handler must take exactly one
        # screenshot and dispatch exactly one click — same as before this feature.
        fake_screenshot = MagicMock()
        fake_screenshot.size = (800, 600)
        fake_checkbox = MagicMock()
        fake_checkbox.mode = "RGB"

        mock_image_open.side_effect = [fake_checkbox, fake_screenshot]

        screenshot_gray = MagicMock()
        screenshot_gray.shape = [600, 800]
        needle_gray = MagicMock()
        needle_gray.shape = [30, 30]
        mock_cv2.cvtColor.side_effect = [screenshot_gray, needle_gray]
        mock_cv2.TM_CCOEFF_NORMED = 5
        mock_cv2.matchTemplate.return_value = MagicMock()
        mock_cv2.minMaxLoc.return_value = (0, 0.95, (0, 0), (100, 200))

        sb = MagicMock()
        sb.execute_cdp_cmd.return_value = {"data": "AAAA"}
        scanner._output_dir = str(tmpdir)
        config = {"checkbox_pngs": ["iVBORw0KGgo="]}

        scanner.visual_checkbox_bypass(sb, config)

        screenshot_calls = [
            c for c in sb.execute_cdp_cmd.call_args_list
            if c[0][0] == "Page.captureScreenshot"
        ]
        click_calls = [
            c for c in sb.execute_cdp_cmd.call_args_list
            if c[0][0] == "Input.dispatchMouseEvent" and c[0][1].get("type") == "mousePressed"
        ]
        assert len(screenshot_calls) == 1
        assert len(click_calls) == 1

    @pytest.mark.unit
    @patch("scanner.time.sleep")
    @patch("scanner.cv2")
    @patch("scanner.Image.open")
    def test_visual_checkbox_bypass_multi_click_two_iterations(
        self, mock_image_open, mock_cv2, _mock_sleep, scanner, tmpdir
    ):
        # Two pngs, three iterations allowed:
        #   iter 1: png[0] matches → click
        #   iter 2: png[0] excluded, png[1] matches → click
        #   iter 3: both excluded → no match → return
        fake_checkbox_0 = MagicMock(); fake_checkbox_0.mode = "RGB"; fake_checkbox_0.size = (30, 30)
        fake_checkbox_1 = MagicMock(); fake_checkbox_1.mode = "RGB"; fake_checkbox_1.size = (30, 30)
        screenshot_1 = MagicMock(); screenshot_1.size = (800, 600)
        screenshot_2 = MagicMock(); screenshot_2.size = (800, 600)
        screenshot_3 = MagicMock(); screenshot_3.size = (800, 600)

        mock_image_open.side_effect = [
            fake_checkbox_0, fake_checkbox_1,  # config load
            screenshot_1, screenshot_2, screenshot_3,  # one per iteration
        ]

        screenshot_gray = MagicMock(); screenshot_gray.shape = [600, 800]
        needle_gray_0 = MagicMock(); needle_gray_0.shape = [30, 30]
        needle_gray_1 = MagicMock(); needle_gray_1.shape = [30, 30]
        # cvtColor is called once for screenshot per iteration, then once per
        # non-matched png until a match is found:
        #   iter 1: screenshot_gray, needle_gray_0 (match → break)
        #   iter 2: screenshot_gray, needle_gray_1 (png[0] skipped, png[1] match)
        #   iter 3: screenshot_gray (both skipped, no needle calls)
        mock_cv2.cvtColor.side_effect = [
            screenshot_gray, needle_gray_0,
            screenshot_gray, needle_gray_1,
            screenshot_gray,
        ]
        mock_cv2.TM_CCOEFF_NORMED = 5
        mock_cv2.matchTemplate.return_value = MagicMock()
        # Both matches are at confidence 0.95 with distinct coordinates so we
        # can distinguish click 1 from click 2.
        mock_cv2.minMaxLoc.side_effect = [
            (0, 0.95, (0, 0), (100, 200)),  # iter 1, png[0]
            (0, 0.95, (0, 0), (300, 400)),  # iter 2, png[1]
        ]

        sb = MagicMock()
        sb.execute_cdp_cmd.return_value = {"data": "AAAA"}
        scanner._output_dir = str(tmpdir)
        config = {
            "checkbox_pngs": ["png0", "png1"],
            "enable_multi_click": True,
            "max_click_iterations": 3,
        }

        scanner.visual_checkbox_bypass(sb, config)

        screenshot_calls = [
            c for c in sb.execute_cdp_cmd.call_args_list
            if c[0][0] == "Page.captureScreenshot"
        ]
        click_calls = [
            c for c in sb.execute_cdp_cmd.call_args_list
            if c[0][0] == "Input.dispatchMouseEvent" and c[0][1].get("type") == "mousePressed"
        ]
        assert len(screenshot_calls) == 3
        assert len(click_calls) == 2
        # Click 1 at center of (100,200) + (15,15) = (115,215)
        # Click 2 at center of (300,400) + (15,15) = (315,415)
        assert (click_calls[0][0][1]["x"], click_calls[0][0][1]["y"]) == (115, 215)
        assert (click_calls[1][0][1]["x"], click_calls[1][0][1]["y"]) == (315, 415)

    @pytest.mark.unit
    @patch("scanner.time.sleep")
    @patch("scanner.cv2")
    @patch("scanner.Image.open")
    def test_visual_checkbox_bypass_multi_click_excludes_matched_index(
        self, mock_image_open, mock_cv2, _mock_sleep, scanner, tmpdir, capsys
    ):
        # Single png that would match every screenshot. With multi-click on,
        # the index must be excluded after iter 1, so iter 2 finds no match
        # and the handler returns after exactly one click.
        fake_checkbox = MagicMock(); fake_checkbox.mode = "RGB"; fake_checkbox.size = (30, 30)
        screenshot_1 = MagicMock(); screenshot_1.size = (800, 600)
        screenshot_2 = MagicMock(); screenshot_2.size = (800, 600)

        mock_image_open.side_effect = [fake_checkbox, screenshot_1, screenshot_2]

        screenshot_gray = MagicMock(); screenshot_gray.shape = [600, 800]
        needle_gray = MagicMock(); needle_gray.shape = [30, 30]
        # iter 1: screenshot_gray, needle_gray (match)
        # iter 2: screenshot_gray (png[0] skipped, no needle calls)
        mock_cv2.cvtColor.side_effect = [
            screenshot_gray, needle_gray,
            screenshot_gray,
        ]
        mock_cv2.TM_CCOEFF_NORMED = 5
        mock_cv2.matchTemplate.return_value = MagicMock()
        # Only one matchTemplate/minMaxLoc result needed — iter 2 has no
        # candidates so neither is called.
        mock_cv2.minMaxLoc.return_value = (0, 0.95, (0, 0), (100, 200))

        sb = MagicMock()
        sb.execute_cdp_cmd.return_value = {"data": "AAAA"}
        scanner._output_dir = str(tmpdir)
        config = {
            "checkbox_pngs": ["png0"],
            "enable_multi_click": True,
            "max_click_iterations": 2,
        }

        scanner.visual_checkbox_bypass(sb, config)

        click_calls = [
            c for c in sb.execute_cdp_cmd.call_args_list
            if c[0][0] == "Input.dispatchMouseEvent" and c[0][1].get("type") == "mousePressed"
        ]
        assert len(click_calls) == 1
        # matchTemplate called exactly once — iter 2 had nothing to match
        assert mock_cv2.matchTemplate.call_count == 1
        captured = capsys.readouterr()
        assert "no further matches, done after 1 click(s)" in captured.out

    @pytest.mark.unit
    @patch("scanner.time.sleep")
    @patch("scanner.cv2")
    @patch("scanner.Image.open")
    def test_visual_checkbox_bypass_multi_click_max_iterations_cap(
        self, mock_image_open, mock_cv2, _mock_sleep, scanner, tmpdir, capsys
    ):
        # Two pngs, max_click_iterations=2. Both pngs would keep matching, but
        # the outer loop must stop at exactly two clicks regardless.
        fake_checkbox_0 = MagicMock(); fake_checkbox_0.mode = "RGB"; fake_checkbox_0.size = (30, 30)
        fake_checkbox_1 = MagicMock(); fake_checkbox_1.mode = "RGB"; fake_checkbox_1.size = (30, 30)
        screenshot_1 = MagicMock(); screenshot_1.size = (800, 600)
        screenshot_2 = MagicMock(); screenshot_2.size = (800, 600)

        mock_image_open.side_effect = [
            fake_checkbox_0, fake_checkbox_1,
            screenshot_1, screenshot_2,
        ]

        screenshot_gray = MagicMock(); screenshot_gray.shape = [600, 800]
        needle_gray_0 = MagicMock(); needle_gray_0.shape = [30, 30]
        needle_gray_1 = MagicMock(); needle_gray_1.shape = [30, 30]
        # iter 1: screenshot_gray, needle_gray_0 (match)
        # iter 2: screenshot_gray, needle_gray_1 (png[0] skipped, match)
        mock_cv2.cvtColor.side_effect = [
            screenshot_gray, needle_gray_0,
            screenshot_gray, needle_gray_1,
        ]
        mock_cv2.TM_CCOEFF_NORMED = 5
        mock_cv2.matchTemplate.return_value = MagicMock()
        mock_cv2.minMaxLoc.side_effect = [
            (0, 0.95, (0, 0), (100, 200)),
            (0, 0.95, (0, 0), (300, 400)),
        ]

        sb = MagicMock()
        sb.execute_cdp_cmd.return_value = {"data": "AAAA"}
        scanner._output_dir = str(tmpdir)
        config = {
            "checkbox_pngs": ["png0", "png1"],
            "enable_multi_click": True,
            "max_click_iterations": 2,
        }

        scanner.visual_checkbox_bypass(sb, config)

        screenshot_calls = [
            c for c in sb.execute_cdp_cmd.call_args_list
            if c[0][0] == "Page.captureScreenshot"
        ]
        click_calls = [
            c for c in sb.execute_cdp_cmd.call_args_list
            if c[0][0] == "Input.dispatchMouseEvent" and c[0][1].get("type") == "mousePressed"
        ]
        assert len(screenshot_calls) == 2
        assert len(click_calls) == 2
        captured = capsys.readouterr()
        assert "reached max_click_iterations=2, stopping" in captured.out


# ---------------------------------------------------------------------------
# WebSocket event handlers
# ---------------------------------------------------------------------------

def _ws_event(**attrs):
    event = MagicMock()
    for k, v in attrs.items():
        setattr(event, k, v)
    return event


def _ws_frame(opcode=1, payload_data="hi"):
    frame = MagicMock()
    frame.opcode = opcode
    frame.payload_data = payload_data
    return frame


class TestWebSocketCreatedHandler:

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_records_url_and_appends_request_entry(self, scanner):
        event = _ws_event(request_id="ws-1", url="wss://example.com/8053", initiator=None)
        await scanner.websocket_created_handler(event)

        assert "ws-1" in scanner.websockets
        assert scanner.websockets["ws-1"]["url"] == "wss://example.com/8053"
        assert scanner.websockets["ws-1"]["created_at"] is not None
        assert len(scanner.requests) == 1
        assert scanner.requests[0]["type"] == "websocket_created"
        assert scanner.requests[0]["url"] == "wss://example.com/8053"
        assert scanner.requests[0]["requestId"] == "ws-1"


class TestWebSocketHandshakeHandlers:

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_handshake_request_captures_headers(self, scanner):
        req = MagicMock()
        req.headers = {"User-Agent": "ua"}
        event = _ws_event(request_id="ws-1", request=req)
        await scanner.websocket_will_send_handshake_handler(event)

        assert scanner.websockets["ws-1"]["handshake_request_headers"] == {"User-Agent": "ua"}
        assert scanner.requests[-1]["type"] == "websocket_handshake_request"
        assert scanner.requests[-1]["headers"] == {"User-Agent": "ua"}

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_handshake_response_captures_status_and_headers(self, scanner):
        resp = MagicMock()
        resp.status = 101
        resp.headers = {"Upgrade": "websocket"}
        event = _ws_event(request_id="ws-1", response=resp)
        await scanner.websocket_handshake_response_handler(event)

        record = scanner.websockets["ws-1"]
        assert record["handshake_response_status"] == 101
        assert record["handshake_response_headers"] == {"Upgrade": "websocket"}
        assert scanner.requests[-1]["type"] == "websocket_handshake_response"
        assert scanner.requests[-1]["status_code"] == 101


class TestWebSocketFrameHandlers:

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_frame_sent_appends_frame_and_entry(self, scanner):
        scanner.websockets["ws-1"] = {
            "requestId": "ws-1", "url": "wss://example.com/8053",
            "created_at": None, "handshake_request_headers": None,
            "handshake_response_status": None, "handshake_response_headers": None,
            "frames": [], "closed_at": None,
        }
        event = _ws_event(request_id="ws-1", response=_ws_frame(opcode=1, payload_data="ping"))
        await scanner.websocket_frame_sent_handler(event)

        frames = scanner.websockets["ws-1"]["frames"]
        assert len(frames) == 1
        assert frames[0]["direction"] == "sent"
        assert frames[0]["opcode"] == 1
        assert frames[0]["payload_data"] == "ping"
        assert frames[0]["payload_truncated"] is False
        assert scanner.requests[-1]["type"] == "websocket_frame_sent"
        assert scanner.requests[-1]["url"] == "wss://example.com/8053"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_frame_received_appends_frame_and_entry(self, scanner):
        event = _ws_event(request_id="ws-1", response=_ws_frame(opcode=2, payload_data="YWJj"))
        await scanner.websocket_frame_received_handler(event)

        frames = scanner.websockets["ws-1"]["frames"]
        assert len(frames) == 1
        assert frames[0]["direction"] == "received"
        assert frames[0]["opcode"] == 2
        assert frames[0]["payload_data"] == "YWJj"
        assert scanner.requests[-1]["type"] == "websocket_frame_received"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_frame_payload_truncated_when_over_cap(self, scanner):
        scanner.MAX_WS_FRAME_BYTES = 8
        event = _ws_event(
            request_id="ws-1",
            response=_ws_frame(opcode=1, payload_data="A" * 32),
        )
        await scanner.websocket_frame_sent_handler(event)

        frame = scanner.websockets["ws-1"]["frames"][0]
        assert frame["payload_truncated"] is True
        assert len(frame["payload_data"]) == 8


class TestWebSocketErrorAndClosedHandlers:

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_frame_error_appends_entry(self, scanner):
        event = _ws_event(request_id="ws-1", error_message="protocol error")
        await scanner.websocket_frame_error_handler(event)

        assert scanner.requests[-1]["type"] == "websocket_frame_error"
        assert scanner.requests[-1]["error_message"] == "protocol error"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_closed_sets_closed_at(self, scanner):
        event = _ws_event(request_id="ws-1")
        await scanner.websocket_closed_handler(event)

        assert scanner.websockets["ws-1"]["closed_at"] is not None
        assert scanner.requests[-1]["type"] == "websocket_closed"


class TestFormatWebSocketBlock:

    @pytest.mark.unit
    def test_block_contains_marker_url_and_frames(self, scanner):
        ws = {
            "requestId": "ws-1",
            "url": "wss://example.com/8053",
            "created_at": "2026-04-21T09:00:00",
            "handshake_request_headers": {},
            "handshake_response_status": 101,
            "handshake_response_headers": {},
            "frames": [
                {"date": "2026-04-21T09:00:01", "direction": "sent",
                 "opcode": 1, "payload_data": "hello", "payload_truncated": False},
                {"date": "2026-04-21T09:00:02", "direction": "received",
                 "opcode": 1, "payload_data": "world", "payload_truncated": True},
            ],
            "closed_at": "2026-04-21T09:00:03",
        }
        block = scanner._format_websocket_block(ws)
        assert "MARKER URL: wss://example.com/8053" in block
        assert "handshake_response_status: 101" in block
        assert "SENT op=1" in block
        assert "RECV op=1 [truncated]" in block
        assert "hello" in block
        assert "world" in block
        assert "closed_at: 2026-04-21T09:00:03" in block

    @pytest.mark.unit
    def test_block_handles_missing_fields(self, scanner):
        ws = {
            "requestId": "ws-1",
            "url": None,
            "created_at": None,
            "handshake_request_headers": None,
            "handshake_response_status": None,
            "handshake_response_headers": None,
            "frames": [],
            "closed_at": None,
        }
        block = scanner._format_websocket_block(ws)
        # MARKER URL line is always present; uses placeholder when url missing
        assert "MARKER URL: <unknown>" in block


class TestScannerInitWebSockets:

    @pytest.mark.unit
    def test_init_includes_websockets_and_frame_cap(self, scanner):
        assert scanner.websockets == {}
        assert scanner.MAX_WS_FRAME_BYTES == 65536


# ---------------------------------------------------------------------------
# Scanner._count_inflight_requests
# ---------------------------------------------------------------------------

class TestCountInflightRequests:

    @pytest.mark.unit
    def test_empty_requests(self, scanner):
        assert scanner._count_inflight_requests() == 0

    @pytest.mark.unit
    def test_single_unsettled_request(self, scanner):
        scanner.requests = [
            {"type": "request", "requestId": "r1", "url": "https://x"},
        ]
        assert scanner._count_inflight_requests() == 1

    @pytest.mark.unit
    def test_request_with_response(self, scanner):
        scanner.requests = [
            {"type": "request", "requestId": "r1", "url": "https://x"},
            {"type": "response", "requestId": "r1", "url": "https://x"},
        ]
        assert scanner._count_inflight_requests() == 0

    @pytest.mark.unit
    def test_request_with_error(self, scanner):
        scanner.requests = [
            {"type": "request", "requestId": "r1", "url": "https://x"},
            {"type": "error", "requestId": "r1", "error_text": "net::ERR_FAILED"},
        ]
        assert scanner._count_inflight_requests() == 0

    @pytest.mark.unit
    def test_two_requests_one_responded(self, scanner):
        scanner.requests = [
            {"type": "request", "requestId": "r1", "url": "https://x"},
            {"type": "request", "requestId": "r2", "url": "https://y"},
            {"type": "response", "requestId": "r1", "url": "https://x"},
        ]
        assert scanner._count_inflight_requests() == 1

    @pytest.mark.unit
    def test_websocket_entries_ignored(self, scanner):
        scanner.requests = [
            {"type": "websocket_created", "requestId": "ws1", "url": "wss://x"},
            {"type": "websocket_frame_sent", "requestId": "ws1"},
            {"type": "websocket_frame_received", "requestId": "ws1"},
        ]
        assert scanner._count_inflight_requests() == 0

    @pytest.mark.unit
    def test_missing_request_id_skipped(self, scanner):
        scanner.requests = [
            {"type": "request"},                         # no requestId
            {"type": "request", "requestId": "r1"},      # valid, unsettled
            {"type": "response"},                         # no requestId
        ]
        assert scanner._count_inflight_requests() == 1


# ---------------------------------------------------------------------------
# last_network_event_ts tracking across CDP handlers
# ---------------------------------------------------------------------------

class TestLastNetworkEventTsUpdated:

    @pytest.mark.unit
    def test_init_starts_at_zero(self, scanner):
        assert scanner.last_network_event_ts == 0.0

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_send_handler_updates_ts(self, scanner):
        with patch("scanner.time.monotonic", return_value=1234.5):
            await scanner.send_handler(_make_request_event())
        assert scanner.last_network_event_ts == 1234.5

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_receive_handler_updates_ts(self, scanner):
        with patch("scanner.time.monotonic", return_value=2345.6):
            await scanner.receive_handler(_make_response_event())
        assert scanner.last_network_event_ts == 2345.6

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_loading_finished_updates_ts(self, scanner):
        scanner.requests.append({
            "requestId": "req-1", "type": "response", "url": "https://example.com/",
        })
        with patch("scanner.time.monotonic", return_value=3456.7):
            await scanner.loading_finished_handler(
                _make_loading_finished_event(request_id="req-1", encoded_data_length=10)
            )
        assert scanner.last_network_event_ts == 3456.7

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_loading_failed_updates_ts(self, scanner):
        with patch("scanner.time.monotonic", return_value=4567.8):
            await scanner.loading_failed_handler(_make_loading_failed_event())
        assert scanner.last_network_event_ts == 4567.8


# ---------------------------------------------------------------------------
# Scanner._wait_for_network_quiescence
# ---------------------------------------------------------------------------

class TestWaitForNetworkQuiescence:

    def _mock_sb(self, urls):
        """Build a mock SB whose cdp.get_current_url returns each value in ``urls``
        in sequence, repeating the final value forever."""
        sb = MagicMock()
        iterator = iter(urls)
        last = [urls[-1]] if urls else [None]

        def get_url():
            try:
                cur = next(iterator)
                last[0] = cur
                return cur
            except StopIteration:
                return last[0]

        sb.cdp.get_current_url.side_effect = get_url
        return sb

    @pytest.mark.unit
    def test_zero_cap_returns_immediately(self, scanner):
        sb = MagicMock()
        with patch("scanner.time.sleep") as mock_sleep:
            scanner._wait_for_network_quiescence(sb, max_extra_wait=0)
        mock_sleep.assert_not_called()
        sb.cdp.get_current_url.assert_not_called()

    @pytest.mark.unit
    def test_quiet_from_start_returns_early(self, scanner):
        # No in-flight requests, last_network_event_ts well in the past, URL
        # never changes. Exits as soon as url_idle >= quiet_window. The loop
        # always runs at least one poll because url_last_change is seeded to
        # ``start`` — so url_idle needs quiet_window seconds of fake clock to
        # accumulate before exit.
        scanner.last_network_event_ts = 100.0
        # start=200.0; then now ticks forward by poll_interval each iteration.
        # With quiet_window=1.0 and poll_interval=0.25, expect ~4 polls.
        clock = iter([200.0] + [200.0 + 0.25 * i for i in range(1, 20)])
        sb = self._mock_sb(["https://fixed.example/"])
        with patch("scanner.time.monotonic", side_effect=lambda: next(clock)), \
             patch("scanner.time.sleep") as mock_sleep:
            scanner._wait_for_network_quiescence(
                sb, max_extra_wait=5.0, quiet_window=1.0, poll_interval=0.25
            )
        # well short of the 5s cap — exit fires as soon as url_idle crosses 1s
        assert mock_sleep.call_count < 10

    @pytest.mark.unit
    def test_inflight_forces_cap(self, scanner):
        # A request sits in-flight forever → loop runs until max_extra_wait.
        scanner.requests = [
            {"type": "request", "requestId": "r1", "url": "https://x"},
        ]
        scanner.last_network_event_ts = 0.0  # treated as "no events yet"
        # Generate a clock that eventually exceeds the cap. We need enough
        # values for: initial `start`, plus per-iteration `now`, until elapsed
        # >= max_extra_wait.
        clock = iter([100.0] + [100.0 + i * 0.25 for i in range(1, 50)])
        sb = self._mock_sb(["https://fixed.example/"])
        with patch("scanner.time.monotonic", side_effect=lambda: next(clock)), \
             patch("scanner.time.sleep") as mock_sleep:
            scanner._wait_for_network_quiescence(
                sb, max_extra_wait=2.0, quiet_window=0.5, poll_interval=0.25
            )
        # inflight != 0 means no early exit, so we hit the cap after several polls
        assert mock_sleep.call_count >= 1

    @pytest.mark.unit
    def test_url_change_resets_idle_clock(self, scanner):
        # No in-flight requests, last_network_event_ts safely in the past,
        # but URL changes on the second poll. The change resets url_last_change
        # and must delay the exit relative to the no-change case.
        scanner.last_network_event_ts = 100.0
        # monotonic returns: start=200.0, then per-iteration now values
        clock_vals = [200.0, 200.1, 200.3, 200.6, 201.0, 201.5, 202.0, 203.0, 204.0]
        clock = iter(clock_vals)
        sb = self._mock_sb([
            "https://a.example/",   # initial (start)
            "https://a.example/",   # iter 1: same
            "https://b.example/",   # iter 2: changes — resets url_idle
            "https://b.example/",   # iter 3
            "https://b.example/",   # iter 4
            "https://b.example/",   # iter 5
            "https://b.example/",   # iter 6
        ])
        with patch("scanner.time.monotonic", side_effect=lambda: next(clock)), \
             patch("scanner.time.sleep"):
            scanner._wait_for_network_quiescence(
                sb, max_extra_wait=10.0, quiet_window=1.0, poll_interval=0.25
            )
        # URL change on iter 2 should have forced at least one more poll
        assert sb.cdp.get_current_url.call_count >= 3

    @pytest.mark.unit
    def test_get_current_url_exception_is_tolerated(self, scanner):
        # First get_current_url call (at start) raises. Loop should not crash;
        # subsequent calls return a stable URL and loop exits cleanly once
        # url_idle >= quiet_window.
        scanner.last_network_event_ts = 100.0
        sb = MagicMock()
        call_count = [0]

        def get_url():
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("cdp disconnected")
            return "https://x/"

        sb.cdp.get_current_url.side_effect = get_url
        clock = iter([200.0] + [200.0 + 0.25 * i for i in range(1, 20)])
        with patch("scanner.time.monotonic", side_effect=lambda: next(clock)), \
             patch("scanner.time.sleep"):
            scanner._wait_for_network_quiescence(
                sb, max_extra_wait=5.0, quiet_window=1.0, poll_interval=0.25
            )
        # didn't raise; called get_current_url at least twice (once raised, then success)
        assert call_count[0] >= 2


# ---------------------------------------------------------------------------
# PhishkitConfig scan_waits loading
# ---------------------------------------------------------------------------

class TestLoadConfigScanWaits:

    @pytest.mark.unit
    def test_scan_waits_defaults_when_missing(self, tmpdir):
        from scanner import _load_config

        path = str(tmpdir.join("minimal.yaml"))
        with open(path, "w") as f:
            yaml.dump({}, f)

        config = _load_config(path)
        assert config.additional_wait == 3
        assert config.max_network_wait == 10.0

    @pytest.mark.unit
    def test_scan_waits_overrides(self, tmpdir):
        from scanner import _load_config

        path = str(tmpdir.join("override.yaml"))
        with open(path, "w") as f:
            yaml.dump({"scan_waits": {"additional_wait": 5, "max_network_wait": 22.5}}, f)

        config = _load_config(path)
        assert config.additional_wait == 5
        assert config.max_network_wait == 22.5

    @pytest.mark.unit
    def test_scanner_exposes_scan_waits_attrs(self, scanner):
        # sample_config_data in conftest does NOT set scan_waits → defaults apply
        assert scanner.ADDITIONAL_WAIT == 3
        assert scanner.MAX_NETWORK_WAIT == 10.0
