from io import StringIO
from unittest.mock import MagicMock, patch
import pytest
import re

from saq.monitor import MonitorEmitter, emit_monitor, enable_monitor_cache, enable_monitor_fluent_bit, enable_monitor_logging, enable_monitor_stderr, enable_monitor_stdout, get_emitter, reset_emitter
from saq.monitor_definitions import MONITOR_TEST
from tests.saq.helpers import log_count

LOG_TEST = "log test"
LOG_TEST_2 = "log test 2"

@pytest.mark.unit
def test_get_emitter():
    assert isinstance(get_emitter(), MonitorEmitter)

@pytest.mark.unit
def test_emit_monitor_logging():
    emit_monitor(MONITOR_TEST, LOG_TEST)
    assert log_count(LOG_TEST) == 0
    enable_monitor_logging()
    emit_monitor(MONITOR_TEST, LOG_TEST)
    assert log_count(LOG_TEST) == 1

@pytest.mark.unit
def test_emit_monitor_logging_with_identifier():
    emit_monitor(MONITOR_TEST, LOG_TEST, "id")
    assert log_count(LOG_TEST) == 0
    enable_monitor_logging()
    emit_monitor(MONITOR_TEST, LOG_TEST, "id")
    assert log_count(LOG_TEST) == 1

@pytest.mark.unit
def test_emit_monitor_stdout(capsys):
    emit_monitor(MONITOR_TEST, LOG_TEST)
    captured = capsys.readouterr()
    assert LOG_TEST not in captured.out
    enable_monitor_stdout()
    emit_monitor(MONITOR_TEST, LOG_TEST)
    captured = capsys.readouterr()
    assert LOG_TEST in captured.out

@pytest.mark.unit
def test_emit_monitor_stderr(capsys):
    emit_monitor(MONITOR_TEST, LOG_TEST)
    captured = capsys.readouterr()
    assert LOG_TEST not in captured.err
    enable_monitor_stderr()
    emit_monitor(MONITOR_TEST, LOG_TEST)
    captured = capsys.readouterr()
    assert LOG_TEST in captured.err

@pytest.mark.unit
def test_emit_monitor_cache():
    emit_monitor(MONITOR_TEST, LOG_TEST)
    assert not get_emitter().cache
    enable_monitor_cache()
    emit_monitor(MONITOR_TEST, LOG_TEST)
    assert get_emitter().cache
    cache_entry = get_emitter().cache[MONITOR_TEST.category][MONITOR_TEST.name]
    assert cache_entry.value == LOG_TEST
    assert not cache_entry.identifier

    # emit the same message and get a different cache entry
    emit_monitor(MONITOR_TEST, LOG_TEST)
    new_cache_entry= get_emitter().cache[MONITOR_TEST.category][MONITOR_TEST.name]
    assert cache_entry is not new_cache_entry
    assert cache_entry.value == LOG_TEST
    assert not cache_entry.identifier
    cache_entry = new_cache_entry

    # emit a new message and get a new cache entry with a different value
    emit_monitor(MONITOR_TEST, LOG_TEST_2)
    new_cache_entry= get_emitter().cache[MONITOR_TEST.category][MONITOR_TEST.name]
    assert cache_entry is not new_cache_entry
    assert new_cache_entry.value == LOG_TEST_2
    assert not new_cache_entry.identifier

    # dump the cache
    _buffer = StringIO()
    get_emitter().dump_cache(_buffer)
    # [test] (test): log test 2 @ 2025-04-09 12:43:11.524041
    assert re.match(r"^\[test\] \(test\): log test 2 @ [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}$", _buffer.getvalue().strip())

    # emit a new message with an identifier
    emit_monitor(MONITOR_TEST, LOG_TEST, "id")
    new_cache_entry= get_emitter().cache[MONITOR_TEST.category][MONITOR_TEST.name]
    assert cache_entry is not new_cache_entry
    assert new_cache_entry.value == LOG_TEST
    assert new_cache_entry.identifier == "id"

    # dump the cache
    _buffer = StringIO()
    get_emitter().dump_cache(_buffer)
    # [test] (test): log test 2 @ 2025-04-09 12:43:11.524041
    assert re.match(r"^\[test\] \(test:id\): log test @ [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}$", _buffer.getvalue().strip())

@pytest.mark.unit
def test_fluent_bit_not_called_when_disabled():
    """fluent-bit sender is not called when use_fluent_bit is False (default)"""
    emitter = get_emitter()
    assert not emitter.use_fluent_bit
    assert emitter.fluent_bit_sender is None
    with patch("saq.monitor.sender.FluentSender") as mock_sender_class:
        emit_monitor(MONITOR_TEST, LOG_TEST)
        mock_sender_class.assert_not_called()

@pytest.mark.unit
def test_fluent_bit_emits_structured_data():
    """fluent-bit emits structured data with correct fields when enabled"""
    with patch("saq.monitor.sender.FluentSender") as mock_sender_class:
        mock_sender_instance = MagicMock()
        mock_sender_class.return_value = mock_sender_instance

        enable_monitor_fluent_bit("localhost", 24224, "ace.monitor")
        emit_monitor(MONITOR_TEST, LOG_TEST)

        mock_sender_instance.emit.assert_called_once()
        call_args = mock_sender_instance.emit.call_args
        assert call_args[0][0] is None
        data = call_args[0][1]
        assert data["category"] == MONITOR_TEST.category
        assert data["name"] == MONITOR_TEST.name
        assert data["value"] == LOG_TEST
        assert "timestamp" in data
        assert "identifier" not in data

@pytest.mark.unit
def test_fluent_bit_emits_with_identifier():
    """fluent-bit includes identifier in structured data when provided"""
    with patch("saq.monitor.sender.FluentSender") as mock_sender_class:
        mock_sender_instance = MagicMock()
        mock_sender_class.return_value = mock_sender_instance

        enable_monitor_fluent_bit("localhost", 24224, "ace.monitor")
        emit_monitor(MONITOR_TEST, LOG_TEST, "test-id")

        mock_sender_instance.emit.assert_called_once()
        data = mock_sender_instance.emit.call_args[0][1]
        assert data["identifier"] == "test-id"

@pytest.mark.unit
def test_fluent_bit_error_does_not_crash():
    """errors in fluent-bit emission are logged but do not crash the emitter"""
    with patch("saq.monitor.sender.FluentSender") as mock_sender_class:
        mock_sender_instance = MagicMock()
        mock_sender_instance.emit.side_effect = Exception("connection refused")
        mock_sender_class.return_value = mock_sender_instance

        enable_monitor_fluent_bit("localhost", 24224, "ace.monitor")
        result = emit_monitor(MONITOR_TEST, LOG_TEST)
        assert result is True

@pytest.mark.unit
def test_fluent_bit_sender_created_with_correct_params():
    """FluentSender is created with the correct host, port, and tag"""
    with patch("saq.monitor.sender.FluentSender") as mock_sender_class:
        enable_monitor_fluent_bit("fb-host", 12345, "my.tag")

        mock_sender_class.assert_called_once_with("my.tag", host="fb-host", port=12345)
        assert get_emitter().use_fluent_bit is True

@pytest.mark.unit
def test_reset_emitter_closes_sender():
    """reset_emitter closes the fluent-bit sender before replacing the emitter"""
    with patch("saq.monitor.sender.FluentSender") as mock_sender_class:
        mock_sender_instance = MagicMock()
        mock_sender_class.return_value = mock_sender_instance

        enable_monitor_fluent_bit("localhost", 24224, "ace.monitor")
        reset_emitter()

        mock_sender_instance.close.assert_called_once()
        assert get_emitter().fluent_bit_sender is None
        assert not get_emitter().use_fluent_bit