import json
import os
import shutil
import subprocess
from subprocess import TimeoutExpired
from unittest.mock import MagicMock, patch

import pytest
import yaml


FULL_PROXY_FALLBACK = {
    "error_patterns": [
        "ERR_TUNNEL_CONNECTION_FAILED",
        "ERR_PROXY_CONNECTION_FAILED",
        "ERR_PROXY_AUTH_FAILED",
        "ERR_PROXY_CERTIFICATE_INVALID",
    ],
    "proxy_status_codes": [400, 403, 407, 500, 502, 504, 522],
    "retry_on_timeout": True,
}

FULL_CONFIG = {"proxy_fallback": FULL_PROXY_FALLBACK}


# ---------------------------------------------------------------------------
# _matched_proxy_error_patterns
# ---------------------------------------------------------------------------


class TestMatchedProxyErrorPatterns:

    @pytest.mark.unit
    @pytest.mark.parametrize("pattern", [
        "ERR_TUNNEL_CONNECTION_FAILED",
        "ERR_PROXY_CONNECTION_FAILED",
        "ERR_PROXY_AUTH_FAILED",
        "ERR_PROXY_CERTIFICATE_INVALID",
    ])
    def test_matched_each_pattern(self, pattern):
        from phishkit import _matched_proxy_error_patterns
        patterns = FULL_PROXY_FALLBACK["error_patterns"]

        assert _matched_proxy_error_patterns(f"some output {pattern} here", "", patterns) == [pattern]

    @pytest.mark.unit
    def test_no_match_returns_empty(self):
        from phishkit import _matched_proxy_error_patterns
        patterns = FULL_PROXY_FALLBACK["error_patterns"]

        assert _matched_proxy_error_patterns("all good", "no errors", patterns) == []

    @pytest.mark.unit
    def test_none_inputs(self):
        from phishkit import _matched_proxy_error_patterns
        patterns = FULL_PROXY_FALLBACK["error_patterns"]

        assert _matched_proxy_error_patterns(None, None, patterns) == []

    @pytest.mark.unit
    def test_match_in_stderr_only(self):
        from phishkit import _matched_proxy_error_patterns
        patterns = FULL_PROXY_FALLBACK["error_patterns"]

        assert _matched_proxy_error_patterns(
            "", "ERR_TUNNEL_CONNECTION_FAILED", patterns,
        ) == ["ERR_TUNNEL_CONNECTION_FAILED"]

    @pytest.mark.unit
    def test_custom_patterns(self):
        from phishkit import _matched_proxy_error_patterns

        assert _matched_proxy_error_patterns(
            "CUSTOM_ERR occurred", "", ["CUSTOM_ERR"]
        ) == ["CUSTOM_ERR"]
        assert _matched_proxy_error_patterns(
            "CUSTOM_ERR occurred", "", ["OTHER_ERR"]
        ) == []

    @pytest.mark.unit
    def test_multiple_matches_returns_all(self):
        from phishkit import _matched_proxy_error_patterns
        patterns = ["ERR_A", "ERR_B", "ERR_C"]

        assert _matched_proxy_error_patterns(
            "ERR_A in stdout", "ERR_C in stderr", patterns,
        ) == ["ERR_A", "ERR_C"]


# ---------------------------------------------------------------------------
# _matched_proxy_status_code
# ---------------------------------------------------------------------------

class TestMatchedProxyStatusCode:

    @pytest.mark.unit
    def test_matching_status_code(self, tmpdir):
        from phishkit import _matched_proxy_status_code

        output_dir = str(tmpdir)
        requests_data = [
            {"type": "request", "url": "https://example.com", "requestId": "1"},
            {"type": "response", "url": "https://example.com", "requestId": "1", "status_code": 502},
        ]
        with open(os.path.join(output_dir, "requests.json"), "w") as f:
            json.dump(requests_data, f)

        assert _matched_proxy_status_code(output_dir, [502, 504]) == 502

    @pytest.mark.unit
    def test_non_matching_status_code(self, tmpdir):
        from phishkit import _matched_proxy_status_code

        output_dir = str(tmpdir)
        requests_data = [
            {"type": "request", "url": "https://example.com", "requestId": "1"},
            {"type": "response", "url": "https://example.com", "requestId": "1", "status_code": 200},
        ]
        with open(os.path.join(output_dir, "requests.json"), "w") as f:
            json.dump(requests_data, f)

        assert _matched_proxy_status_code(output_dir, [502, 504]) is None

    @pytest.mark.unit
    def test_missing_requests_json(self, tmpdir):
        from phishkit import _matched_proxy_status_code

        assert _matched_proxy_status_code(str(tmpdir), [502]) is None

    @pytest.mark.unit
    def test_empty_requests_json(self, tmpdir):
        from phishkit import _matched_proxy_status_code

        output_dir = str(tmpdir)
        with open(os.path.join(output_dir, "requests.json"), "w") as f:
            json.dump([], f)

        assert _matched_proxy_status_code(output_dir, [502]) is None

    @pytest.mark.unit
    def test_empty_status_codes_list(self, tmpdir):
        from phishkit import _matched_proxy_status_code

        assert _matched_proxy_status_code(str(tmpdir), []) is None

    @pytest.mark.unit
    def test_only_checks_first_response(self, tmpdir):
        from phishkit import _matched_proxy_status_code

        output_dir = str(tmpdir)
        requests_data = [
            {"type": "request", "url": "https://example.com", "requestId": "1"},
            {"type": "response", "url": "https://example.com", "requestId": "1", "status_code": 200},
            {"type": "response", "url": "https://cdn.example.com/bad", "requestId": "2", "status_code": 502},
        ]
        with open(os.path.join(output_dir, "requests.json"), "w") as f:
            json.dump(requests_data, f)

        assert _matched_proxy_status_code(output_dir, [502]) is None


# ---------------------------------------------------------------------------
# _sanitize_proxy_for_display
# ---------------------------------------------------------------------------

class TestSanitizeProxyForDisplay:

    @pytest.mark.unit
    def test_none_returns_none(self):
        from phishkit import _sanitize_proxy_for_display

        assert _sanitize_proxy_for_display(None) is None

    @pytest.mark.unit
    def test_empty_returns_none(self):
        from phishkit import _sanitize_proxy_for_display

        assert _sanitize_proxy_for_display("") is None

    @pytest.mark.unit
    def test_no_credentials_passthrough(self):
        from phishkit import _sanitize_proxy_for_display

        assert _sanitize_proxy_for_display("socks5://gate.example:1080") == "socks5://gate.example:1080"
        assert _sanitize_proxy_for_display("proxy.example:8080") == "proxy.example:8080"

    @pytest.mark.unit
    def test_strips_credentials_with_scheme(self):
        from phishkit import _sanitize_proxy_for_display

        assert _sanitize_proxy_for_display(
            "socks5://user:p@ss@gate.example:1080"
        ) == "socks5://gate.example:1080"

    @pytest.mark.unit
    def test_strips_credentials_without_scheme(self):
        from phishkit import _sanitize_proxy_for_display

        assert _sanitize_proxy_for_display("user:pass@gate.example:1080") == "gate.example:1080"


# ---------------------------------------------------------------------------
# _sync_config
# ---------------------------------------------------------------------------

class TestSyncConfig:

    @pytest.mark.unit
    def test_sync_config_valid_file(self, tmpdir, monkeypatch):
        import phishkit as phishkit_mod

        source = str(tmpdir.join("source_config.yaml"))
        with open(source, "w") as f:
            f.write("test: true\n")

        dest_dir = str(tmpdir.join("shared"))
        monkeypatch.setattr(phishkit_mod, "SHARED_CONFIG_DIR", dest_dir)

        result = phishkit_mod._sync_config(source)
        assert result is not None
        assert os.path.dirname(result) == dest_dir
        assert os.path.basename(result).startswith("phishkit_config-")
        assert result.endswith(".yaml")
        assert os.path.isfile(result)
        with open(result) as f:
            assert f.read() == "test: true\n"

    @pytest.mark.unit
    def test_sync_config_none_path(self):
        from phishkit import _sync_config

        assert _sync_config(None) is None

    @pytest.mark.unit
    def test_sync_config_nonexistent_path(self):
        from phishkit import _sync_config

        assert _sync_config("/nonexistent/config.yaml") is None

    @pytest.mark.unit
    def test_sync_config_copy_failure(self, tmpdir, monkeypatch):
        import phishkit as phishkit_mod

        source = str(tmpdir.join("source.yaml"))
        with open(source, "w") as f:
            f.write("test: true\n")

        dest_dir = str(tmpdir.join("shared"))
        monkeypatch.setattr(phishkit_mod, "SHARED_CONFIG_DIR", dest_dir)
        monkeypatch.setattr(shutil, "copyfile", MagicMock(side_effect=PermissionError("denied")))

        result = phishkit_mod._sync_config(source)
        assert result is None
        # a failed sync must not leak a partial config file
        assert not [n for n in os.listdir(dest_dir) if n.startswith("phishkit_config-")]

    @pytest.mark.unit
    def test_sync_config_unique_paths(self, tmpdir, monkeypatch):
        """Each sync writes a distinct file so concurrent scans never collide."""
        import phishkit as phishkit_mod

        source = str(tmpdir.join("source.yaml"))
        with open(source, "w") as f:
            f.write("test: true\n")

        monkeypatch.setattr(phishkit_mod, "SHARED_CONFIG_DIR", str(tmpdir.join("shared")))

        first = phishkit_mod._sync_config(source)
        second = phishkit_mod._sync_config(source)
        assert first != second
        assert os.path.isfile(first)
        assert os.path.isfile(second)


# ---------------------------------------------------------------------------
# _run_scanner
# ---------------------------------------------------------------------------

class TestRunScanner:

    def _make_mock_process(self, stdout="", stderr="", returncode=0):
        proc = MagicMock()
        proc.communicate.return_value = (stdout, stderr)
        proc.returncode = returncode
        proc.kill = MagicMock()
        proc.wait = MagicMock()
        return proc

    def _write_config(self, tmpdir, config_data=None):
        """Write a YAML config file and return its absolute path.

        Passing an absolute path as config_path causes os.path.join("/opt/ace", abs)
        to return the absolute path unchanged, so the real file is read.
        """
        if config_data is None:
            config_data = FULL_CONFIG
        config_file = tmpdir.join("phishkit_config.yaml")
        config_file.write(yaml.dump(config_data))
        return str(config_file)

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_run_scanner_successful(self, mock_sync, mock_force_stop, tmpdir):
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = self._make_mock_process(stdout="scan complete", stderr="", returncode=0)
        with patch("phishkit.Popen", return_value=proc):
            stdout, stderr, rc = _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=30,
                proxy=None,
                proxy_fallback_to_direct=False,
                config_path=config_path,
            )

        assert stdout == "scan complete"
        assert rc == 0
        assert os.path.isfile(os.path.join(output_dir, "std.out"))
        assert os.path.isfile(os.path.join(output_dir, "std.err"))
        assert os.path.isfile(os.path.join(output_dir, "exit.code"))

        with open(os.path.join(output_dir, "exit.code")) as f:
            assert f.read() == "0"

        # no proxy configured — proxy.json records final_route=none
        with open(os.path.join(output_dir, "proxy.json")) as f:
            proxy_status = json.load(f)
        assert proxy_status["configured"] is False
        assert proxy_status["fallback_triggered"] is False
        assert proxy_status["fallback_reason"] is None
        assert proxy_status["final_route"] == "none"
        assert proxy_status["host"] is None

        # finally-block cleanup always attempts to stop the container, even on success
        mock_force_stop.assert_called_with("phishkit-scan-test-job")

    @pytest.mark.unit
    @patch("phishkit._graceful_stop_container")
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_run_scanner_timeout_no_proxy_returns_partial(self, mock_sync, mock_force_stop, mock_graceful, tmpdir):
        """Timeout without proxy kills the container then returns partial results.

        The scanner's SIGTERM handler flushes partial requests.json/dom.html
        before the container dies; rather than raising those away, _run_scanner
        persists std.out/exit.code/proxy.json and returns so the caller can still
        harvest captured-traffic observables.
        """
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = MagicMock()
        # first communicate call raises; second (post-kill) returns output
        proc.communicate.side_effect = [
            TimeoutExpired(cmd="docker", timeout=10),
            ("partial stdout", ""),
        ]
        # a SIGTERM-killed container exits 143
        proc.returncode = 143
        proc.kill = MagicMock()
        proc.wait = MagicMock()

        with patch("phishkit.Popen", return_value=proc):
            stdout, stderr, rc = _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=10,
                proxy=None,
                proxy_fallback_to_direct=False,
                config_path=config_path,
            )

        # does not raise; returns the (non-zero) exit code and persists outputs
        assert rc == 143
        assert os.path.isfile(os.path.join(output_dir, "std.out"))
        assert os.path.isfile(os.path.join(output_dir, "exit.code"))
        with open(os.path.join(output_dir, "exit.code")) as f:
            assert f.read() == "143"
        with open(os.path.join(output_dir, "proxy.json")) as f:
            proxy_status = json.load(f)
        assert proxy_status["fallback_triggered"] is False
        assert proxy_status["final_route"] == "none"
        # on timeout the container is SIGTERMed gracefully (so the scanner flushes
        # partial output) and still hard-reaped in the finally block
        mock_graceful.assert_any_call("phishkit-scan-test-job")
        mock_force_stop.assert_any_call("phishkit-scan-test-job")

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    @patch("phishkit._graceful_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_run_scanner_timeout_graceful_stop_precedes_hard_kill(self, mock_sync, mock_graceful, mock_force_stop, tmpdir):
        """On timeout the scanner container is SIGTERMed (graceful docker stop) BEFORE
        any hard kill, so the scanner's _on_term handler can flush partial
        requests.json/dom.html and exit 143 — otherwise a SIGKILL discards the
        in-memory request log (e.g. the redirect chain) and no URL observables survive.
        """
        from phishkit import _run_scanner

        # track interleaved call order across both stop helpers
        manager = MagicMock()
        manager.attach_mock(mock_graceful, "graceful")
        manager.attach_mock(mock_force_stop, "force")

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = MagicMock()
        proc.communicate.side_effect = [
            TimeoutExpired(cmd="docker", timeout=10),
            ("partial stdout", ""),
        ]
        proc.returncode = 143
        proc.kill = MagicMock()
        proc.wait = MagicMock()

        with patch("phishkit.Popen", return_value=proc):
            _stdout, _stderr, rc = _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=10,
                proxy=None,
                proxy_fallback_to_direct=False,
                config_path=config_path,
            )

        # graceful SIGTERM stop issued, and strictly before the finally-block hard kill
        mock_graceful.assert_any_call("phishkit-scan-test-job")
        ordered_names = [c[0] for c in manager.mock_calls]
        assert "graceful" in ordered_names and "force" in ordered_names
        assert ordered_names.index("graceful") < ordered_names.index("force")
        # the graceful stop gave the flush window, so no escalation to process.kill()
        assert proc.kill.call_count == 0
        assert rc == 143

    @pytest.mark.unit
    @patch("phishkit._graceful_stop_container")
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_run_scanner_timeout_with_proxy_retries(self, mock_sync, mock_force_stop, mock_graceful, tmpdir):
        """Timeout with proxy + fallback enabled retries without proxy."""
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        direct_proc = self._make_mock_process(stdout="scan complete", stderr="", returncode=0)

        call_count = 0

        def popen_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                proc = MagicMock()
                proc.communicate.side_effect = [
                    TimeoutExpired(cmd="docker", timeout=10),
                    ("", ""),
                ]
                proc.kill = MagicMock()
                proc.wait = MagicMock()
                return proc
            return direct_proc

        with patch("phishkit.Popen", side_effect=popen_side_effect):
            stdout, stderr, rc = _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=10,
                proxy="http://proxy:8080",
                proxy_fallback_to_direct=True,
                config_path=config_path,
            )

        assert call_count == 2
        assert "PROXY ATTEMPT (timed out, retried direct)" in stdout
        assert "DIRECT ATTEMPT" in stdout
        assert rc == 0

        with open(os.path.join(output_dir, "proxy.json")) as f:
            proxy_status = json.load(f)
        assert proxy_status["configured"] is True
        assert proxy_status["host"] == "http://proxy:8080"
        assert proxy_status["fallback_enabled"] is True
        assert proxy_status["fallback_triggered"] is True
        assert proxy_status["fallback_reason"] == "timeout"
        assert proxy_status["final_route"] == "direct"

    @pytest.mark.unit
    @patch("phishkit._graceful_stop_container")
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_run_scanner_timeout_both_attempts_returns_partial(self, mock_sync, mock_force_stop, mock_graceful, tmpdir):
        """Proxy attempt times out AND the direct retry times out — still returns partial.

        The direct attempt's SIGTERM-flushed requests.json (written into
        {output_dir}-direct) is copied back into output_dir, so the redirect
        chain captured before the kill survives.
        """
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        call_count = 0

        def popen_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            proc = MagicMock()
            proc.communicate.side_effect = [
                TimeoutExpired(cmd="docker", timeout=10),
                ("partial direct stdout", ""),
            ]
            proc.returncode = 143
            proc.kill = MagicMock()
            proc.wait = MagicMock()
            # the direct attempt (2nd Popen) writes to {output_dir}-direct; mimic
            # the scanner's SIGTERM flush so the copy-back has something to move
            if call_count == 2:
                direct_dir = f"{output_dir}-direct"
                os.makedirs(direct_dir, exist_ok=True)
                with open(os.path.join(direct_dir, "requests.json"), "w") as f:
                    json.dump(
                        [{"type": "request", "url": "https://redirect.example.net/ns", "requestId": "1"}],
                        f,
                    )
            return proc

        with patch("phishkit.Popen", side_effect=popen_side_effect):
            stdout, stderr, rc = _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=10,
                proxy="http://proxy:8080",
                proxy_fallback_to_direct=True,
                config_path=config_path,
            )

        assert call_count == 2
        assert rc == 143
        # the direct attempt's partial requests.json was copied back into output_dir
        copied = os.path.join(output_dir, "requests.json")
        assert os.path.isfile(copied)
        with open(copied) as f:
            assert json.load(f)[0]["url"] == "https://redirect.example.net/ns"
        with open(os.path.join(output_dir, "proxy.json")) as f:
            proxy_status = json.load(f)
        assert proxy_status["fallback_triggered"] is True
        assert proxy_status["fallback_reason"] == "timeout"
        assert proxy_status["final_route"] == "direct"

    @pytest.mark.unit
    @patch("phishkit._graceful_stop_container")
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_run_scanner_timeout_retry_disabled_returns_partial(self, mock_sync, mock_force_stop, mock_graceful, tmpdir):
        """Timeout with retry_on_timeout=False returns partial results (no retry, no raise)."""
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir, {"proxy_fallback": {
            **FULL_PROXY_FALLBACK,
            "retry_on_timeout": False,
        }})
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = MagicMock()
        proc.communicate.side_effect = [
            TimeoutExpired(cmd="docker", timeout=10),
            ("", ""),
        ]
        proc.returncode = 143
        proc.kill = MagicMock()
        proc.wait = MagicMock()

        with patch("phishkit.Popen", return_value=proc) as mock_popen:
            stdout, stderr, rc = _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=10,
                proxy="http://proxy:8080",
                proxy_fallback_to_direct=True,
                config_path=config_path,
            )

        # retry disabled — only one attempt, no raise, partial output persisted
        assert mock_popen.call_count == 1
        assert rc == 143
        with open(os.path.join(output_dir, "proxy.json")) as f:
            proxy_status = json.load(f)
        assert proxy_status["fallback_triggered"] is False
        assert proxy_status["final_route"] == "proxy"

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_run_scanner_proxy_fallback(self, mock_sync, mock_force_stop, tmpdir):
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        # first call has proxy error, second succeeds
        proxy_proc = self._make_mock_process(
            stdout="ERR_TUNNEL_CONNECTION_FAILED", stderr="", returncode=1
        )
        direct_proc = self._make_mock_process(
            stdout="scan complete", stderr="", returncode=0
        )

        call_count = 0

        def popen_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return proxy_proc
            return direct_proc

        with patch("phishkit.Popen", side_effect=popen_side_effect):
            stdout, stderr, rc = _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=30,
                proxy="http://proxy:8080",
                proxy_fallback_to_direct=True,
                config_path=config_path,
            )

        assert call_count == 2
        assert "PROXY ATTEMPT (failed, retried direct)" in stdout
        assert "DIRECT ATTEMPT" in stdout
        assert rc == 0

        with open(os.path.join(output_dir, "proxy.json")) as f:
            proxy_status = json.load(f)
        assert proxy_status["fallback_triggered"] is True
        assert proxy_status["fallback_reason"] == "error_pattern"
        assert proxy_status["fallback_details"]["matched_error_patterns"] == [
            "ERR_TUNNEL_CONNECTION_FAILED",
        ]
        assert proxy_status["final_route"] == "direct"

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_run_scanner_proxy_status_code_fallback(self, mock_sync, mock_force_stop, tmpdir):
        """Proxy error status code in requests.json triggers retry."""
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        # write requests.json with a 502 main page response
        requests_data = [
            {"type": "request", "url": "https://example.com", "requestId": "1"},
            {"type": "response", "url": "https://example.com", "requestId": "1", "status_code": 502},
        ]
        with open(os.path.join(output_dir, "requests.json"), "w") as f:
            json.dump(requests_data, f)

        proxy_proc = self._make_mock_process(stdout="proxy page", stderr="", returncode=0)
        direct_proc = self._make_mock_process(stdout="scan complete", stderr="", returncode=0)

        call_count = 0

        def popen_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return proxy_proc
            return direct_proc

        with patch("phishkit.Popen", side_effect=popen_side_effect):
            stdout, stderr, rc = _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=30,
                proxy="http://proxy:8080",
                proxy_fallback_to_direct=True,
                config_path=config_path,
            )

        assert call_count == 2
        assert "PROXY ATTEMPT (failed, retried direct)" in stdout
        assert rc == 0

        with open(os.path.join(output_dir, "proxy.json")) as f:
            proxy_status = json.load(f)
        assert proxy_status["fallback_triggered"] is True
        assert proxy_status["fallback_reason"] == "status_code"
        assert proxy_status["fallback_details"]["matched_status_code"] == 502
        assert proxy_status["final_route"] == "direct"

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_run_scanner_proxy_no_fallback(self, mock_sync, mock_force_stop, tmpdir):
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = self._make_mock_process(
            stdout="ERR_TUNNEL_CONNECTION_FAILED", stderr="", returncode=1
        )

        with patch("phishkit.Popen", return_value=proc) as mock_popen:
            _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=30,
                proxy="http://proxy:8080",
                proxy_fallback_to_direct=False,
                config_path=config_path,
            )

        # should only be called once (no retry)
        assert mock_popen.call_count == 1

        # proxy was configured but fallback disabled — final_route stays "proxy"
        with open(os.path.join(output_dir, "proxy.json")) as f:
            proxy_status = json.load(f)
        assert proxy_status["configured"] is True
        assert proxy_status["fallback_enabled"] is False
        assert proxy_status["fallback_triggered"] is False
        assert proxy_status["fallback_reason"] is None
        assert proxy_status["final_route"] == "proxy"

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    def test_run_scanner_with_config(self, mock_force_stop, tmpdir):
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        # a real synced config file the finally-block should delete after the scan
        synced = str(tmpdir.join("synced_config.yaml"))
        with open(synced, "w") as f:
            f.write("test: true\n")

        proc = self._make_mock_process(stdout="ok", stderr="", returncode=0)

        with patch("phishkit._sync_config", return_value=synced), \
                patch("phishkit.Popen", return_value=proc) as mock_popen:
            _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=30,
                proxy=None,
                proxy_fallback_to_direct=False,
                config_path=config_path,
            )

        cmd = mock_popen.call_args[0][0]
        assert "--config" in cmd
        assert synced in cmd
        # the synced config is removed once the scan completes
        assert not os.path.exists(synced)

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    def test_run_scanner_deletes_config_on_timeout(self, mock_force_stop, tmpdir):
        """The synced config is removed even when the scan times out.

        A timeout now returns partial results instead of raising, but the outer
        finally must still clean up the synced config file.
        """
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        synced = str(tmpdir.join("synced_config.yaml"))
        with open(synced, "w") as f:
            f.write("test: true\n")

        proc = MagicMock()
        proc.communicate.side_effect = [
            TimeoutExpired(cmd="docker", timeout=10),
            ("", ""),
        ]
        proc.returncode = 143
        proc.kill = MagicMock()
        proc.wait = MagicMock()

        with patch("phishkit._sync_config", return_value=synced), \
                patch("phishkit.Popen", return_value=proc):
            _, _, rc = _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=10,
                proxy=None,
                proxy_fallback_to_direct=False,
                config_path=config_path,
            )

        assert rc == 143
        assert not os.path.exists(synced)

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_run_scanner_output_files_content(self, mock_sync, mock_force_stop, tmpdir):
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = self._make_mock_process(stdout="hello stdout", stderr="hello stderr", returncode=42)

        with patch("phishkit.Popen", return_value=proc):
            _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=30,
                proxy=None,
                proxy_fallback_to_direct=False,
                config_path=config_path,
            )

        with open(os.path.join(output_dir, "std.out")) as f:
            assert f.read() == "hello stdout"
        with open(os.path.join(output_dir, "std.err")) as f:
            assert f.read() == "hello stderr"
        with open(os.path.join(output_dir, "exit.code")) as f:
            assert f.read() == "42"


# ---------------------------------------------------------------------------
# _correct_file_extension
# ---------------------------------------------------------------------------

class TestCorrectFileExtension:

    @pytest.mark.unit
    def test_correct_file_extension_already_correct(self, tmpdir):
        from phishkit import _correct_file_extension

        file_path = str(tmpdir.join("page.html"))
        with open(file_path, "w") as f:
            f.write("<html></html>")

        with patch("phishkit.magic") as mock_magic:
            mock_magic.from_file.return_value = "text/html"
            result = _correct_file_extension(file_path)

        assert result == file_path

    @pytest.mark.unit
    def test_correct_file_extension_needs_correction(self, tmpdir):
        from phishkit import _correct_file_extension

        file_path = str(tmpdir.join("page.txt"))
        with open(file_path, "w") as f:
            f.write("<html></html>")

        with patch("phishkit.magic") as mock_magic:
            mock_magic.from_file.return_value = "text/html"
            result = _correct_file_extension(file_path)

        assert result.endswith(".html")
        assert not os.path.exists(file_path)

    @pytest.mark.unit
    def test_correct_file_extension_keeps_html_when_misdetected_as_text_plain(self, tmpdir):
        """Regression: an HTML email body that is a bare fragment is misdetected by libmagic
        as text/plain. _correct_file_extension must NOT downgrade the .html extension to .txt,
        otherwise the scanner navigates to a .txt file:// URL and the browser renders the raw
        HTML source instead of the page."""
        from phishkit import _correct_file_extension

        file_path = str(tmpdir.join("body.unknown_text_html_000.html"))
        with open(file_path, "w") as f:
            f.write('<div id="isPasted"><span>Hello</span></div>')

        with patch("phishkit.magic") as mock_magic:
            mock_magic.from_file.return_value = "text/plain"
            result = _correct_file_extension(file_path)

        # extension preserved, file not renamed
        assert result == file_path
        assert os.path.exists(file_path)

    @pytest.mark.unit
    def test_correct_file_extension_no_mime(self, tmpdir):
        from phishkit import _correct_file_extension

        file_path = str(tmpdir.join("mystery"))
        with open(file_path, "w") as f:
            f.write("data")

        with patch("phishkit.magic") as mock_magic:
            mock_magic.from_file.return_value = None
            result = _correct_file_extension(file_path)

        assert result == file_path

    @pytest.mark.unit
    def test_correct_file_extension_no_extension_guess(self, tmpdir):
        from phishkit import _correct_file_extension

        file_path = str(tmpdir.join("file.bin"))
        with open(file_path, "w") as f:
            f.write("data")

        with patch("phishkit.magic") as mock_magic, \
             patch("phishkit.mimetypes") as mock_mimetypes:
            mock_magic.from_file.return_value = "application/x-custom"
            mock_mimetypes.guess_extension.return_value = None
            result = _correct_file_extension(file_path)

        assert result == file_path


# ---------------------------------------------------------------------------
# Celery tasks: scan_url, scan_file
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Container resource-limit / reaper helpers
# ---------------------------------------------------------------------------

class TestBuildCmdArgs:

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_docker_run_includes_resource_limits_and_labels(self, mock_sync, mock_force_stop, tmpdir):
        """The docker run subprocess must include --memory, --init, --name, and labels."""
        from phishkit import _run_scanner

        config_data = {
            "proxy_fallback": FULL_PROXY_FALLBACK,
            "resource_limits": {
                "container_memory": "1g",
                "container_cpus": "1.5",
                "reaper_max_age_seconds": 600,
                "reaper_interval_seconds": 60,
                "scanner_timeout_hint": 15,
            },
        }
        config_file = tmpdir.join("phishkit_config.yaml")
        config_file.write(yaml.dump(config_data))

        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = MagicMock()
        proc.communicate.return_value = ("ok", "")
        proc.returncode = 0

        with patch("phishkit.Popen", return_value=proc) as mock_popen:
            _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="abc-123",
                timeout=30,
                proxy=None,
                proxy_fallback_to_direct=False,
                config_path=str(config_file),
            )

        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == "docker"
        assert "--init" in cmd
        assert "--rm" in cmd
        assert "--name" in cmd
        assert "phishkit-scan-abc-123" in cmd
        assert "--memory" in cmd
        # --memory and --memory-swap must both be 1g
        mem_idx = cmd.index("--memory")
        assert cmd[mem_idx + 1] == "1g"
        memswap_idx = cmd.index("--memory-swap")
        assert cmd[memswap_idx + 1] == "1g"
        assert "--cpus" in cmd
        assert cmd[cmd.index("--cpus") + 1] == "1.5"
        # label with job_id must be present
        label_vals = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--label"]
        assert any(lv == "phishkit.job_id=abc-123" for lv in label_vals)
        assert any(lv.startswith("phishkit.worker=") for lv in label_vals)
        assert any(lv.startswith("phishkit.started_at=") for lv in label_vals)


class TestForceStopContainer:

    @pytest.mark.unit
    def test_force_stop_runs_docker_kill_and_rm(self):
        from phishkit import _force_stop_container
        with patch("phishkit.subprocess.run") as mock_run:
            _force_stop_container("phishkit-scan-xyz")
        cmds = [call.args[0] for call in mock_run.call_args_list]
        assert ["docker", "kill", "phishkit-scan-xyz"] in cmds
        assert ["docker", "rm", "-f", "phishkit-scan-xyz"] in cmds

    @pytest.mark.unit
    def test_force_stop_swallows_exceptions(self):
        """Must not raise even if docker CLI is unavailable."""
        from phishkit import _force_stop_container
        with patch("phishkit.subprocess.run", side_effect=FileNotFoundError("no docker")):
            _force_stop_container("phishkit-scan-xyz")  # should not raise


class TestReapOrphans:

    def _mock_docker_ps(self, containers):
        """Build a fake `docker ps` stdout from a list of container dicts."""
        lines = [
            f"{c['id']}|{c['name']}|{c['started_at']}|{c['worker']}"
            for c in containers
        ]
        result = MagicMock()
        result.stdout = "\n".join(lines) + ("\n" if lines else "")
        return result

    @pytest.mark.unit
    def test_reap_orphans_kills_old_containers(self):
        import phishkit
        from phishkit import _reap_orphans

        old = {"id": "a", "name": "phishkit-scan-old", "started_at": 100, "worker": "h1"}
        young = {"id": "b", "name": "phishkit-scan-young", "started_at": 9_999_999_999, "worker": "h1"}

        with patch("phishkit.subprocess.run", return_value=self._mock_docker_ps([old, young])), \
             patch("phishkit._force_stop_container") as mock_force, \
             patch("phishkit.time.time", return_value=10_000):
            killed = _reap_orphans(max_age_seconds=60)

        assert killed == 1
        mock_force.assert_called_once_with("phishkit-scan-old")

    @pytest.mark.unit
    def test_reap_orphans_only_this_worker_filters(self):
        from phishkit import _reap_orphans
        this_host = __import__("socket").gethostname()

        mine = {"id": "a", "name": "phishkit-scan-mine", "started_at": 0, "worker": this_host}
        theirs = {"id": "b", "name": "phishkit-scan-theirs", "started_at": 0, "worker": "other-host"}

        with patch("phishkit.subprocess.run",
                   return_value=TestReapOrphans()._mock_docker_ps([mine, theirs])), \
             patch("phishkit._force_stop_container") as mock_force, \
             patch("phishkit.time.time", return_value=1_000_000):
            killed = _reap_orphans(max_age_seconds=0, only_this_worker=True)

        assert killed == 1
        mock_force.assert_called_once_with("phishkit-scan-mine")

    @pytest.mark.unit
    def test_reap_orphans_empty_ps(self):
        from phishkit import _reap_orphans
        result = MagicMock()
        result.stdout = ""
        with patch("phishkit.subprocess.run", return_value=result), \
             patch("phishkit._force_stop_container") as mock_force:
            killed = _reap_orphans(max_age_seconds=60)
        assert killed == 0
        mock_force.assert_not_called()


class TestInstanceIsolation:
    """Several ACE instances can share one docker daemon, so everything this worker does over
    the socket has to be scoped to its own instance."""

    @pytest.mark.unit
    def test_reaper_only_lists_its_own_instances_containers(self):
        """Without the stack filter, `docker ps` returns another instance's scanner containers
        and the reaper kills them -- including via the shutdown sweep, which cannot fall back to
        the worker hostname because docker-compose.yml pins `hostname: phishkit` everywhere."""
        import phishkit
        from phishkit import _list_phishkit_containers

        result = MagicMock()
        result.stdout = ""
        with patch("phishkit.subprocess.run", return_value=result) as mock_run:
            _list_phishkit_containers()

        argv = mock_run.call_args[0][0]
        assert f"label=phishkit.stack={phishkit.STACK}" in argv
        assert "label=phishkit.job_id" in argv

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_spawned_containers_carry_the_stack_label_and_volume(
        self, mock_sync, mock_force_stop, tmpdir
    ):
        """The reaper's stack filter only helps if the containers actually carry the label, and
        the scanner only sees its input if it mounts this instance's volume."""
        import phishkit
        from phishkit import _run_scanner

        config_data = {
            "proxy_fallback": FULL_PROXY_FALLBACK,
            "resource_limits": {
                "container_memory": "1g",
                "container_cpus": "1.5",
                "reaper_max_age_seconds": 600,
                "reaper_interval_seconds": 60,
                "scanner_timeout_hint": 15,
            },
        }
        config_file = tmpdir.join("phishkit_config.yaml")
        config_file.write(yaml.dump(config_data))

        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = MagicMock()
        proc.communicate.return_value = ("ok", "")
        proc.returncode = 0

        with patch("phishkit.Popen", return_value=proc) as mock_popen:
            _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="abc-123",
                timeout=30,
                proxy=None,
                proxy_fallback_to_direct=False,
                config_path=str(config_file),
            )

        cmd = mock_popen.call_args[0][0]
        label_vals = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--label"]
        assert f"phishkit.stack={phishkit.STACK}" in label_vals
        assert f"{phishkit.PHISHKIT_VOLUME}:/phishkit" in cmd

    @pytest.mark.unit
    def test_volume_name_is_read_from_the_environment(self):
        """Compose prefixes named volumes with the project name, so the shared volume is not a
        fixed string -- it is handed in as ACE_PHISHKIT_VOLUME."""
        import importlib
        import phishkit

        with patch.dict(os.environ, {"ACE_PHISHKIT_VOLUME": "ace2_phishkit"}):
            reloaded = importlib.reload(phishkit)
            try:
                assert reloaded.PHISHKIT_VOLUME == "ace2_phishkit"
            finally:
                importlib.reload(phishkit)

    @pytest.mark.unit
    def test_volume_name_defaults_to_the_legacy_name(self):
        import importlib
        import phishkit

        env = {k: v for k, v in os.environ.items() if k != "ACE_PHISHKIT_VOLUME"}
        with patch.dict(os.environ, env, clear=True):
            reloaded = importlib.reload(phishkit)
            try:
                assert reloaded.PHISHKIT_VOLUME == "ace-phishkit"
            finally:
                importlib.reload(phishkit)


class TestLoadResourceLimits:

    @pytest.mark.unit
    def test_load_resource_limits_uses_defaults_when_missing(self, tmpdir):
        from phishkit import _load_resource_limits, DEFAULT_RESOURCE_LIMITS
        cfg = _load_resource_limits(str(tmpdir.join("nonexistent.yaml")))
        assert cfg == DEFAULT_RESOURCE_LIMITS

    @pytest.mark.unit
    def test_load_resource_limits_merges_user_values(self, tmpdir):
        from phishkit import _load_resource_limits, DEFAULT_RESOURCE_LIMITS
        path = tmpdir.join("c.yaml")
        path.write(yaml.dump({"resource_limits": {"container_memory": "4g"}}))
        cfg = _load_resource_limits(str(path))
        assert cfg["container_memory"] == "4g"
        assert cfg["container_cpus"] == DEFAULT_RESOURCE_LIMITS["container_cpus"]

    @pytest.mark.unit
    def test_load_resource_limits_ignores_unknown_keys(self, tmpdir):
        from phishkit import _load_resource_limits
        path = tmpdir.join("c.yaml")
        path.write(yaml.dump({"resource_limits": {"bogus": "drop"}}))
        cfg = _load_resource_limits(str(path))
        assert "bogus" not in cfg


class TestScanUrl:

    @pytest.mark.unit
    @patch("phishkit._process_output", return_value="/phishkit/output/job-1")
    @patch("phishkit._run_scanner", return_value=("ok", "", 0))
    @patch("phishkit.os.makedirs")
    @patch("phishkit.uuid.uuid4", return_value="job-1")
    def test_scan_url_success(self, mock_uuid, mock_makedirs, mock_run, mock_process):
        from phishkit import scan_url

        result = scan_url("https://example.com", timeout=15)
        mock_run.assert_called_once()
        assert result == "/phishkit/output/job-1"

    @pytest.mark.unit
    @patch("phishkit._run_scanner", return_value=("", "error occurred", 1))
    @patch("phishkit.os.makedirs")
    @patch("phishkit.uuid.uuid4", return_value="job-1")
    def test_scan_url_nonzero_exit(self, mock_uuid, mock_makedirs, mock_run):
        from phishkit import scan_url

        with pytest.raises(Exception, match="scan failed"):
            scan_url("https://example.com", timeout=15)


class TestScanFile:

    @pytest.mark.unit
    @patch("phishkit._process_output", return_value="/phishkit/output/job-1")
    @patch("phishkit._run_scanner", return_value=("ok", "", 0))
    @patch("phishkit._correct_file_extension", side_effect=lambda p: p)
    @patch("phishkit.shutil.copy2")
    @patch("phishkit.os.makedirs")
    @patch("phishkit.uuid.uuid4", return_value="job-1")
    def test_scan_file_success(self, mock_uuid, mock_makedirs, mock_copy,
                               mock_correct, mock_run, mock_process):
        from phishkit import scan_file

        result = scan_file("/some/path/malware.html", timeout=15)
        mock_run.assert_called_once()
        # verify --file is in the target_args
        run_call = mock_run.call_args
        assert "--file" in run_call.kwargs["target_args"]
        assert result == "/phishkit/output/job-1"


# ---------------------------------------------------------------------------
# maintain_files / _delete_aged_dirs
# ---------------------------------------------------------------------------


class TestDeleteAgedDirs:

    @pytest.mark.unit
    def test_removes_only_aged_dirs(self, tmp_path):
        import time
        from phishkit import _delete_aged_dirs

        old_dir = tmp_path / "old-job"
        new_dir = tmp_path / "new-job"
        old_dir.mkdir()
        new_dir.mkdir()
        (old_dir / "result.json").write_text("{}")

        now = time.time()
        # backdate old_dir to 10 days ago
        os.utime(old_dir, (now - 10 * 86400, now - 10 * 86400))

        # cutoff is 3 days ago
        removed = _delete_aged_dirs(str(tmp_path), now - 3 * 86400)

        assert removed == [str(old_dir)]
        assert not old_dir.exists()
        assert new_dir.exists()

    @pytest.mark.unit
    def test_ignores_files_in_directory(self, tmp_path):
        import time
        from phishkit import _delete_aged_dirs

        loose_file = tmp_path / "loose.txt"
        loose_file.write_text("data")
        os.utime(loose_file, (0, 0))

        removed = _delete_aged_dirs(str(tmp_path), time.time())

        assert removed == []
        assert loose_file.exists()

    @pytest.mark.unit
    def test_missing_directory_returns_empty(self):
        import time
        from phishkit import _delete_aged_dirs

        assert _delete_aged_dirs("/phishkit/does-not-exist", time.time()) == []


class TestMaintainFiles:

    @pytest.mark.unit
    def test_maintain_files_sweeps_data_dirs(self, tmp_path):
        import time
        import phishkit as phishkit_mod
        from phishkit import maintain_files

        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        old_job = input_dir / "old-job"
        new_job = output_dir / "new-job"
        old_job.mkdir()
        new_job.mkdir()

        now = time.time()
        os.utime(old_job, (now - 10 * 86400, now - 10 * 86400))

        with patch.object(phishkit_mod, "PHISHKIT_DATA_DIRS",
                           (str(input_dir), str(output_dir))):
            result = maintain_files(3)

        assert result[str(input_dir)] == [str(old_job)]
        assert result[str(output_dir)] == []
        assert not old_job.exists()
        assert new_job.exists()


# ---------------------------------------------------------------------------
# _has_recoverable_output
# ---------------------------------------------------------------------------

class TestHasRecoverableOutput:

    @pytest.mark.unit
    @pytest.mark.parametrize("filename", ["requests.json", "dom.html"])
    def test_recoverable_when_partial_artifact_present(self, tmp_path, filename):
        from phishkit import _has_recoverable_output

        (tmp_path / filename).write_text("partial")
        assert _has_recoverable_output(str(tmp_path)) is True

    @pytest.mark.unit
    def test_not_recoverable_when_empty(self, tmp_path):
        from phishkit import _has_recoverable_output

        assert _has_recoverable_output(str(tmp_path)) is False

    @pytest.mark.unit
    def test_not_recoverable_when_only_metadata(self, tmp_path):
        from phishkit import _has_recoverable_output

        # std.out / exit.code alone are not captured traffic worth returning
        (tmp_path / "std.out").write_text("")
        (tmp_path / "exit.code").write_text("143")
        assert _has_recoverable_output(str(tmp_path)) is False


# ---------------------------------------------------------------------------
# scan_url — return-vs-raise on non-zero exit
# ---------------------------------------------------------------------------

class TestScanUrlPartial:

    @pytest.mark.unit
    def test_returns_dir_when_partial_output_present(self):
        """A non-zero exit with recoverable artifacts returns the dir, not raises."""
        import phishkit as phishkit_mod

        with patch.object(phishkit_mod.os, "makedirs"), \
             patch.object(phishkit_mod, "_run_scanner", return_value=("", "killed", 143)), \
             patch.object(phishkit_mod, "_has_recoverable_output", return_value=True), \
             patch.object(phishkit_mod, "_process_output", side_effect=lambda job_id, out: out):
            result = phishkit_mod.scan_url.run(
                "https://example.com", timeout=10, config_path="etc/phishkit_config.yaml"
            )

        assert result.startswith("/phishkit/output/")

    @pytest.mark.unit
    def test_raises_when_nonzero_and_no_partial_output(self):
        """A non-zero exit with an empty output dir is a hard failure — raise."""
        import phishkit as phishkit_mod

        with patch.object(phishkit_mod.os, "makedirs"), \
             patch.object(phishkit_mod, "_run_scanner", return_value=("", "boom", 1)), \
             patch.object(phishkit_mod, "_has_recoverable_output", return_value=False):
            with pytest.raises(Exception, match="scan failed"):
                phishkit_mod.scan_url.run(
                    "https://example.com", timeout=10, config_path="etc/phishkit_config.yaml"
                )


# ---------------------------------------------------------------------------
# scanner_image_id task + worker-side freeze (ACE analysis cache key support).
# The id is resolved once at startup and frozen for the worker lifetime, so
# `docker inspect` stays entirely off the per-call path (the scanner image only
# changes on a rebuild, which here coincides with a manager restart). Frozen only
# on the first *successful* probe. See docs/ANALYSIS_CACHING.md (phishkit opt-in).
# ---------------------------------------------------------------------------

class TestScannerImageId:

    @staticmethod
    def _inspect_result(image_id):
        result = MagicMock()
        result.stdout = image_id + "\n"
        return result

    @pytest.mark.unit
    def test_scanner_image_id_task_returns_parsed_id(self):
        import phishkit as phishkit_mod
        phishkit_mod._reset_scanner_image_cache_for_tests()
        try:
            with patch.object(phishkit_mod.subprocess, "run",
                              return_value=self._inspect_result("sha256:aaa")):
                result = phishkit_mod.scanner_image_id.run()
            assert result["image_id"] == "sha256:aaa"
            assert result["image_url"]  # defaults to "phishkit"
        finally:
            phishkit_mod._reset_scanner_image_cache_for_tests()

    @pytest.mark.unit
    def test_docker_inspect_runs_once_after_first_success(self):
        """the core guarantee: once resolved, repeated calls return the frozen id
        without ever re-shelling docker inspect."""
        import phishkit as phishkit_mod
        phishkit_mod._reset_scanner_image_cache_for_tests()
        try:
            with patch.object(phishkit_mod.subprocess, "run",
                              return_value=self._inspect_result("sha256:aaa")) as mock_run:
                first = phishkit_mod.get_scanner_image_id()
                second = phishkit_mod.get_scanner_image_id()
            assert first == second
            assert first["image_id"] == "sha256:aaa"
            assert mock_run.call_count == 1  # frozen after the first success
        finally:
            phishkit_mod._reset_scanner_image_cache_for_tests()

    @pytest.mark.unit
    def test_first_probe_failure_does_not_freeze_then_freezes_on_success(self):
        """a failed first probe (e.g. docker not ready at boot) must NOT freeze:
        the next call re-probes, and once it succeeds the id freezes."""
        import phishkit as phishkit_mod
        phishkit_mod._reset_scanner_image_cache_for_tests()
        try:
            with patch.object(phishkit_mod.subprocess, "run",
                              side_effect=FileNotFoundError("docker not ready")):
                assert phishkit_mod.get_scanner_image_id()["image_id"] is None
            # docker comes up: the next call re-probes and resolves the id
            with patch.object(phishkit_mod.subprocess, "run",
                              return_value=self._inspect_result("sha256:ready")) as mock_run:
                assert phishkit_mod.get_scanner_image_id()["image_id"] == "sha256:ready"
                # now frozen: a further call does not re-probe
                assert phishkit_mod.get_scanner_image_id()["image_id"] == "sha256:ready"
                assert mock_run.call_count == 1
        finally:
            phishkit_mod._reset_scanner_image_cache_for_tests()

    @pytest.mark.unit
    def test_inspect_failure_degrades_to_none_without_raising(self):
        """with no resolved value, a docker inspect failure returns image_id=None
        and never raises (the cache key degrades to config-hash-only)."""
        import phishkit as phishkit_mod
        phishkit_mod._reset_scanner_image_cache_for_tests()
        try:
            with patch.object(phishkit_mod.subprocess, "run",
                              side_effect=RuntimeError("docker down")):
                result = phishkit_mod.get_scanner_image_id()
            assert result["image_id"] is None  # degraded, not raised
            assert result["image_url"]
        finally:
            phishkit_mod._reset_scanner_image_cache_for_tests()
