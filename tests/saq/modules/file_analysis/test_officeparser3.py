import logging
import os
import shutil
import signal
import time
import uuid

import psutil
import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import DIRECTIVE_SANDBOX, AnalysisExecutionResult
from saq.environment import get_data_dir
from saq.modules.file_analysis.file_type import FileTypeAnalysis
from saq.modules.file_analysis.officeparser3 import OfficeParserAnalysis3, OfficeParserAnalyzer3
from tests.saq.test_util import create_test_context

OLE_HEADER = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"


@pytest.fixture
def hanging_officeparser():
    """An officeparser that never finishes, recording its pid. It lives under the data directory
    because /tmp is mounted noexec."""
    tool_dir = os.path.join(get_data_dir(), f"hanging-officeparser-{uuid.uuid4()}")
    os.makedirs(tool_dir)
    pid_file = os.path.join(tool_dir, "pid")
    tool_path = os.path.join(tool_dir, "officeparser")
    with open(tool_path, "w") as fp:
        fp.write(f"#!/bin/sh\necho $$ > {pid_file}\nexec sleep 60\n")
    os.chmod(tool_path, 0o755)

    pids = []

    def _pid() -> int:
        with open(pid_file) as fp:
            pids.append(int(fp.read()))
        return pids[-1]

    yield tool_path, _pid

    # what a failing run left behind
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # killed and reaped, as it should be

    shutil.rmtree(tool_dir, ignore_errors=True)


@pytest.mark.integration
def test_officeparser_that_times_out_is_killed(root_analysis, hanging_officeparser, monkeypatch, caplog):
    tool_path, pid = hanging_officeparser
    analyzer = OfficeParserAnalyzer3(
        context=create_test_context(root=root_analysis),
        config=get_analysis_module_config("officeparser3"))
    monkeypatch.setattr(analyzer.config, "officeparser_path", tool_path)
    monkeypatch.setattr(analyzer.config, "timeout", 1)

    file_path = root_analysis.create_file_path("macro.doc")
    with open(file_path, "wb") as fp:
        fp.write(OLE_HEADER + b"\x00" * 504)
    observable = root_analysis.add_file_observable(file_path)
    observable.add_analysis(FileTypeAnalysis())

    started = time.monotonic()
    with caplog.at_level(logging.WARNING):
        assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    # it used to wait out the whole sleep (or the worker's analysis time limit)
    assert time.monotonic() - started < 30
    assert not psutil.pid_exists(pid())
    assert observable.has_tag("officeparser_failed")
    assert observable.has_directive(DIRECTIVE_SANDBOX)
    assert observable.get_analysis(OfficeParserAnalysis3) is None
    assert any(r.getMessage().startswith("timeout expired for officeparser") for r in caplog.records)
