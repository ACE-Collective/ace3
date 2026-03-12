import json
import logging
import os
import subprocess
from unittest.mock import patch

import pytest

from saq.collectors.hunter.executable_hunter import (
    ExecutableHunt,
    ExecutableHuntConfig,
)
from saq.collectors.hunter.result_processing import QUERY_DETAILS_EVENTS
from saq.constants import F_IPV4, F_HOSTNAME
from saq.observables.mapping import ObservableMapping


def make_hunt(
    uuid="d1e2f3a4-b5c6-7890-1234-567890abcdef",
    name="test_executable_hunt",
    type="executable",
    enabled=True,
    description="Test Executable Hunt",
    alert_type="test - executable",
    frequency="00:10",
    tags=None,
    instance_types=None,
    program="/bin/echo",
    arguments=None,
    environment=None,
    timeout=None,
    group_by=None,
    description_field=None,
    dedup_key=None,
    observable_mapping=None,
    **kwargs,
):
    if tags is None:
        tags = ["test_tag"]
    if instance_types is None:
        instance_types = ["unittest"]
    if arguments is None:
        arguments = []
    if environment is None:
        environment = {}
    if observable_mapping is None:
        observable_mapping = []

    config = ExecutableHuntConfig(
        uuid=uuid,
        name=name,
        type=type,
        enabled=enabled,
        description=description,
        alert_type=alert_type,
        frequency=frequency,
        tags=tags,
        instance_types=instance_types,
        program=program,
        arguments=arguments,
        environment=environment,
        timeout=timeout,
        group_by=group_by,
        description_field=description_field,
        dedup_key=dedup_key,
        observable_mapping=observable_mapping,
        **kwargs,
    )

    return ExecutableHunt(config=config)


def make_completed_process(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(
        args=["test"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


@pytest.mark.unit
class TestExecutableHuntConfig:
    def test_basic_config(self):
        config = ExecutableHuntConfig(
            uuid="test-uuid",
            name="test",
            type="executable",
            enabled=True,
            description="test desc",
            alert_type="test",
            frequency="00:10",
            program="/usr/bin/test_script.sh",
        )
        assert config.program == "/usr/bin/test_script.sh"
        assert config.arguments == []
        assert config.environment == {}
        assert config.timeout is None
        assert config.group_by is None

    def test_config_with_all_fields(self):
        config = ExecutableHuntConfig(
            uuid="test-uuid",
            name="test",
            type="executable",
            enabled=True,
            description="test desc",
            alert_type="test",
            frequency="00:10",
            program="/usr/bin/test_script.sh",
            arguments=["--flag", "value"],
            environment={"KEY": "VALUE"},
            timeout="00:05:00",
            group_by="hostname",
            description_field="desc_field",
            dedup_key="${hostname}",
        )
        assert config.arguments == ["--flag", "value"]
        assert config.environment == {"KEY": "VALUE"}
        assert config.timeout == "00:05:00"
        assert config.group_by == "hostname"
        assert config.description_field == "desc_field"
        assert config.dedup_key == "${hostname}"


@pytest.mark.unit
class TestExecutableHuntProperties:
    def test_program_property(self):
        hunt = make_hunt(program="/usr/bin/my_script")
        assert hunt.program == "/usr/bin/my_script"

    def test_arguments_property(self):
        hunt = make_hunt(arguments=["--verbose", "--output", "json"])
        assert hunt.arguments == ["--verbose", "--output", "json"]

    def test_environment_property(self):
        hunt = make_hunt(environment={"API_KEY": "secret123"})
        assert hunt.environment == {"API_KEY": "secret123"}

    def test_timeout_property(self):
        hunt = make_hunt(timeout="00:05:00")
        assert hunt.timeout == 300.0

    def test_timeout_none(self):
        hunt = make_hunt(timeout=None)
        assert hunt.timeout is None

    def test_group_by_property(self):
        hunt = make_hunt(group_by="hostname")
        assert hunt.group_by == "hostname"

    def test_observable_mapping_property(self):
        mapping = [ObservableMapping(fields=["src_ip"], type=F_IPV4)]
        hunt = make_hunt(observable_mapping=mapping)
        assert hunt.observable_mapping == mapping


@pytest.mark.unit
class TestExecutableHuntExecution:
    @patch("saq.collectors.hunter.executable_hunter.subprocess.run")
    def test_basic_jsonl_parsing(self, mock_run):
        events = [
            {"src_ip": "10.0.0.1", "hostname": "ws-1"},
            {"src_ip": "10.0.0.2", "hostname": "ws-2"},
        ]
        stdout = "\n".join(json.dumps(e) for e in events)
        mock_run.return_value = make_completed_process(stdout=stdout)

        mapping = [ObservableMapping(fields=["src_ip"], type=F_IPV4)]
        hunt = make_hunt(observable_mapping=mapping)
        result = hunt.execute()

        assert result is not None
        assert len(result) == 2
        assert mock_run.called

    @patch("saq.collectors.hunter.executable_hunter.subprocess.run")
    def test_empty_output(self, mock_run):
        mock_run.return_value = make_completed_process(stdout="")

        hunt = make_hunt()
        result = hunt.execute()

        assert result is not None
        assert len(result) == 0

    @patch("saq.collectors.hunter.executable_hunter.subprocess.run")
    def test_non_zero_exit_code(self, mock_run):
        mock_run.return_value = make_completed_process(returncode=1, stderr="something went wrong")

        hunt = make_hunt()
        result = hunt.execute()

        assert result is None

    @patch("saq.collectors.hunter.executable_hunter.subprocess.run")
    def test_timeout_handling(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["test"], timeout=300)

        hunt = make_hunt(timeout="00:05:00")
        result = hunt.execute()

        assert result is None

    @patch("saq.collectors.hunter.executable_hunter.subprocess.run")
    def test_execution_exception(self, mock_run):
        mock_run.side_effect = OSError("command not found")

        hunt = make_hunt(program="/nonexistent/program")
        result = hunt.execute()

        assert result is None

    @patch("saq.collectors.hunter.executable_hunter.subprocess.run")
    def test_stderr_logged_as_warning(self, mock_run, caplog):
        mock_run.return_value = make_completed_process(
            stdout='{"key": "value"}\n',
            stderr="this is a warning message",
        )

        hunt = make_hunt()
        with caplog.at_level(logging.WARNING):
            hunt.execute()

        assert "this is a warning message" in caplog.text

    @patch("saq.collectors.hunter.executable_hunter.subprocess.run")
    def test_invalid_json_lines_skipped(self, mock_run, caplog):
        stdout = '{"valid": "json"}\nnot valid json\n{"also": "valid"}\n'
        mock_run.return_value = make_completed_process(stdout=stdout)

        hunt = make_hunt()
        with caplog.at_level(logging.WARNING):
            result = hunt.execute()

        assert result is not None
        # 2 valid JSON lines become 2 submissions (no observable mapping, no grouping)
        assert len(result) == 2
        assert "invalid JSON on line 2" in caplog.text

    @patch("saq.collectors.hunter.executable_hunter.subprocess.run")
    def test_blank_lines_skipped(self, mock_run):
        stdout = '{"key": "value"}\n\n\n{"key2": "value2"}\n'
        mock_run.return_value = make_completed_process(stdout=stdout)

        hunt = make_hunt()
        result = hunt.execute()

        assert result is not None
        assert len(result) == 2

    @patch("saq.collectors.hunter.executable_hunter.subprocess.run")
    def test_environment_variables_passed(self, mock_run):
        mock_run.return_value = make_completed_process(stdout="")

        hunt = make_hunt(environment={"CUSTOM_VAR": "custom_value"})
        hunt.execute()

        call_kwargs = mock_run.call_args
        passed_env = call_kwargs.kwargs.get("env") or call_kwargs[1].get("env")
        assert passed_env["CUSTOM_VAR"] == "custom_value"
        # should also have inherited env vars
        assert "PATH" in passed_env

    @patch("saq.collectors.hunter.executable_hunter.subprocess.run")
    def test_arguments_passed(self, mock_run):
        mock_run.return_value = make_completed_process(stdout="")

        hunt = make_hunt(program="/usr/bin/script", arguments=["--flag", "value"])
        hunt.execute()

        call_args = mock_run.call_args
        cmd = call_args[0][0] if call_args[0] else call_args.kwargs.get("args") or call_args[1].get("args")
        assert cmd == ["/usr/bin/script", "--flag", "value"]

    @patch("saq.collectors.hunter.executable_hunter.subprocess.run")
    def test_timeout_passed_to_subprocess(self, mock_run):
        mock_run.return_value = make_completed_process(stdout="")

        hunt = make_hunt(timeout="00:05:00")
        hunt.execute()

        call_kwargs = mock_run.call_args
        passed_timeout = call_kwargs.kwargs.get("timeout") or call_kwargs[1].get("timeout")
        assert passed_timeout == 300.0


@pytest.mark.unit
class TestExecutableHuntResultProcessing:
    @patch("saq.collectors.hunter.executable_hunter.subprocess.run")
    def test_observable_mapping(self, mock_run):
        events = [
            {"src_ip": "10.0.0.1", "hostname": "ws-1"},
        ]
        stdout = "\n".join(json.dumps(e) for e in events)
        mock_run.return_value = make_completed_process(stdout=stdout)

        mapping = [
            ObservableMapping(fields=["src_ip"], type=F_IPV4),
            ObservableMapping(fields=["hostname"], type=F_HOSTNAME),
        ]
        hunt = make_hunt(observable_mapping=mapping)
        result = hunt.execute()

        assert result is not None
        assert len(result) == 1
        obs_types = {o.type for o in result[0].root.observables}
        assert F_IPV4 in obs_types
        assert F_HOSTNAME in obs_types

    @patch("saq.collectors.hunter.executable_hunter.subprocess.run")
    def test_group_by(self, mock_run):
        events = [
            {"src_ip": "10.0.0.1", "hostname": "ws-1"},
            {"src_ip": "10.0.0.2", "hostname": "ws-1"},
            {"src_ip": "10.0.0.3", "hostname": "ws-2"},
        ]
        stdout = "\n".join(json.dumps(e) for e in events)
        mock_run.return_value = make_completed_process(stdout=stdout)

        mapping = [ObservableMapping(fields=["src_ip"], type=F_IPV4)]
        hunt = make_hunt(observable_mapping=mapping, group_by="hostname")
        result = hunt.execute()

        assert result is not None
        assert len(result) == 2

        # find the group with hostname ws-1
        for submission in result:
            if "ws-1" in submission.root.description:
                assert len(submission.root.details[QUERY_DETAILS_EVENTS]) == 2
                break
        else:
            pytest.fail("did not find ws-1 group")

    @patch("saq.collectors.hunter.executable_hunter.subprocess.run")
    def test_events_stored_in_details(self, mock_run):
        events = [{"src_ip": "10.0.0.1"}]
        stdout = json.dumps(events[0])
        mock_run.return_value = make_completed_process(stdout=stdout)

        hunt = make_hunt()
        result = hunt.execute()

        assert result is not None
        assert len(result) == 1
        assert result[0].root.details[QUERY_DETAILS_EVENTS] == events


@pytest.mark.unit
class TestExecutableHuntLoadConfig:
    def test_load_from_yaml(self):
        hunt = ExecutableHunt(hunt_config_file_path="hunts/test/executable/test_1.yaml")
        assert hunt.name == "executable_test_1"
        assert hunt.config.program == "hunts/test/executable/test_script.sh"
        assert hunt.type == "executable"
        assert hunt.alert_type == "hunter - executable - test"
