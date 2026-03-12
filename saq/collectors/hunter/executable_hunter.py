# vim: sw=4:ts=4:et:cc=120
#
# ACE Hunting System - executable based hunting
#

import json
import logging
import os
import subprocess
from typing import Optional

from pydantic import Field

from saq.collectors.hunter.base_hunter import Hunt, HuntConfig
from saq.collectors.hunter.loader import load_from_yaml
from saq.collectors.hunter.result_processing import ResultProcessingMixin
from saq.observables.mapping import ObservableMapping
from saq.query.config import BaseQueryConfig
from saq.util import create_timedelta


class ExecutableHuntConfig(HuntConfig, BaseQueryConfig):
    program: str = Field(..., description="The path to the program or script to execute.")
    arguments: list[str] = Field(default_factory=list, description="Command-line arguments to pass to the program.")
    environment: dict[str, str] = Field(default_factory=dict, description="Additional environment variables to set for the program.")
    timeout: Optional[str] = Field(default=None, description="Execution timeout in HH:MM:SS format.")
    group_by: Optional[str] = Field(default=None, description="The field to group the results by.")
    description_field: Optional[str] = Field(default=None, description="The event field to use for the alert description suffix.")
    dedup_key: Optional[str] = Field(default=None, description="Optional interpolation template for deduplication.")


class ExecutableHunt(Hunt, ResultProcessingMixin):
    """A hunt that executes a local program and parses JSONL output from stdout."""

    config: ExecutableHuntConfig

    @property
    def group_by(self) -> Optional[str]:
        return self.config.group_by

    @property
    def description_field(self) -> Optional[str]:
        return self.config.description_field

    @property
    def dedup_key(self) -> Optional[str]:
        return self.config.dedup_key

    @property
    def observable_mapping(self) -> list[ObservableMapping]:
        return self.config.observable_mapping

    @property
    def program(self) -> str:
        return self.config.program

    @property
    def arguments(self) -> list[str]:
        return self.config.arguments

    @property
    def environment(self) -> dict[str, str]:
        return self.config.environment

    @property
    def timeout(self) -> Optional[float]:
        if self.config.timeout:
            return create_timedelta(self.config.timeout).total_seconds()
        return None

    def load_hunt_config(self, path: str) -> tuple[ExecutableHuntConfig, set[str]]:
        return load_from_yaml(path, ExecutableHuntConfig)

    def execute(self, *args, **kwargs):
        env = os.environ.copy()
        env.update(self.environment)

        cmd = [self.program] + self.arguments
        logging.info("executing program hunt %s: %s", self.name, " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
            )
        except subprocess.TimeoutExpired:
            logging.error("program hunt %s timed out after %s seconds", self.name, self.timeout)
            return None
        except Exception as e:
            logging.error("program hunt %s failed to execute: %s", self.name, e)
            return None

        if result.stderr:
            for line in result.stderr.strip().splitlines():
                logging.warning("program hunt %s stderr: %s", self.name, line)

        if result.returncode != 0:
            logging.error("program hunt %s exited with code %s", self.name, result.returncode)
            return None

        results = []
        for line_number, line in enumerate(result.stdout.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError as e:
                logging.warning("program hunt %s: invalid JSON on line %s: %s", self.name, line_number, e)

        logging.info("program hunt %s produced %s results", self.name, len(results))
        return self.process_query_results(results, **kwargs)
