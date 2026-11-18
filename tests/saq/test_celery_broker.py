"""The phishkit and js-deobfuscator managers and ACE's clients for them send to one broker (#1100).

The clients send through the managers' own modules, so both sides agree as long as the modules build
their app from what compose gives the manager containers and ACE's containers alike."""

import copy
import os
import subprocess
import sys

import pytest
import yaml
from pydantic import ValidationError

from saq.configuration.config import get_config
from saq.configuration.schema import ACEConfig
from saq.environment import get_base_dir

MANAGER_MODULES = ["phishkit.phishkit", "js_deobfuscator.js_deobfuscator"]
RABBITMQ_VARIABLES = ["ACE_RABBITMQ_HOST", "ACE_RABBITMQ_PORT", "ACE_RABBITMQ_USER"]


def _broker_url(module: str, environment: dict[str, str]) -> str:
    # the app is built when the module is imported, so each environment gets a fresh interpreter
    env = {key: value for key, value in os.environ.items() if key not in RABBITMQ_VARIABLES}
    env.update(environment)
    code = f"import {module} as manager\nprint(manager.app.conf.broker_url)\n"
    result = subprocess.run([sys.executable, "-c", code], cwd=get_base_dir(), env=env, capture_output=True,
                            text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _without_password(url: str) -> str:
    scheme, _, rest = url.partition("://")
    credentials, _, location = rest.partition("@")
    user, _, _ = credentials.partition(":")
    return f"{scheme}://{user}@{location}"


@pytest.mark.unit
@pytest.mark.parametrize("module", MANAGER_MODULES)
def test_a_manager_builds_its_broker_from_the_environment(module):
    url = _broker_url(module, {"ACE_RABBITMQ_HOST": "mq.example.com", "ACE_RABBITMQ_PORT": "5671",
                               "ACE_RABBITMQ_USER": "celery-user"})

    assert _without_password(url) == "pyamqp://celery-user@mq.example.com:5671//"


@pytest.mark.unit
@pytest.mark.parametrize("module", MANAGER_MODULES)
def test_without_the_environment_a_manager_uses_the_stacks_rabbitmq(module):
    assert _without_password(_broker_url(module, {})) == "pyamqp://ace3@rabbitmq:5672//"


@pytest.mark.unit
@pytest.mark.parametrize("module", MANAGER_MODULES)
def test_a_manager_logs_the_broker_it_uses_without_the_password(module):
    # ACE's clients import the module on first use, so every ACE process and each manager says where it sends
    env = {key: value for key, value in os.environ.items() if key not in RABBITMQ_VARIABLES}
    env.update({"ACE_RABBITMQ_HOST": "mq.example.com", "ACE_RABBITMQ_PORT": "5671", "ACE_RABBITMQ_USER": "celery-user"})
    code = ("import logging\nlogging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')\n"
            f"import {module} as manager\nprint(manager.rabbitmq_password)\n")
    result = subprocess.run([sys.executable, "-c", code], cwd=get_base_dir(), env=env, capture_output=True,
                            text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    password = result.stdout.strip()

    (record,) = [line for line in result.stderr.splitlines() if "celery broker" in line]
    assert record.startswith("INFO ") and "pyamqp://celery-user:**@mq.example.com:5671//" in record
    assert not password or password not in record


def _compose() -> dict:
    with open(os.path.join(get_base_dir(), "docker-compose.yml")) as fp:
        return yaml.safe_load(fp)


@pytest.mark.unit
def test_compose_gives_the_managers_and_every_ace_container_the_same_broker():
    services = _compose()["services"]
    # every ACE container gets the common environment, which is the one with SAQ_ENC in it
    ace_services = [name for name, service in services.items()
                    if isinstance(service.get("environment"), dict) and "SAQ_ENC" in service["environment"]]
    assert "ace" in ace_services and "dev" in ace_services

    def broker(name):
        environment = services[name]["environment"]
        return {variable: environment.get(variable) for variable in RABBITMQ_VARIABLES}

    expected = broker("phishkit")
    assert all(expected.values())
    for name in ["js-deobfuscator", *ace_services]:
        assert broker(name) == expected, name
    # the stack's own rabbitmq creates the user the others connect as
    assert services["rabbitmq"]["environment"]["RABBITMQ_DEFAULT_USER"] == expected["ACE_RABBITMQ_USER"]


@pytest.mark.unit
def test_a_rabbitmq_block_fails_instead_of_moving_only_ace():
    data = copy.deepcopy(get_config().raw._data)
    data["rabbitmq"] = {"username": "ace3", "password": "x", "host": "elsewhere", "port": 5672}

    with pytest.raises(ValidationError, match="rabbitmq: was removed.*ACE_RABBITMQ_HOST"):
        ACEConfig.model_validate(data)
