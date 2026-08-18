"""Boot-time custody assertions for the AI investigation API container.

The container's security property is that the process the AI key talks to holds nothing valuable
to the rest of ACE: no encryption capability (so the encrypted secrets table is unreadable even
under full compromise), no GUI/node credentials, and no plaintext secret beyond the read-only
vendor credentials its own backends declare. These checks make that property enforced rather than
reviewed: the app refuses to boot when any of them fails.

Called from the api_ai_uvicorn entrypoint ONLY -- never from create_app() -- because the unit-test
environment legitimately runs with SAQ_ENC set and must still be able to build the app. Tests
exercise these checks by calling them directly.
"""

import logging
import os
import re

from pydantic import BaseModel

from saq.ai_query.registry import build_backend_registry
from saq.configuration.config import INTEGRATION_CONFIGURATIONS, get_config
from saq.configuration.secret_ref import SecretRef
from saq.environment import get_global_runtime_settings

# the value etc/saq.ai.yaml assigns to infrastructure secrets this process must not hold
AI_UNUSED_SENTINEL = "ai-container-unused"

# config paths whose infrastructure secret this container legitimately needs
ADVISORY_SWEEP_EXCLUSIONS = {
    "redis.password",       # the rate limiter's shared state
    "redis_local.password",
}

SECRETISH_FIELD_NAME = re.compile(r"(password|token|secret|secret_key|api_key)$")


def _walk_model(model: BaseModel, path_prefix: str, visit) -> None:
    """Depth-first visit(path, field_name, value) over a validated config model."""

    def _walk(value, path: str, field_name: str) -> None:
        if isinstance(value, BaseModel):
            for name in type(value).model_fields:
                child_path = f"{path}.{name}" if path else name
                _walk(getattr(value, name), child_path, name)
        elif isinstance(value, dict):
            for k, v in value.items():
                _walk(v, f"{path}[{k!r}]", str(k))
        elif isinstance(value, (list, tuple)):
            for i, v in enumerate(value):
                _walk(v, f"{path}[{i}]", field_name)
        else:
            visit(path, field_name, value)

    _walk(model, path_prefix, "")


def _secret_bearing_models() -> list[tuple[str, BaseModel]]:
    """Every validated config model that can carry a SecretRef, with its config-path prefix.

    The top-level ACEConfig fields plus the prefix-scanned families whose models declare SecretRef
    fields (splunk configs, proxies) and the registered integration config models. A new
    prefix-scanned family with SecretRef fields must be added here to be covered by the custody
    check -- the check errs loud, not silent: an undeclared plaintext literal fails the boot.
    """
    config = get_config()
    models: list[tuple[str, BaseModel]] = [("", config)]

    for key in config.raw._data:
        if key.startswith("splunk_config_"):
            models.append((key, config.get_splunk_config(key[len("splunk_config_"):])))
        elif key.startswith("proxy_"):
            models.append((key, config.get_proxy_config(key[len("proxy_"):])))

    for integration_name, integration_config in INTEGRATION_CONFIGURATIONS.items():
        models.append((f"integration:{integration_name}", integration_config))

    return models


def check_no_encryption_capability(failures: list[str]) -> None:
    if "SAQ_ENC" in os.environ:
        failures.append(
            "SAQ_ENC is set in the environment; the AI container must not hold the encryption "
            "password (remove it from the service's environment)")

    if get_global_runtime_settings().encryption_key is not None:
        failures.append("the encryption subsystem is unlocked; the AI container must not be able "
                        "to read the encrypted secrets table")


def check_local_overlay_skipped(failures: list[str]) -> None:
    if "SAQ_SKIP_LOCAL_SAQ_YAML" not in os.environ:
        failures.append(
            "SAQ_SKIP_LOCAL_SAQ_YAML is not set; without it the etc/saq.yaml dev overlay (which "
            "may hold live credentials) merges into this container's configuration")


def check_infra_secrets_neutralized(failures: list[str]) -> None:
    config = get_config()
    for path, value in (
        ("api.secret_key", config.api.secret_key if config.api else None),
        ("api.api_key", config.api.api_key if config.api else None),
        ("gui.secret_key", config.gui.secret_key if config.gui else None),
    ):
        if value != AI_UNUSED_SENTINEL:
            failures.append(
                f"{path} is not the '{AI_UNUSED_SENTINEL}' sentinel; the AI container must not "
                "hold the GUI signing key or the node-to-node API key (override it in the AI "
                "config overlay)")


def check_backend_credentials(failures: list[str]) -> list[str]:
    """Run every enabled backend's validate_startup; returns the declared plaintext-secret paths."""
    declared: list[str] = []
    try:
        registry = build_backend_registry()
    except Exception as e:
        failures.append(f"failed to build the query backend registry: {e}")
        return declared

    for backend in registry.values():
        try:
            declared.extend(backend.validate_startup())
        except Exception as e:
            failures.append(f"backend {backend.name}: {e}")

    return declared


def check_secret_literal_allowlist(failures: list[str], declared_paths: list[str]) -> None:
    """Every plaintext SecretRef in the process must be declared by an enabled backend."""
    allowed = set(declared_paths)
    offenders: list[str] = []

    def visit(path: str, field_name: str, value) -> None:
        if isinstance(value, SecretRef) and value.literal and path not in allowed:
            offenders.append(path)

    for prefix, model in _secret_bearing_models():
        _walk_model(model, prefix, visit)

    if offenders:
        failures.append(
            "plaintext credential(s) present that no enabled AI query backend declares: "
            f"{', '.join(sorted(offenders))} -- the AI container may hold only the read-only "
            "credentials its backends own; remove them from the AI config overlay")


def advisory_plaintext_sweep() -> list[str]:
    """Non-fatal: plain-str fields that look like credentials and hold real values.

    Catches secrets smuggled into fields not yet typed SecretRef. Advisory because path-like and
    infrastructure values make this heuristic; the SecretRef allow-list above is the enforced rule.
    """
    warnings: list[str] = []

    def visit(path: str, field_name: str, value) -> None:
        if not isinstance(value, str) or not value or value == AI_UNUSED_SENTINEL:
            return
        if path in ADVISORY_SWEEP_EXCLUSIONS or path.split(".")[-1] in ("ssl_cert", "ssl_key"):
            return
        if SECRETISH_FIELD_NAME.search(field_name) and not value.startswith(("file:", "env:")):
            warnings.append(path)

    for prefix, model in _secret_bearing_models():
        _walk_model(model, prefix, visit)

    return warnings


def run_startup_checks() -> None:
    failures: list[str] = []

    check_no_encryption_capability(failures)
    check_local_overlay_skipped(failures)
    check_infra_secrets_neutralized(failures)
    declared = check_backend_credentials(failures)
    check_secret_literal_allowlist(failures, declared)

    for path in advisory_plaintext_sweep():
        logging.warning("ai startup: %s looks like a plaintext credential in a plain-string "
                        "config field; consider migrating the field to SecretRef", path)

    if failures:
        raise RuntimeError(
            "AI API custody checks failed, refusing to start:\n  - " + "\n  - ".join(failures))

    logging.info("AI API custody checks passed (%d declared read-only credential(s))", len(declared))
