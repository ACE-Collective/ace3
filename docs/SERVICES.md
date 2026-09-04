# ACE Services

A "service" in ACE is a long-running process that exposes a uniform lifecycle (start / wait / stop) and is typically run as its own container in `docker-compose.yml`. Examples include `engine`, `remediation`, `hunter`, `cron`, `yara`, `network_semaphore`, `monitoring`, and `llm_embedding`.

This document describes how the service framework is wired together and what is required to add a new service.

---

## Architecture

### The interface

All services implement `ACEServiceInterface` (`saq/service.py`):

```python
class ACEServiceInterface(Protocol):
    def start(self): ...
    def wait_for_start(self, timeout: float = 5) -> bool: ...
    def start_single_threaded(self): ...
    def stop(self): ...
    def wait(self): ...

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]: ...
```

The service class is just a lifecycle adapter — the actual work is normally done by a "manager" or "server" object that the service class owns (e.g. `RemediationService` -> `RemediationManager`, `NetworkSemaphoreService` -> `NetworkSemaphoreServer`).

### How a service is launched

Each service container in `docker-compose.yml` runs:

```
/opt/ace/docker/startup/start.sh ace service start <name>
```

`start.sh` waits for the database, then execs the `ace` CLI. The `service start` subcommand is defined in the `ace` script (`ace:528-566`) and does roughly:

```python
service = load_service_by_name(args.service)
signal.signal(signal.SIGTERM, lambda *_: service.stop())
service.start()        # or start_single_threaded() with --single-threaded
service.wait()
```

`load_service_by_name` (`saq/service.py:81`) consults the parsed config, returns a `DisabledService` placeholder if the service is disabled or not valid for the current `ACE_INSTANCE_TYPE`, and otherwise dynamically imports the configured `python_module` / `python_class` and instantiates it with no arguments.

### How config is loaded

On startup, `ACEConfig.load_service_configs()` (`saq/configuration/schema.py:609`) walks every top-level YAML key that starts with `service_`, validates the common fields against `ServiceConfig`, then imports the class and re-validates the same dict against the class-specific config returned by `get_config_class()`. Result: the service can read its config later via `get_service_config(name)` and get back a fully-typed Pydantic model with its custom fields.

The base `ServiceConfig` schema (`saq/configuration/schema.py:47`):

```python
class ServiceConfig(BaseModel):
    name: str
    python_module: str
    python_class: str
    description: str
    enabled: bool
    instance_types: Optional[list[str]] = None  # e.g. ["DEV", "PRODUCTION"], or omit/["ANY"] for all
```

---

## Adding a new service

Pick a short snake_case `<name>`. Then:

### 1. Implement the service class

Create `saq/<name>/service.py` (or wherever the work lives) with a class that implements `ACEServiceInterface`. If the service has its own settings, subclass `ServiceConfig`:

```python
# saq/myservice/service.py
from typing import Type
from pydantic import Field
from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.service import ACEServiceInterface

MY_SERVICE_NAME = "myservice"

class MyServiceConfig(ServiceConfig):
    poll_interval_seconds: int = Field(..., description="how often the worker polls")

class MyService(ACEServiceInterface):
    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return MyServiceConfig

    def start(self):
        config = get_service_config(MY_SERVICE_NAME)
        self.manager = MyManager(poll_interval_seconds=config.poll_interval_seconds)
        self.manager.start()

    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.manager.wait_for_start(timeout)

    def start_single_threaded(self):
        self.manager.start_single_threaded()

    def stop(self):
        self.manager.stop()

    def wait(self):
        self.manager.wait()
```

Add a `SERVICE_MYSERVICE = "myservice"` constant in `saq/constants.py` alongside the other `SERVICE_*` entries and use it instead of a string literal.

### 2. Register the configuration

Add a `service_<name>` block to `etc/saq.default.yaml` (or a dedicated default file like `etc/saq.remediation.default.yaml`). The fields must match `MyServiceConfig`:

```yaml
service_myservice:
  name: myservice
  python_module: saq.myservice.service
  python_class: MyService
  description: Short human-readable description.
  enabled: true
  instance_types: [ANY]   # optional; omit or use ANY for all
  poll_interval_seconds: 30
```

The `name` field is what `ace service start <name>` and `get_service_config(<name>)` look up.

### 3. Add a Docker Compose service

There are two compose files to update:

- **`docker-compose.yml`** (repo root) — local development only. Updating this lets you run the new service with `docker compose up`.
- **`<your production overlay>/docker-compose.yml`** — the production deployment overlay (deployed via your config-management tooling). **This file controls the actual production rollout, so a new service is not deployed until it is added here.**

Add a stanza to *both* files, modeled after the existing services (e.g. the `remediation` stanza in the root file, and its corresponding stanza in the production-overlay file). The minimal shape:

```yaml
myservice:
  platform: linux/amd64
  environment:
    <<: *common-env
    ACE_LOG_CONFIG_PATH: etc/logging_configs/ace_logging.yaml
    FLUENT_BIT_TAG: ace-myservice
  image: ${ACE3_IMAGE_URL:-ace3:latest}
  depends_on:
    ace:
      condition: service_started   # or ace-setup: service_completed_successfully if it doesn't need the engine
  command: /bin/bash -c "/opt/ace/docker/startup/start.sh ace service start myservice"
  restart: always
  volumes: *common-volumes
  hostname: ace
  cap_add:
    - SYS_PTRACE
  networks:
    - ace
```

No image rebuild is needed — every service shares the `ace3:latest` image and bind-mounts the repo at `/opt/ace`. Restart the new container to pick up code changes.

#### Production-overlay differences

The production-overlay stanzas are similar to the root file but with a few extras to mirror nearby services:

- **`profiles:`** — every service is gated by one or more Compose profiles (`correlation`, `email-scanner`, `file-content-scanner`, `core`, `db`, etc.). Pick the same profile(s) used by the closest equivalent service so it deploys to the right node group. A service with no profile will *not* start in production.
- **`environment:`** uses the overlay's `*common-env` anchor (deployment-wide environment and credentials) — just `<<: *common-env` like the others; no manual edits needed.
- The `platform: linux/amd64` line is omitted in the production-overlay file.
- Production secrets/config come from your deployment's secret-management tooling, not from compose defaults — don't hard-code values.

### 4. Verify

```
docker compose up -d myservice
docker compose logs -f myservice
```

`SIGTERM` is wired to `service.stop()`, so `docker compose stop myservice` should shut it down cleanly. If the service is config-disabled or excluded by `instance_types`, `load_service_by_name` returns a `DisabledService` that simply blocks on a shutdown event — the container will start, log the disabled message, and idle until stopped.

---

## Reference: existing services

| Service              | Class                                          | Config section               |
|----------------------|------------------------------------------------|------------------------------|
| `engine`             | `saq.engine.core.EngineService` *(via config)* | `service_engine`             |
| `remediation`        | `saq.remediation.service.RemediationService`   | `service_remediation`        |
| `hunter`             | `saq.collectors.hunter.HunterService`          | `service_hunter`             |
| `cron`               | `saq.cron.ACECronService`                      | `service_cron`               |
| `yara`               | `saq.yara.service.*`                           | `service_yara`               |
| `network_semaphore`  | `saq.network_semaphore.service.NetworkSemaphoreService` | `service_network_semaphore` |
| `monitoring`         | `saq.monitoring.service.ACEMonitoringService`  | `service_monitoring`         |
| `llm_embedding`      | `saq.llm.embedding.service.*`                  | `service_llm_embedding`      |

`saq/monitoring/service.py` is a good reference for a service that itself loads a configurable set of named sub-workers; `saq/remediation/service.py` is the simplest possible "wrap a manager" pattern.
