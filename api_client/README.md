# aceapi-v2-client

A Python client library for the **ACE (Analysis Correlation Engine) API v2**.

The client is generated from the API's OpenAPI schema with
[openapi-python-client](https://github.com/openapi-generators/openapi-python-client),
so every endpoint and model is fully typed. A small hand-written `auth` module
adds convenience helpers for ACE's API-key authentication.

## Installation

```bash
pip install aceapi-v2-client
```

Or install from a checkout of this directory:

```bash
pip install .
```

Requires Python 3.9+.

## Quickstart (API key)

ACE's primary machine-to-machine authentication is an API key sent in the
`x-ace-auth` header. Use the `authenticated_client` helper to build a client
with that header pre-populated:

```python
from aceapi_v2_client.auth import authenticated_client
from aceapi_v2_client.api.common import ping_common_ping_get
from aceapi_v2_client.api.observables import (
    list_observable_types_observable_types_get,
)

client = authenticated_client(
    base_url="https://localhost:8443/api/v2",
    api_key="YOUR-API-KEY",
    verify_ssl=False,  # development instances use a self-signed certificate
)

# a simple authenticated health check
pong = ping_common_ping_get.sync(client=client)
print(pong.result)  # "pong"

# call a data endpoint — responses are parsed into typed models
types = list_observable_types_observable_types_get.sync(client=client)
print(types)
```

Every endpoint module under `aceapi_v2_client.api.*` exposes four functions:

| function          | returns                          |
| ----------------- | -------------------------------- |
| `sync(...)`       | the parsed body (or `None`)      |
| `sync_detailed(...)` | a `Response` with status + parsed body |
| `asyncio(...)`    | the parsed body, async           |
| `asyncio_detailed(...)` | a `Response`, async         |

All take `client=` as a keyword argument plus any path/query/body parameters
the operation defines.

### Async usage

```python
import asyncio
from aceapi_v2_client.auth import authenticated_client
from aceapi_v2_client.api.common import ping_common_ping_get

client = authenticated_client("https://localhost:8443/api/v2", "YOUR-API-KEY",
                              verify_ssl=False)

async def main():
    async with client as c:
        print(await ping_common_ping_get.asyncio(client=c))

asyncio.run(main())
```

## API keys are scoped

An API key carries its own permission scope. A key's **effective permission is
the intersection of that scope with its owner's permissions** — a key can never
do more than its owner, and a restricted key does strictly less. A key created
with "inherit" scope simply gets whatever its owner has.

The practical consequence for client code: a call can fail with
`403 {"detail": "Permission denied"}` even though the key is valid and the owner
is privileged, because the *key* is scoped too narrowly. Most read/write
endpoints are permission-gated — including `/observable-types/`, the
`observable-*` and `threat*` endpoints, and `/common/valid_*`. Only
`/health/ping`, `/common/ping`, `/common/supported_api_version`, and
`/users/me/apikeys` are reachable with any valid key.

Keys are **display-once**: the plaintext is returned only by the create call and
is never recoverable afterward. Mint one with `POST /users/{user_id}/apikeys`
(requires `user:write`) or from the CLI:

```bash
ace user add-api-key    # also: list-api-keys, revoke-api-key
```

To see your own keys — metadata only, never the secret:

```python
from aceapi_v2_client.api.users import list_my_api_keys_users_me_apikeys_get

for key in list_my_api_keys_users_me_apikeys_get.sync(client=client):
    print(key.id, key.name, key.inherit_user_scope, key.scope)
```

> JWT/OAuth2 login (`POST /auth/token`, `POST /auth/refresh`) and the
> `token_client` helper were removed. The API key above is the only mechanism
> available to a machine client.

## Base URL and TLS notes

- **The base URL must include the `/api/v2` prefix.** The generated client
  appends operation paths (e.g. `/common/ping`) directly to `base_url`.
  - From inside the docker compose network: `https://ace-http/api/v2`
  - From the docker host: `https://localhost:8443/api/v2`
- Development instances serve a **self-signed certificate**. Pass
  `verify_ssl=False` (as above) or point `verify_ssl` at a CA bundle path for
  production.

## Keeping the client up to date

The generated code is committed to this repository. When the ACE API v2 changes,
regenerate it from the live schema:

```bash
# against the default instance (https://ace-http/api/v2/openapi.json)
scripts/regenerate.sh

# or against a specific instance
scripts/regenerate.sh https://localhost:8443/api/v2/openapi.json
```

The script:

1. fetches the latest `openapi.json` into this directory (the build-time source
   of truth),
2. installs `openapi-python-client` into a throwaway virtualenv (so it never
   touches your main environment),
3. regenerates the package, preserving the hand-maintained files
   (`aceapi_v2_client/auth.py` and `aceapi_v2_client/py.typed`).

After running it:

1. **Review the diff**: `git diff aceapi_v2_client/`
2. **Bump the version** if the API changed — update `version` in
   `pyproject.toml` and `package_version_override` in
   `openapi-python-client-config.yaml`. The client version mirrors the API's
   major version (`2.x.y`); bump the patch/minor for client-only changes.
3. **Rebuild and verify** (below).

> Only `auth.py` and `py.typed` are hand-maintained. Do not add other custom
> code inside `aceapi_v2_client/` — it would be overwritten on regeneration.

## Building and publishing to PyPI

```bash
pip install -r requirements-dev.txt
python -m build              # produces dist/*.whl and dist/*.tar.gz
twine check dist/*           # validate metadata for PyPI
twine upload dist/*          # publish (requires PyPI credentials)
```

## Running the smoke test

The smoke test only runs when pointed at a live instance:

```bash
ACE_API_BASE_URL=https://ace-http/api/v2 \
ACE_API_KEY=YOUR-API-KEY \
ACE_API_VERIFY_SSL=false \
pytest tests/test_smoke.py -v
```

## License

Apache-2.0. See [LICENSE](LICENSE).
