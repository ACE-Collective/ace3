# The engine API container

ACE nodes talk to each other over the API. The routes they use, `/api/v2/engine/*`, are served
by a container of their own, `http-api-engine`, and not by `http-api-v2`, which serves everything
else under `/api/v2`. This page explains why, and how to size it.

## What it serves

| route | caller |
|---|---|
| `GET /api/v2/engine/download/{uuid}` | an engine pulling a work item from this node (`transfer_work_target`, `saq/engine/workload_manager/database.py`) |
| `POST /api/v2/engine/clear/{uuid}/{lock_uuid}` | the same engine, once it owns the pulled copy |
| `POST /api/v2/engine/upload/{uuid}` | remote collector delivery (`saq/collectors/remote_node.py`) and drain (`saq/engine/node_manager/drain.py`) |
| `POST /api/v2/engine/cli/{id}` | the node that took a GUI CLI request, starting the run recorded for this node ([GUI_CLI.md](GUI_CLI.md)) |

The container runs `api_engine_uvicorn.py`, which serves `aceapi_v2.create_engine_app()`: the
engine router plus `/health` and `/common`, and nothing a user would call. Both nginx listeners
(`etc/nginx/conf.d/default.conf` and the mTLS `conf.d.external`) send `/api/v2/engine/` there.
Longest prefix wins, so those requests never reach the `/api/v2` location. The URLs are the same
as before, so no client, `api.prefix` or `nodes.location` changes. Logs go to
`data/logs/ace-api-engine`.

`create_app()` still mounts the engine routes, so the full application (tests,
`ace gui start --api-v2`) stays complete. It is nginx that decides which container gets them.

`POST /api/v2/analysis/` (`alert:create`) is not an engine route. The GUI's New Alert and
external `ace_api.submit()` callers use it, so it stays on `http-api-v2`.

## Why it is separate

`http-api-v2` is shared by analysts' browsers, API keys, hunt validation, search and CI. All of
them compete for the same uvicorn workers, and for each worker's threads and database pools.
When the engine routes were served there too, enough user traffic could slow down or fail the
engines' work transfers. It could also exhaust the retries of remote collector delivery, which
then marks the work item ERROR. In its own container, the engine traffic has processes, threads
and database pools that user traffic cannot reach.

## Sizing

The worker count is set per node with `ACE_API_ENGINE_WORKERS` (default `4`) in that node's
`.env`:

```bash
# .env
ACE_API_ENGINE_WORKERS=8
```

```bash
docker compose up -d http-api-engine     # recreates the container with the new count
```

### Why it scales with the cluster

The load on a node's engine API comes from the *other* nodes:

- Every engine worker process on a node whose `target_nodes` include this node can pull work
  from it, and each pull is a `download` and a `clear`. An engine runs `cpu_count()` workers by
  default (`saq/engine/worker_manager.py`) unless `engine.pool_size_limit` or
  `analysis_pools` say otherwise.
- Every remote collector delivery group that delivers to this node sends `upload`s.
- A node being drained toward this one sends `upload`s.

The most requests that can arrive at once is therefore roughly

    P = (engine workers, summed over the nodes that pull from this one)
      + (collector delivery groups that deliver to this one)

and P grows with both the number of nodes and their core counts.

### What one worker can carry

`upload` and `clear` use the synchronous database pool (`saq/database/pool.py`), which the ORM and
raw cursor code share: 5 connections plus 10 overflow per process by default. An `upload` holds
two of them at once (it looks the alert up through the ORM, then schedules it through a cursor),
so `run_db_in_thread` (`aceapi_v2/sync.py`) runs at most half the pool, **7** calls, at once per
uvicorn worker and queues the rest. A `download` builds the tar in one of those 7 slots too, and
then streams it asynchronously. It is mostly disk I/O and cheaper than an upload.

Size each node at

    ACE_API_ENGINE_WORKERS ≈ max(4, ceil(P / 7))

| cluster | P (pulling from one node) | workers |
|---|---|---|
| single node | 0 (it only serves itself and collectors) | 4 |
| 3 nodes × 16 cores | ~32 | 5 |
| 6 nodes × 16 cores | ~80 | 12 |
| 10 nodes × 32 cores | ~290 | 42 |

Raising `pool_size` or `max_overflow` in the `database_ace:` block raises the per-worker figure
with it (half of their sum), for every process on the node.

These are upper bounds: P counts every peer worker pulling from the same node at the same time.
That happens when one node holds the backlog, for example a node that collects but does little
analysis. A cluster whose work is spread evenly needs fewer.

### MySQL connections

Each uvicorn worker can hold up to about 30 database connections: 15 in the async pool
(`aceapi_v2/database.py`) and 15 in the sync pool. Add `ACE_API_ENGINE_WORKERS × 30` per node,
across every node that shares the database, to everything else connected to it, and keep the
total under `max_connections` (3600 by default, `etc/mysqld/conf.d/config.cnf`).

### Signs that it is undersized

- `upload`/`download`/`clear` taking far longer than the work they do (requests queued for one of
  a worker's 7 slots), or 5xx responses on them.
- the engine log: `unable to transfer <uuid>` on the nodes pulling from this one.
- the collector logs: `work item ... stays locked for retry by group ...` warnings, and in the
  worst case `failed delivery N times via group ..., giving up and marking ERROR`.

If these appear while `http-api-engine` is busy, raise `ACE_API_ENGINE_WORKERS` on the node being
called (not the caller), and check the MySQL budget above.
