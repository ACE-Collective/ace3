# Running more than one ACE instance on a host

Two ACE stacks can run side by side on the same machine — one per branch, or a stable stack
next to one you are breaking. Everything that separates them is derived from a single variable,
`ACE_STACK`.

## Quick start

```bash
git clone <url> /opt/ace2                    # see below: a clone, not a worktree
cd /opt/ace2
bin/generate-instance-env.sh ace2 100 > .env
docker compose build
docker compose up -d
```

With an offset of 100 the second instance's GUI is at `https://localhost:5100/ace`, nginx at
8543 and 9543. The original checkout needs no `.env` and keeps every default it has today.

> **Use a clone, not a `git worktree`.** A worktree has no stack of its own: its scripts find the
> stack of the checkout it was made from (see *Working with a specific instance* below), so it
> cannot be a second instance.

## How the isolation works

`ACE_STACK` (default `ace`) is the compose **project name**, set by the top-level `name:` key
in `docker-compose.yml`. Compose derives from the project name:

| | instance `ace` | instance `ace2` |
|---|---|---|
| containers | `ace-ace-1`, `ace-dev-1`, … | `ace2-ace-1`, `ace2-dev-1`, … |
| network | `ace_ace` | `ace2_ace` |
| volumes | `ace_data`, `ace_db`, `ace_auth`, … | `ace2_data`, `ace2_db`, `ace2_auth`, … |

Because each stack gets its own network, the in-container hostnames (`ace-db`, `redis`,
`rabbitmq`, `qdrant`, `ace-http`, `fluent-bit`) resolve to that stack's own containers and need
no per-instance configuration. Each stack also generates its own credentials into its own
`auth` volume, and its own self-signed certificates into its own bind-mounted `ssl/` directory —
so the second instance's certificate is a different CA and has to be trusted separately in your
browser.

> **Do not set `COMPOSE_PROJECT_NAME`.** It overrides the top-level `name:`, which would leave
> the project name and the volume names disagreeing. `docker/startup/initialize_volumes.sh`
> detects this and refuses to start rather than let two stacks share one MySQL datadir.

### `ACE_STACK` is not `ACE_INSTANCE_NAME` or `ACE_INSTANCE_TYPE`

Three similarly named variables that do unrelated things:

| variable | what it sets | who reads it |
|---|---|---|
| `ACE_STACK` | the compose project name — the prefix on every container, the network and all ten volumes; also the `phishkit.stack` label and the `.ace_stack` guard marker | docker only; no ACE code reads it |
| `ACE_INSTANCE_NAME` | `global.instance_name` | the navbar label `ACE3 (…)` and the `tool_instance` recorded on manually created alerts |
| `ACE_INSTANCE_TYPE` | `global.instance_type` | picks the Flask config class and gates which services are allowed to run (`DEV`/`QA`/`PRODUCTION`) |

They vary independently: a second dev stack is typically project `ace2`, label `DEV2`, type
`DEV`. Only `ACE_STACK` affects docker naming, and only it needs to be unique per host.

## Ports

Only five host ports are fixed. The generator offsets all of them:

| variable | default | what it is |
|---|---|---|
| `ACE_PORT_GUI` | 5000 | the Flask dev GUI (`http-debug`) |
| `ACE_PORT_DEV_GUI` | 5001 | the `dev` container's GUI port |
| `ACE_PORT_HTTP` | 8443 | nginx |
| `ACE_PORT_HTTP_EXTERNAL` | 9443 | nginx, mTLS listener |
| `ACE_PORT_FLUENT_BIT` | 24224 | the fluent-bit forward input |

Everything else — MySQL, the read-only replica, redis, rabbitmq, qdrant and the network
semaphore — is published on an **ephemeral** host port bound to `ACE_BIND_ADDRESS`
(`127.0.0.1` by default). Nothing in ACE depends on those host ports; every consumer reaches
those services by hostname on the compose network. To connect from the host, ask compose which
port it got:

```bash
docker compose port ace-db 3306      # -> 127.0.0.1:49154
```

`ACE_PORT_FLUENT_BIT` is the one that cannot be ephemeral. Every service logs through the
docker `fluentd` driver, whose `fluentd-address` is resolved by **dockerd on the host**, not
inside the compose network — so the port has to be known before the stack starts. This is also
the subtlest thing multi-instance support had to fix: with both stacks on 24224, the second
fluent-bit failed to bind and every one of its containers shipped its logs into the first
stack's `data/logs`.

Set `ACE_BIND_ADDRESS=0.0.0.0` to reach an instance from another machine.

## Images

`docker compose build` tags its output, and by default every checkout tags `ace3:latest`. Two
instances sharing that tag means building in one changes what the other starts next time. The
generator gives each instance its own tags (`ace3:ace2`, `phishkit:ace2`, …). That costs a
second full set of images on disk; if both checkouts sit on the same revision and you would
rather share, delete the five `ACE3_*_IMAGE_URL` lines from the generated `.env`.

## Working with a specific instance

The `bin/` helpers and the `Makefile` are all project-scoped — they act on the checkout they
live in, whatever your working directory:

```bash
/opt/ace2/bin/attach-container.sh              # shell in ace2's dev container
/opt/ace2/bin/exec-in-container.sh pytest -m unit
cd /opt/ace2 && make db-upgrade
cd /opt/ace2 && bin/ace-shutdown.sh
```

A git worktree under a checkout has no stack of its own. In a worktree, `get-dev-container.sh` and
`get-ace-container.sh` find the stack of the checkout the worktree was made from, and
`exec-in-container.sh` runs its command from the worktree's own path in the container, with
`SAQ_HOME` set to that path. Started inside the container, which has no `docker`, it runs the
command in place, from the worktree.

A worktree's `.git` file names its repository by absolute path, and the host sees the checkout at a
different path than the container's `/opt/ace`, so `git` works in a worktree only on the side that
created it, and its git work is done there. On the host, the scripts refuse a worktree that git
cannot open rather than fall back to the main checkout's stack and code; in the container,
`exec-in-container.sh` runs a host worktree's command in place, which needs no git.

A worktree outside its checkout (T3 Code keeps them under `~/.t3/worktrees/<repo>/`) is not visible
in the container until you mount it. In the checkout's `docker-compose.override.yml`, mount the
directory that holds the worktrees, and `local/` at its host path, because such a worktree's `local`
link is absolute:

```yaml
services:
  dev:
    volumes:
      - ./.git:/absolute/host/path/to/the/checkout/.git
      - ./local:/absolute/host/path/to/the/checkout/local
      - /absolute/host/path/to/the/worktrees:/opt/ace-worktrees
```

Recreate `dev` with `docker compose up -d --no-deps dev`. `exec-in-container.sh` asks `docker inspect`
for the bind mounts and uses the deepest one above the worktree, so the destination can be any path.
Keep it short: a long path can push a unix socket under the data directory past the 108-byte
`AF_UNIX` limit, and a `.` in it makes SVS replay refuse the `work_dir`.

They find the stack by asking compose (`docker compose ps -q <service>`), which means they
resolve whichever compose file that checkout would use by default. A deployment that runs its
own compose file rather than the one at the repo root — `integrations/bv_ace/docker-compose.yml`,
for instance — points them at it by exporting `COMPOSE_FILE`:

```bash
export COMPOSE_FILE=integrations/bv_ace/docker-compose.yml
bin/attach-container.sh
```

Compose then takes its project directory — and so its project name and its `.env` — from that
file's directory, which is the behaviour such a deployment already has.

## Running the test suite in more than one instance

Two instances can run the suite at the same time. They do not share state:

- the run marker lives at `$SAQ_HOME/.pytest-running`, which is each stack's own
  bind-mounted checkout, and the port block locks at `/tmp/ace-pytest-ports-<n>.lock`, which
  are each container's own (`tests/session_lock.py`);
- each session provisions its own databases on its own `ace-db`;
- the suite's API (24443+) and network-semaphore (53560+) ports are internal to the container
  and never published to the host.

`CLAUDE.md`'s rule against starting more than one run at a time is about one checkout, not one
container or one host.

## Upgrading an existing environment

Before multi-instance support, the volumes carried an explicit `name:` that pinned them to
global names (`ace-data`, `ace-db`, …). Those names are what made a second instance impossible,
so they are now project-prefixed (`ace_data`, `ace_db`, …). **There is no migration path: an
existing environment has to be torn down and rebuilt from empty volumes.** Anything in the old
volumes — alerts, the databases, generated passwords — is not carried forward, and the old
volumes are left behind for you to remove.

### First, if your checkout directory is not named `ace`

The project name also changes with this release. It used to come from the checkout directory, so
a checkout in `~/dev/ace3` ran as project `ace3` — containers `ace3-dev-1`, network `ace3_ace`.
It is now `ACE_STACK`, which defaults to `ace`. **This matters before you tear anything
down**, because until the two agree the checkout's own tooling is pointed at a project that does
not exist:

- `docker compose ps`, `docker compose down`, `docker compose stop` and every `bin/` helper
  (`get-dev-container.sh`, `exec-in-container.sh`, `attach-container.sh`, `ace-shutdown.sh`)
  resolve to the new project and report nothing, while the old containers keep running;
- `docker compose up -d` builds a second, parallel set of containers instead of replacing them.

So the old stack has to be brought down under the name it was created with, which this checkout
can no longer do for you. `docker compose ls` tells you what that name is:

```bash
docker compose -p ace3 down -v       # old project name, not this checkout's
```

If you would rather keep the name the environment already has, set it explicitly and the
containers, network and volumes all stay under it:

```bash
echo ACE_STACK=ace3 >> .env       # whatever `docker compose ls` calls the running stack
```

### Then start clean

```bash
docker compose down -v               # or `-p <old project> down -v`, per above
docker compose up --build
```

`docker volume ls` afterwards should show only the `<instance>_`-prefixed volumes. Any
remaining `ace-data`, `ace-db`, … are the orphaned originals; remove them with
`docker volume rm` to reclaim the space.

## Verifying two instances are isolated

```bash
docker volume ls --filter name=ace2_                     # its own ten volumes
docker network ls | grep _ace                            # ace_ace and ace2_ace
docker compose ps                                        # from each checkout: only its own
docker compose exec dev cat /auth/passwords/ace-user     # differs between instances
docker inspect ace2-ace-1 --format '{{json .HostConfig.LogConfig}}'   # localhost:24324
```

Three things worth checking explicitly, because they fail quietly rather than loudly:

- **Logs.** Tail `data/logs/ace-engine*` in one instance while restarting a service in the
  other. Nothing from the other instance may appear.
- **Phishkit.** Start a scan in one instance, then `docker compose down` the other. The running
  `phishkit-scan-<uuid>` container must survive — each manager only reaps containers carrying
  its own `phishkit.stack` label. `docker ps --filter label=phishkit.stack=ace2` should list
  only the second instance's scanners.
- **Data.** Create an alert in one instance and confirm `select count(*) from alerts` differs
  between the two `ace-db` containers.
