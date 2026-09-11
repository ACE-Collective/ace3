# Running more than one ACE instance on a host

Two ACE stacks can run side by side on the same machine — one per branch, or a stable stack
next to one you are breaking. Everything that separates them is derived from a single variable,
`ACE_INSTANCE`.

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

> **Use a clone, not a `git worktree`.** A worktree's `.git` is a *file* holding an absolute host
> path back to the parent repo (`gitdir: /path/to/parent/.git/worktrees/<name>`). The containers
> bind-mount only the worktree directory itself at `/opt/ace`, so that path does not exist inside
> them and every `git` command against the checkout fails with `fatal: not a git repository`.
> Nothing in the running stack depends on the ACE checkout being a git repository — the signature
> and hunt repositories are separate repos with real `.git` directories and are unaffected — but
> the test suite does, and
> `tests/saq/configuration/test_analysis_mode_config.py::test_no_duplicate_keys_in_any_tracked_config_yaml`
> fails on `git ls-files`. If you want a worktree anyway, also bind-mount the parent repo's `.git`
> into the container at the same absolute path the gitdir names.

## How the isolation works

`ACE_INSTANCE` (default `ace`) is the compose **project name**, set by the top-level `name:` key
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

## Running the test suite in more than one instance

Two instances can run the suite at the same time. They do not share state:

- the `.pytest-running` marker lives at `$SAQ_HOME/.pytest-running`, which is each stack's own
  bind-mounted checkout (`tests/session_lock.py`);
- each session provisions its own databases on its own `ace-db`;
- the suite's API (24443+) and network-semaphore (53560+) ports are internal to the container
  and never published to the host.

`CLAUDE.md`'s rule against starting more than one run at a time is about one checkout, not one
host.

## Migrating an existing environment

Before multi-instance support, the volumes carried an explicit `name:` that pinned them to
global names (`ace-data`, `ace-db`, …). Those names are what made a second instance impossible,
so they are now project-prefixed (`ace_data`, `ace_db`, …). **An existing checkout will come up
with empty volumes after pulling this change** — the old data is still there, just no longer
attached.

### First, if your checkout directory is not named `ace`

The project name also changes with this release. It used to come from the checkout directory, so
a checkout in `~/dev/ace3` ran as project `ace3` — containers `ace3-dev-1`, network `ace3_ace`.
It is now `ACE_INSTANCE`, which defaults to `ace`. **Decide which name you want before you
migrate**, because until the two agree the checkout's own tooling is pointed at a project that
does not exist:

- `docker compose ps`, `docker compose stop` and every `bin/` helper (`get-dev-container.sh`,
  `exec-in-container.sh`, `attach-container.sh`, `ace-shutdown.sh`) resolve to the new project
  and report nothing, while the old containers keep running;
- `docker compose up -d` builds a second, parallel set of containers instead of replacing them.

The path of least surprise is to keep the name the environment already has:

```bash
echo ACE_INSTANCE=ace3 >> .env       # whatever `docker compose ls` calls the running stack
```

The volumes then migrate to `ace3_data`, `ace3_db`, … and the containers and network keep their
existing names. To move to `ace` instead, stop the old project explicitly first — the checkout
can no longer do it for you:

```bash
docker compose -p ace3 down          # old project name, not this checkout's
```

`bin/migrate-volume-names.sh` checks for this: it refuses to run while anything is holding the
legacy volumes, names the containers and the project they belong to, and tells you which of the
two paths above you are on. It looks the containers up by volume rather than by project, so the
check still works when the project name no longer matches.

If the data is disposable, start clean:

```bash
docker compose down -v
docker compose up --build
```

To keep it, copy each volume across:

```bash
bin/ace-shutdown.sh --fast          # the stack must be stopped
bin/migrate-volume-names.sh         # dry run: shows what would be copied
bin/migrate-volume-names.sh --yes   # do it
docker compose up -d
```

The migration only ever reads the old volumes. Once the stack comes up cleanly it prints the
`docker volume rm` commands to reclaim the space, but does not run them.

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
