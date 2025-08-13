# Analysis Correlation Engine v3

This project is a continuation of [this project from 2014](https://github.com/ace-ecosystem/ACE). 

At this time this project is very much a work in progress. I'm making sweeping changes as I go, so for now, **expect breaking changes with every commit**.

## Quick Setup

```bash
docker compose up --build
```

And then connect on [https://localhost:5000/ace](https://localhost:5000/ace) username **analyst** password **analyst**.

Optionally execute `bin/attach-container.sh` to gain a shell to the containerized environment. Then use the `ace` command line to interact from the cli.

```bash
ace --help
```

## Testing

Execute the following after attaching to the container.

```bash
pytest -m "unit or integration or system"
```

## Malware

This repo contains some live malware samples for testing purposes. Keep this in mind if your using a system with some kind of anti virus protection.