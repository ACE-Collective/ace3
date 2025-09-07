# Analysis Correlation Engine v3

This project is a continuation of [this project from 2014](https://github.com/ace-ecosystem/ACE). 

I'm in the process of creating what I consider to be the "3.0" version of ACE.
See below for the roadmap. Until I get to that point I'm not going to build any
migration utilities. That means I'll be introducing breaking changes as I go,
so you may need to rebuild your containers (and volumes) from scratch.

## Quick Setup

```bash
docker compose build
docker compose up

# once you've built it you can do this instead
docker compose up --build
```

And then connect on [https://localhost:5000/ace](https://localhost:5000/ace) username **analyst** password **analyst**.

Optionally execute `bin/attach-container.sh` to gain a shell to the containerized environment. Then use the `ace` command line to interact from the cli.

```bash
ace --help
```

## The Path to "3.0"

- ☑ switch to YAML for configuration
- ☐ runtime configuration settings + gui interface (looking at Hydra + OmegaConf)
- ☐ async for I/O
- ☐ FastAPI
- ☐ easily scalable deployment
- ☐ distributed file storage (Minio/S3)
- ☑ ace3 search feature using VectorDB
    - ☑ improve summary of all analysis
- ☑ user permissions
- ☐ user password reset and initial password flow
- ☐ SSO support
- ☐ monitoring API
- ☐ kubernetes
- ☐ credential management
- ☐ direct support for regression testing
- ☐ direct support for signatures
- ☐ support ARM
- ☐ intense refactoring

## beyond 3.0

- ☐ modern web app (looking at vuejs)

## Testing

Execute the following after attaching to the container.

```bash
pytest -m "unit or integration or system"
```

## Malware

This repo contains some live malware samples for testing purposes. Keep this in mind if your using a system with some kind of anti virus protection.