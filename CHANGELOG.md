# ACE3 Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project (tries to) adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.5] - 2026-03-04

- [Updates Docker images to use Trixie and related fixes](Updates Docker images to use Trixie and related fixes)

## [3.0.4] - 2026-03-04

- [Unified Hunt & API Analysis Module Refactoring](https://github.com/ACE-Collective/ace3/pull/54)

## [3.0.3] - 2026-03-03

- Updates remaining places that used static VALID_OBSERVABLE_TYPES list
- dependency upgrades
    - markdown==3.10.2
    - pytz==2026.1.post1
    - SQLAlchemy==2.0.48
    - urlfinderlib==0.20.1
    - fastapi==0.135.1

## [3.0.2] - 2026-03-02

- minor bugfixes

## [3.0.1] - 2026-02-28

- summary detail processing for `QueryHunt` with `SummaryDetailConfig` for grouped/ungrouped details, format validation, and limit enforcement
- adds support for analysis module config propert default_collapsed 
- adds support for the new meta tagging for yara rules as defined in `YARA_META_TAGS.md`.
- added logo source files and adjusted title to include version and svg for favicon

## [3.0.0] - 2026-02-27

- integration support
- phishkit scanning support, which doubles as a web crawler / renderer
- support for S3-like storage with MinIO
- direct support for git repos with service to manage
- FastAPI based v2 of API
- massive refactoring
- updated to the latest version of yara
- using new `yara_scanner_v2` project (fixed support for include directive)
- manage email archives database by partition
- build jtr as part of the image
- removed need for custom yara build
- updated to officeparser3
- fixed issues with crypto usage
- switched to YAML for configuration
- fixed authentication issues with some of the exposed services
- deal with ipv6 (hunter trying to parse ipv4 as ipv6)
- fix the "send to" system
- fix the remediation system (call should not block like it does)
- work goes to data directory first, then worker moves work into "work directory" if enabled, when the worker starts
- attachment names are now logged correctly for phishfinder logs
- unravel python code and achieve high test coverage

## [1.0.0] - 2025-07-20

- initial port for ace v1
