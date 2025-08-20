# ACE3 Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project (tries to) adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- integration support.

### Changed

- updated to the lastest version of yara.
- using new yara_scanner_v2 project (fixed support for include diretive).
- manage email archives database by partition.
- build jtr as part of the image.
- removed need for custom yara build.
- updated to officeparser3.
- fixed issues with crypto usage.
- switched to YAML for configuration.
- added direct support for git repos with service to manage.
- added phishkit scanning support, which doubles as a web crawler / renderer
- added support for S3-like storage with MinIO
- fixed authentication issues with some of the exposed services

### Removed

- None.

## [3.0.0] - YYYY-MM-DD
