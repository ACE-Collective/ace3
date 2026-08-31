# Integrations

An integration is a way to extend ACE in a structured way. The intention is to
allow you to easily build stuff for **your** environment without having to build
it directly into the core project.

This is an expiremental feature and subject to change as I figure out how I want
this to work.

## Goal

I want to be able to...

- Install an integration from a local directory.
- Enable and disable the integration.
- Add features to the application without having to modify the core project.

## Implementation Overview

- Integrations are subdirectories of (subdirectories of) the `integrations` directory.
- Each integration is it's own subdirectory.
- An integration directory can contain multiple integration directories.
- The presence of an `integration.md` file signifies that the directory is, in fact, an integration. This file serves as the documentation for it.
- The presence of an `install.sh` script is executed at image build time.
- The presence of a `src` directory is automatically appended to PYTHONPATH.
- The presence of a `etc` directory with the file `saq.integration.yaml` is automatically loaded.
- The presence of a `bin` directory is appended to PATH.
- See below for what happens with the `tests` directory.

## Instructions

To install an integration, simply copy (or clone) the integration directly into the integrations folder.

```bash
( cd integrations && git clone git@github.com:unixfreak0037/ace3-integrations.git )
```

Then rebuild the docker image and redeploy. The integration is enabled by default. You can use the ace cli to enable, disable and list the integrations.

```bash
ace integration --help # get the list of supported integration commands
ace integration list # list the status of all available integrations
ace integration enable NAME # enable the integration named NAME (requires restart)
ace integration disable NAME # disable the integration named NAME (required restart)

# (for pytest testing only)
ace integration install NAME # installs the integration name NAME (see Integration Tests)
ace integration uninstall NAME # uninstalls the integration name NAME (see Integration Tests)
```

## Integration Tests

This seems to be the trickiest part.

- I want the tests to have access to all the setup fixtures and utilities.
- pytest gets weird when loading from a deeply nested directory.

To solve this, for now, an integration has to be "installed". All this does is
create a symlink in the `tests` directory to the tests defined for the
integration. I know this is a bit of a kludge but it works.

## Development

Follow these steps to bulid a new integration.

1. Create a new subdirectory in the `integrations` directory.
1. Create an `integration.md` file to document your integration.
1. (optional) If your integration requires additional python or debian packages, or anything custom, create an `install.sh` file and make sure to `chmod 755 install.sh` so that it can be executed. This script is executed at image build time, so any changes made by this script are built into the final image.
1. Create a `src` directory to contain your python source code. Note that this directory is automatically included in the PYTHONPATH, so any modules defined in this directory are available.
1. (optional) Create a `bin` directory and include any additional executable binaries needed by your integration. Note this directory is automatically added to the PATH environment variable.
1. (optional) Create a `tests` directory for your tests. (See Integration Tests.)
1. Create an `etc` directory and put your configuration files in here.

You can use the example provided in `integrations.example` as a starting point to create a new integration.

## Integration Configuration

Each integration requires an integration configuration section, in a file named exactly
`etc/saq.integration.yaml`. 

```yaml
# each integration block starts with integration_NAME
# where NAME is a unique name for the integration
integration_example:
  name: example
  # required -- an integration with enabled: false is not imported
  enabled: true
  # a brief description of what the integration provides
  description: "Example Integration"
  # the python package to import
  python_module: example
  # extra keys are permitted and ignored
  author: unixfreak0037@gmail.com
  repo: https://github.com/unixfreak0037/ace3-example-integration
```

**The `integration_<name>:` block is mandatory.** 

ACE logs a warning at startup for any discovered integration directory that has no
`integration_*:` block.

## Notes

- Python analyzers in vscode/cursor have to be updated to reference the `src` directories in the integrations.
```javascript
// example .vscode/settings.json
{
    "python.analysis.extraPaths": ["integrations/example/src"],
    "cursorpyright.analysis.extraPaths": ["integrations/example/src"]
}
```
- An integration can be a whole separate git repository.
- The `integrations` directory is in .gitignore.
- The symlinks created for the tests are also in .gitignore.
