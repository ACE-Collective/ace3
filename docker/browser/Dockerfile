# headless Chromium for agent-driven GUI testing (docs/GUI_TESTING.md)
#
# It lives in its own image so that the ACE image, which every ACE service runs, carries no browser.
# The compose services built from it run either the Playwright MCP server or a Playwright server
# that the Python playwright package in the dev image connects to.

ARG DOCKER_IMAGE_PREFIX=docker.io
FROM ${DOCKER_IMAGE_PREFIX}/library/node:24-trixie-slim

# PLAYWRIGHT_VERSION decides the Chromium build. The pip playwright in the ACE Dockerfile must have
# the same major.minor version, or its connect() to the Playwright server is refused.
# @playwright/mcp bundles its own playwright-core, which looks for the Chromium revision it was
# built for, so PLAYWRIGHT_MCP_VERSION must be one that uses the same revision; the check below
# fails the build when it does not.
ARG PLAYWRIGHT_VERSION=1.65.0
ARG PLAYWRIGHT_MCP_VERSION=0.0.85

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

RUN npm install -g playwright@${PLAYWRIGHT_VERSION} @playwright/mcp@${PLAYWRIGHT_MCP_VERSION} && \
    npm cache clean --force && \
    playwright install --with-deps chromium && \
    rm -rf /var/lib/apt/lists/*

RUN browsers="$(npm root -g)/@playwright/mcp/node_modules/playwright-core/browsers.json" && \
    revision=$(node -p "require('$browsers').browsers.find(b => b.name === 'chromium').revision") && \
    if [ ! -d "$PLAYWRIGHT_BROWSERS_PATH/chromium-$revision" ]; then \
        echo "@playwright/mcp@${PLAYWRIGHT_MCP_VERSION} needs chromium-$revision," \
             "but playwright@${PLAYWRIGHT_VERSION} installed: $(ls $PLAYWRIGHT_BROWSERS_PATH)" >&2; \
        exit 1; \
    fi
