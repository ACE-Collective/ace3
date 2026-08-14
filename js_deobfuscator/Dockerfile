ARG DOCKER_IMAGE_PREFIX=docker.io
FROM ${DOCKER_IMAGE_PREFIX}/library/docker:dind

# The manager is a long-running Celery worker that spawns throwaway
# scanner containers (built from Dockerfile.js_deobfuscator) on demand.
# It needs the host docker socket to be mounted at /var/run/docker.sock
# so that `docker run` from here actually launches sibling containers.

RUN apk update && apk add --no-cache python3

RUN python3 -m venv /opt/venv
RUN /opt/venv/bin/pip install -U pip
COPY js_deobfuscator/requirements.txt /opt/app/js_deobfuscator/
RUN /opt/venv/bin/pip install -r /opt/app/js_deobfuscator/requirements.txt

COPY js_deobfuscator/js_deobfuscator.py js_deobfuscator/harness.js /opt/app/js_deobfuscator/

WORKDIR /opt/app
CMD ["/opt/venv/bin/celery", "-A", "js_deobfuscator.js_deobfuscator", "worker", "--loglevel", "INFO", "-Q", "js_deobfuscator"]
