ARG DOCKER_IMAGE_PREFIX=docker.io
FROM ${DOCKER_IMAGE_PREFIX}/library/docker:dind

RUN apk update && apk add --no-cache python3 libmagic

RUN python3 -m venv /opt/venv
RUN /opt/venv/bin/pip install -U pip
COPY phishkit/requirements.txt /opt/app/phishkit/
RUN /opt/venv/bin/pip install -r /opt/app/phishkit/requirements.txt
COPY phishkit/phishkit.py phishkit/scanner.py phishkit/worker_launcher.py /opt/app/phishkit/
COPY phishkit/Dockerfile.phishkit /opt/app/phishkit/Dockerfile

RUN mkdir -p /output

WORKDIR /opt/app
# runs the scan worker and the control worker, see worker_launcher.py
CMD ["/opt/venv/bin/python3", "-m", "phishkit.worker_launcher"]