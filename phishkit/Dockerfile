FROM docker:dind

RUN apk update && apk add --no-cache python3

RUN python3 -m venv /opt/venv
RUN /opt/venv/bin/pip install -U pip
COPY requirements.txt /opt/app/phishkit/
RUN /opt/venv/bin/pip install -r /opt/app/phishkit/requirements.txt
COPY phishkit.py scanner.py /opt/app/phishkit/
COPY Dockerfile.phishkit /opt/app/phishkit/Dockerfile

RUN mkdir -p /output

WORKDIR /opt/app
CMD ["/opt/venv/bin/celery", "-A", "phishkit.phishkit", "worker", "--loglevel", "INFO"]