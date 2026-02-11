ARG PYTHON_DOCKER_IMAGE=python:3.12-bookworm
FROM ${PYTHON_DOCKER_IMAGE}

# add metadata labels
LABEL maintainer="John Davison <unixfreak0037@gmail.com>"
LABEL description="Analysis Correlation Engine"
LABEL version="3.0.0"

# env vars
ENV SAQ_HOME=/opt/ace \
    SAQ_USER=ace \
    SAQ_GROUP=ace \
    TZ=UTC \
    DEBIAN_FRONTEND=noninteractive \
    NPM_CONFIG_PREFIX=/usr/local/share/npm-global \
    PATH=$PATH:/usr/local/share/npm-global/bin

# build arguments
ARG SAQ_USER_ID=1000
ARG SAQ_GROUP_ID=1000
ARG http_proxy
ARG https_proxy

# set proxy environment variables if provided
ENV http_proxy=$http_proxy \
    https_proxy=$https_proxy

# create user and group
RUN groupadd ace -g $SAQ_GROUP_ID && \
    useradd -g ace -m -s /bin/bash -u $SAQ_USER_ID ace

# update sources to include contrib, non-free, and backports
# Note: de4dot uses mono-runtime from Debian - dotnet runtime not needed.
RUN sed -i -e '/^Components: main$/ s/$/ contrib non-free/' /etc/apt/sources.list.d/debian.sources && \
    sed -i -e '/^Suites: bookworm bookworm-updates$/ s/$/ bookworm-backports/' /etc/apt/sources.list.d/debian.sources

# install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        apt-transport-https \
        apt-utils \
        automake \
        bison \
        bsdmainutils \
        build-essential \
        ca-certificates \
        coreutils \
        curl \
        default-jre \
        default-mysql-client \
        dirmngr \
        dmg2img \
        dmg2img \
        dnsutils \
        enchant-2 \
        exiftool \
        file \
        flex \
        gcc \
        ghostscript \
        git \
        htop \
        less \
        libarchive-zip-perl \
        libbz2-dev \
        libffi-dev \
        libfuzzy-dev \
        libgdbm-dev \
        libimage-exiftool-perl \
        libldap2-dev \
        libmagic-dev \
        libncurses5-dev \
        libnss3-dev \
        libreadline-dev \
        libsasl2-dev \
        libsqlite3-dev \
        libssl-dev \
        libtesseract-dev \
        libtool \
        libxml2-dev \
        libxslt1-dev \
        libyaml-dev \
        locales \
        logrotate \
        lsb-release \
        lsof \
        make \
        man \
        net-tools \
        nginx \
        nmap \
        openjdk-17-jre \
        p7zip-full \
        p7zip-rar \
        pkg-config \
        poppler-utils \
        rng-tools \
        rsync \
        screen \
        smbclient \
        software-properties-common \
        ssdeep \
        strace \
        tcpdump \
        tesseract-ocr \
        tshark \
        unace-nonfree \
        unixodbc-dev \
        unrar \
        unzip \
        upx-ucl \
        vim \
        wireshark-common \
        zbar-tools \
        zip \
        zlib1g-dev \
    && apt-get clean  \
    && rm -rf /var/lib/apt/lists/*

# install de4dot separately - Mono's GAC assembly registration crashes under
# Rosetta/QEMU emulation, so we handle the post-install failure gracefully.
# This does not have an impact on native amd64 systems.
RUN apt-get update && \
    (apt-get install -y --no-install-recommends de4dot || true) && \
    rm -f /var/lib/dpkg/info/libdnlib2.1-cil.postinst && \
    dpkg --configure libdnlib2.1-cil de4dot && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# install microsoft's official package signing key
RUN curl -fsSLk https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -o /tmp/packages-microsoft-prod.deb && \
    dpkg -i /tmp/packages-microsoft-prod.deb && \
    rm -f /tmp/packages-microsoft-prod.deb

# install dotnet sdk
RUN apt-get update && \
    apt-get install -y dotnet-sdk-8.0

# install ilspycmd
RUN dotnet tool install --tool-path /opt/dotnet ilspycmd

# create necessary directories
RUN mkdir -p /opt/signatures /opt/ace /venv /opt/tools && \
    chown -R ace:ace /opt/signatures /opt/ace /venv /opt/tools

# configure Python and install base packages
RUN python3 -m pip config set global.cert /etc/ssl/certs/ca-certificates.crt && \
    python3 -m pip install --no-cache-dir pip virtualenv --upgrade

# install additional tools
COPY packages/unautoit /usr/local/bin/unautoit
RUN curl -fsSLk https://github.com/leibnitz27/cfr/releases/download/0.151/cfr-0.151.jar -o /usr/local/bin/cfr.jar
RUN chmod a+x /usr/local/bin/unautoit && \
    chmod a+x /usr/local/bin/cfr.jar

# configure locale
RUN sed -i '/en_US.UTF-8 UTF-8/ s/^# //' /etc/locale.gen && \
    locale-gen en_US en_US.UTF-8 && \
    dpkg-reconfigure locales && \
    update-locale LANG=en_US.utf8 && \
    rmdir /opt/signatures && \
    ln -s /opt/ace/etc/yara /opt/signatures

# install nodejs, deobfuscator, and esprima
RUN curl -fsSLk https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    npm install --global deobfuscator && \
    npm install --global esprima && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# set up Python virtual environment
USER ace
COPY --chown=ace:ace installer/requirements.txt /venv/python-requirements.txt
COPY --chown=ace:ace installer/requirements-2.7.txt /venv/python-requirements-2.7.txt

# NOTE for now we're installing sentence-transformers w/o nvidia gpu support
RUN python3 -m virtualenv --python=python3 /venv && \
    . /venv/bin/activate && \
    pip config set global.cert /etc/ssl/certs/ca-certificates.crt && \
    pip install --no-cache-dir -U pip wheel setuptools && \
    pip install --no-cache-dir -r /venv/python-requirements.txt && \
    pip install --no-cache-dir git+https://github.com/unixfreak0037/yara_scanner_v2.git && \
    pip install --no-cache-dir git+https://github.com/unixfreak0037/officeparser3.git && \
    pip install sentence-transformers --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cpu

# configure bash environment
RUN echo 'source /venv/bin/activate' >> /home/ace/.bashrc && \
    echo 'export PATH="$PATH:/opt/ace/bin:/opt/ace:/usr/local/share/npm-global/bin"' >> /home/ace/.bashrc && \
    echo 'if [ -e /opt/ace/load_environment ]; then source /opt/ace/load_environment; fi' >> /home/ace/.bashrc

# install additional Python packages
RUN . /venv/bin/activate && \
    pip install --no-cache-dir -U \
        https://github.com/DissectMalware/xlrd2/archive/master.zip \
        https://github.com/DissectMalware/pyxlsb2/archive/master.zip \
        https://github.com/DissectMalware/XLMMacroDeobfuscator/archive/master.zip

# install john the ripper
USER ace
RUN cd /opt/tools && \
    git clone https://github.com/openwall/john.git john-1.9.0-jumbo-1 && \
    cd john-1.9.0-jumbo-1/src && \
    ./configure && \
    make -s -j $(nproc)

# the olevba library wants to reset the logging levels you set
# so we patch it so that it doesn't do that
#RUN sed -i -e '/# TODO: here it works only/,+1d' /venv/lib/python3.9/site-packages/oletools/olevba.py

RUN mkdir -p /opt/ace/data/logs /opt/ace/data/error_reports /opt/ace/data/external /opt/ace/data/var && \
    rm -rf /opt/ace/etc/yara && \
    mkdir -p /opt/ace/etc/yara && \
    touch /opt/ace/etc/yara/.empty && \
    rm -rf /opt/ace/hunts/site && \
    mkdir -p /opt/ace/hunts/site && \
    touch /opt/ace/hunts/site/.empty && \
    rm -rf /opt/ace/etc/collection/tuning && \
    mkdir -p /opt/ace/etc/collection/tuning && \
    touch /opt/ace/etc/collection/tuning/.empty && \
    find /opt/ace -type d -name __pycache__ -print0 | xargs -0 rm -rf

# configure git for automation
RUN git config --global user.email 'ace@localhost' && \
    git config --global user.name "ACE Automation"

# clean up proxy settings
USER root
RUN rm -f /etc/apt/apt.conf.d/proxy.conf

# XXX is this needed?
RUN sed -i -e 's/MinProtocol = TLSv1.2/MinProtocol = TLSv1.0/' /etc/ssl/openssl.cnf

# XXX is this line needed?
RUN mkdir -p /opt/ace/data/logs /opt/ace/data/error_reports /opt/ace/data/external /opt/ace/data/var

# ------------------------------------------------------------------------------------------------
# claude code setup
# ------------------------------------------------------------------------------------------------

# eventually we'll move this to a dev container Dockerfile

ARG CLAUDE_CODE_VERSION=latest

# setup needed for claude dev container work
RUN mkdir -p /usr/local/share/npm-global /home/ace/.claude && \
    chown -R ace:ace /usr/local/share /home/ace/.claude

USER ace
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}

USER root

# NOTE that COPY app /opt/ace does not create /opt/ace/app, it actually copies everything inside of app into /opt/ace
# so we copy each individual thing we need
COPY --chown=ace:ace ace ace_api.py ace_uwsgi.py analyst_on_ace.png ansistrm.py api_uwsgi.py api_uvicorn.py flask_config.py load_environment pytest.ini /opt/ace/
COPY --chown=ace:ace aceapi /opt/ace/aceapi
COPY --chown=ace:ace aceapi_v2 /opt/ace/aceapi_v2
COPY --chown=ace:ace app /opt/ace/app
COPY --chown=ace:ace bin /opt/ace/bin
COPY --chown=ace:ace bro /opt/ace/bro
COPY --chown=ace:ace cron /opt/ace/cron
COPY --chown=ace:ace docker /opt/ace/docker
COPY --chown=ace:ace saq /opt/ace/saq
COPY --chown=ace:ace sql /opt/ace/sql
COPY --chown=ace:ace tests /opt/ace/tests
COPY --chown=ace:ace etc /opt/ace/etc
COPY --chown=ace:ace hunts /opt/ace/hunts
COPY --chown=ace:ace phishkit /opt/ace/phishkit

# install all available integrations
# note that all integrations are installed even if they are disabled in the config
COPY --chown=ace:ace integrations /opt/ace/integrations
RUN /opt/ace/bin/install_integrations.sh

USER ace
WORKDIR /opt/ace
VOLUME [ "/opt/ace/data", "/opt/ace/etc/yara", "/opt/ace/hunts", "/opt/ace/etc/collection" ]
