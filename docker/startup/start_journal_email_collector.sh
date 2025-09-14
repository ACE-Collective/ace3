#!/usr/bin/env bash

cd /opt/ace
source /venv/bin/activate
source load_environment
source docker/startup/start.sh

if [ -e data/var/services/journal_email_collector ]
then
    rm data/var/services/journal_email_collector
fi

./ace -L etc/logging_configs/service_journal_email_collector.yaml service start journal_email_collector

