#!/usr/bin/env bash

cd /opt/ace
source /venv/bin/activate
source load_environment
source docker/startup/start.sh

if [ -e data/var/services/embedding_service ]
then
    rm data/var/services/embedding_service
fi

./ace -L etc/logging_configs/service_llm_embedding.yaml service start llm_embedding

