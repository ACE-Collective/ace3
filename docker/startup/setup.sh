#!/usr/bin/env bash
#

cd /opt/ace
source /venv/bin/activate
source load_environment

if [ -z "${SAQ_ENC}" ]
then
    echo "WARNING: SAQ_ENC environment variable not set, using default value 'test'"
    export SAQ_ENC="test"
fi

ace enc test -p "$SAQ_ENC"
TEST_RESULT="$?"

if [ "$TEST_RESULT" -eq 2 ]
then
    echo "setting encryption password"
    ace enc set -o --password="$SAQ_ENC"
elif [ "$TEST_RESULT" -ne 0 ]
then
    echo "encryption verification failed: is SAQ_ENC env var correct?"
    exit 1
else
    echo "encryption password verified"
fi

# load any auto-generated username/passwords automatically
# once these are loaded we can remove the plaintext files

if [ -f "/auth/passwords/redis" ] && [ ! -f "/auth/passwords/redis.loaded" ]; then
    echo "loading redis auth into ace"
    ace enc config set redis.password --load-from-file /auth/passwords/redis && touch /auth/passwords/redis.loaded
fi

if [ -f "/auth/passwords/minio" ] && [ ! -f "/auth/passwords/minio.loaded" ]; then
    echo "loading minio auth into ace"
    ace enc config set minio.password --load-from-file /auth/passwords/minio && touch /auth/passwords/minio.loaded
fi

if [ -f "/auth/passwords/rabbitmq" ] && [ ! -f "/auth/passwords/rabbitmq.loaded" ]; then
    echo "loading rabbitmq auth into ace"
    ace enc config set rabbitmq.password --load-from-file /auth/passwords/rabbitmq && touch /auth/passwords/rabbitmq.loaded
fi

if [ -f "/auth/passwords/qdrant" ] && [ ! -f "/auth/passwords/qdrant.loaded" ]; then
    echo "loading qdrant auth into ace"
    ace enc config set qdrant.api_key --load-from-file /auth/passwords/qdrant && touch /auth/passwords/qdrant.loaded
fi

if [ -f "/auth/passwords/ace-api-key" ]; then
    echo "loading ace api key into ace"
    ace enc config set ace.api_key --load-from-file /auth/passwords/ace-api-key && rm /auth/passwords/ace-api-key
fi

if [ -f "/auth/passwords/ace-api-key-sha256" ]; then
    echo "loading ace api key sha256 into ace"
    ace enc config set ace.api_key-sha256 --load-from-file /auth/passwords/ace-api-key-sha256 && rm /auth/passwords/ace-api-key-sha256
fi
