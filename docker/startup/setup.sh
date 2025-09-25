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

ace enc test -p "$SAQ_ENC" &> /dev/null
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

if [ ! -e data/etc/saq.api-keys.yaml ]
then
    API_KEY=$(cat /proc/sys/kernel/random/uuid)
    API_KEY_SHA256=$(echo -ne $API_KEY | openssl sha256 -r | awk '{print $1}')
    cat<<EOF > data/etc/saq.api-keys.yaml
api:
  api_key: $API_KEY

apikeys:
  automation: $API_KEY_SHA256
EOF
fi

# load any auto-generated username/passwords automatically
# use a marker file to indicate that we've already performed this activity
if [ ! -f /auth/setup.executed ]
then
    echo "loading redis auth into ace"
    ace enc config set redis.password --load-from-file /auth/passwords/redis && \
    ace enc config set minio.password --load-from-file /auth/passwords/minio && \
    ace enc config set rabbitmq.password --load-from-file /auth/passwords/rabbitmq && \
    ace enc config set qdrant.api_key --load-from-file /auth/passwords/qdrant && \
    touch /auth/setup.executed
fi
