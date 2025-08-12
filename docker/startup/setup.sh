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

if ! ace enc test -p "$SAQ_ENC" &> /dev/null
then
    echo "setting encryption password"
    ace enc set -o --password="$SAQ_ENC"
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
