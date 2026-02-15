#!/usr/bin/env bash
#

source bin/initialize-environment.sh

if [ -z "${SAQ_ENC}" ]
then
    echo "WARNING: SAQ_ENC environment variable not set, using default value 'test'"
    export SAQ_ENC="test"
fi

ace enc test -p "$SAQ_ENC"
TEST_RESULT="$?"

# if the encryption password hasn't been set yet, go ahead and set it now
if [ "$TEST_RESULT" -eq 2 ]
then
    echo "setting encryption password"
    ace enc set -o --password="$SAQ_ENC"
elif [ "$TEST_RESULT" -ne 0 ]
then
    # otherwise we've provided the wrong encryption password
    echo "encryption verification failed: is SAQ_ENC env var correct?"
    exit 1
else
    echo "encryption password verified"
fi

# load any auto-generated username/passwords automatically
# some of these still need to use the plain text files so they are left in place

if [ -f "/auth/passwords/redis" ] && [ ! -f "/auth/passwords/redis.loaded" ]; then
    echo "loading redis auth into ace"
    ace enc config set redis.password --load-from-file /auth/passwords/redis && touch /auth/passwords/redis.loaded
fi

if [ -f "/auth/passwords/garage-secret-key" ] && [ ! -f "/auth/passwords/garage-secret-key.loaded" ]; then
    echo "loading s3 auth into ace"
    ace enc config set s3.password --load-from-file /auth/passwords/garage-secret-key && touch /auth/passwords/garage-secret-key.loaded
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
    ace enc config set ace.api_key --load-from-file /auth/passwords/ace-api-key
fi

if [ -f "/auth/passwords/ace-api-key-sha256" ]; then
    echo "loading ace api key sha256 into ace"
    ace enc config set ace.api_key-sha256 --load-from-file /auth/passwords/ace-api-key-sha256
fi

if [ -f "/auth/keys/flask-secret-key" ]; then
    echo "loading flask secret key into ace"
    ace enc config set flask.secret_key --load-from-file /auth/keys/flask-secret-key
fi

# write S3 test credentials for unit tests
# garage-init generates the API keys and saves them to /auth/passwords/
# the test config needs these actual credentials since GarageHQ auto-generates them
if [ -f "/auth/passwords/garage-test-access-key" ] && [ -f "/auth/passwords/garage-test-secret-key" ]; then
    S3_TEST_ACCESS_KEY=$(cat /auth/passwords/garage-test-access-key)
    S3_TEST_SECRET_KEY=$(cat /auth/passwords/garage-test-secret-key)
    cat > /docker-entrypoint-initdb.d/saq.s3.test.passwords.yaml <<EOF
s3:
  access_key: ${S3_TEST_ACCESS_KEY}
  secret_key: ${S3_TEST_SECRET_KEY}
EOF
    echo "wrote S3 test credentials to saq.s3.test.passwords.yaml"
fi
