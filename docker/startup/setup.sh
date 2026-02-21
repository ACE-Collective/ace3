#!/usr/bin/env bash
#

source bin/initialize-environment.sh

if [ -z "${SAQ_ENC}" ]
then
    echo "WARNING: SAQ_ENC environment variable not set, using default value 'test'"
    export SAQ_ENC="test"
fi

# Run database migrations first — tables must exist before encryption check
echo "running database migrations..."
/venv/bin/alembic upgrade head
DATABASE_NAME=ace-unittest /venv/bin/alembic upgrade head
DATABASE_NAME=ace-unittest-2 /venv/bin/alembic upgrade head
echo "database migrations complete"

# Seed database before encryption check — ace enc test calls initialize_node()
# which INSERTs into nodes with a company_id FK, so company must exist first.
echo "seeding database..."
/venv/bin/python bin/seed_database.py
echo "database seeding complete"

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
