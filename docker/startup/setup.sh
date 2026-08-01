#!/usr/bin/env bash
#

source bin/initialize-environment.sh

# if this is not the primary node, we don't need to do anything
if [ "${ACE_IS_PRIMARY_NODE}" -ne 1 ]
then
    echo "not primary node -- skipping setup"
    exit 0
fi

if [ -z "${SAQ_ENC}" ]
then
    echo "WARNING: SAQ_ENC environment variable not set, using default value 'test'"
    export SAQ_ENC="test"
fi

# Run database migrations first — tables must exist before encryption check
echo "running database migrations..."
/venv/bin/alembic -c alembic/ace.ini upgrade head
if [ "${ACE_INSTANCE_TYPE}" = "DEV" ]; then
    DATABASE_NAME=ace-unittest /venv/bin/alembic -c alembic/ace.ini upgrade head
    DATABASE_NAME=ace-unittest-2 /venv/bin/alembic -c alembic/ace.ini upgrade head
fi
echo "database migrations complete"

echo "running analysis cache database migrations..."
/venv/bin/alembic -c alembic/analysis_cache.ini upgrade head
if [ "${ACE_INSTANCE_TYPE}" = "DEV" ]; then
    CACHE_DATABASE_NAME=analysis-result-cache-unittest /venv/bin/alembic -c alembic/analysis_cache.ini upgrade head
fi
echo "analysis cache database migrations complete"

echo "running brocess database migrations..."
/venv/bin/alembic -c alembic/brocess.ini upgrade head
if [ "${ACE_INSTANCE_TYPE}" = "DEV" ]; then
    BROCESS_DATABASE_NAME=brocess-unittest /venv/bin/alembic -c alembic/brocess.ini upgrade head
fi
echo "brocess database migrations complete"

echo "running email archive database migrations..."
/venv/bin/alembic -c alembic/email_archive.ini upgrade head
if [ "${ACE_INSTANCE_TYPE}" = "DEV" ]; then
    EMAIL_ARCHIVE_DATABASE_NAME=email-archive-unittest /venv/bin/alembic -c alembic/email_archive.ini upgrade head
fi
echo "email archive database migrations complete"

# Seed database before encryption check — ace enc test calls initialize_node()
# which INSERTs into nodes with a company_id FK, so company must exist first.
echo "seeding database..."
if [ "${ACE_INSTANCE_TYPE}" = "DEV" ]; then
    /venv/bin/python bin/seed_database.py --seed-unittests
else
    /venv/bin/python bin/seed_database.py
fi
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
