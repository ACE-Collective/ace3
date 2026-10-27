.PHONY: db-revision db-upgrade db-downgrade db-seed db-check \
        cache-db-revision cache-db-upgrade cache-db-downgrade cache-db-check \
        brocess-db-revision brocess-db-upgrade brocess-db-downgrade brocess-db-check \
        email-archive-db-revision email-archive-db-upgrade email-archive-db-downgrade email-archive-db-check

# runs in this checkout's dev container, from this checkout's own path in it, so a git worktree
# runs its own code (bin/exec-in-container.sh)
EXEC = bin/exec-in-container.sh

db-revision:
	$(EXEC) '/venv/bin/alembic -c alembic/ace.ini revision --autogenerate -m "$(MESSAGE)"'

db-upgrade:
	$(EXEC) '/venv/bin/alembic -c alembic/ace.ini upgrade head'

db-downgrade:
	$(EXEC) '/venv/bin/alembic -c alembic/ace.ini downgrade -1'

db-seed:
	$(EXEC) '/venv/bin/python bin/seed_database.py'

db-check:
	$(EXEC) '/venv/bin/python bin/check_model_drift.py'

cache-db-revision:
	$(EXEC) '/venv/bin/alembic -c alembic/analysis_cache.ini revision --autogenerate -m "$(MESSAGE)"'

cache-db-upgrade:
	$(EXEC) '/venv/bin/alembic -c alembic/analysis_cache.ini upgrade head'

cache-db-downgrade:
	$(EXEC) '/venv/bin/alembic -c alembic/analysis_cache.ini downgrade -1'

cache-db-check:
	$(EXEC) '/venv/bin/python bin/check_model_drift.py --database cache'

brocess-db-revision:
	$(EXEC) '/venv/bin/alembic -c alembic/brocess.ini revision --autogenerate -m "$(MESSAGE)"'

brocess-db-upgrade:
	$(EXEC) '/venv/bin/alembic -c alembic/brocess.ini upgrade head'

brocess-db-downgrade:
	$(EXEC) '/venv/bin/alembic -c alembic/brocess.ini downgrade -1'

brocess-db-check:
	$(EXEC) '/venv/bin/python bin/check_model_drift.py --database brocess'

email-archive-db-revision:
	$(EXEC) '/venv/bin/alembic -c alembic/email_archive.ini revision --autogenerate -m "$(MESSAGE)"'

email-archive-db-upgrade:
	$(EXEC) '/venv/bin/alembic -c alembic/email_archive.ini upgrade head'

email-archive-db-downgrade:
	$(EXEC) '/venv/bin/alembic -c alembic/email_archive.ini downgrade -1'

email-archive-db-check:
	$(EXEC) '/venv/bin/python bin/check_model_drift.py --database email-archive'
