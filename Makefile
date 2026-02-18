.PHONY: db-revision db-upgrade db-downgrade db-seed db-check

db-revision:
	docker compose exec dev /venv/bin/alembic revision --autogenerate -m "$(MESSAGE)"

db-upgrade:
	docker compose exec dev /venv/bin/alembic upgrade head

db-downgrade:
	docker compose exec dev /venv/bin/alembic downgrade -1

db-seed:
	docker compose exec dev /venv/bin/python bin/seed_database.py

db-check:
	docker compose exec -e DATABASE_NAME=ace-unittest-2 dev /venv/bin/python bin/check_model_drift.py
