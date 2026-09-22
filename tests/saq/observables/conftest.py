import fakeredis
import pytest


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    """Backs the redis export with fakeredis, keyed by database on one shared server.

    One server is the point: swapdb is a server-level command, so both databases have to live on the
    same one for the cutover to be observable.

    Autouse, and in a conftest rather than in test_export_redis.py, because run_exports() with no
    names selects every *enabled* target -- and observable_export_redis is enabled in the shipped
    configuration. Without this, every bare run_exports() in this directory does a real flushdb on
    REDIS_DB_FOR_DETECTION_B and a server-level swapdb against the redis the engine reads its
    detection cache from, which every other xdist worker is sharing.
    """
    server = fakeredis.FakeServer()
    connections = {}

    def _get_connection(database, config_name=None):
        if database not in connections:
            connections[database] = fakeredis.FakeStrictRedis(
                server=server, db=database, decode_responses=True)

        return connections[database]

    monkeypatch.setattr(
        "saq.observables.export.redis_cache.get_redis_connection", _get_connection)
    return _get_connection
