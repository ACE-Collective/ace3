"""`ace search ...`: index, query and inspect the alert search index (docs/SEARCH.md)."""

import dataclasses
import json

from saq.cli.cli_main import get_cli_subparsers
from saq.database.pool import get_db

search_parser = get_cli_subparsers().add_parser("search", help="Alert search index operations.")
search_sp = search_parser.add_subparsers(dest="search_cmd")


def _all_alert_uuids() -> list[str]:
    from saq.database.model import Alert
    return [row[0] for row in get_db().query(Alert.uuid).order_by(Alert.id.asc())]


def cli_index(args):
    from saq.search.tasks import submit_index_task

    if args.storage_dir:
        from saq.database.model import load_alert_by_storage_dir
        alert = load_alert_by_storage_dir(args.storage_dir)
        if alert is None:
            print(f"{args.storage_dir} is not the storage directory of an alert (only alerts are indexed)")
            return 1

        uuids = [alert.uuid]
    elif args.uuid:
        uuids = [args.uuid]
    elif args.all:
        uuids = _all_alert_uuids()
    else:
        print("specify -u UUID, --all or a storage directory")
        return 1

    if args.sync:
        # deferred: loads the embedding model
        from saq.search.index import index_alert
        from saq.search.model import load_model
        model = load_model()
        for alert_uuid in uuids:
            result = index_alert(alert_uuid, model=model)
            if result.skipped:
                print(f"{alert_uuid}: skipped ({result.skipped})")
            else:
                print(f"{alert_uuid}: {result.document_count} documents, {result.point_count} points, {result.seconds:.2f}s")
                if args.verbose:
                    for document in result.documents:
                        print(f"  [{document.kind}/{document.key}] {document.title or ''}: {document.text[:120]!r}")
    else:
        submitted = sum(1 for alert_uuid in uuids if submit_index_task(alert_uuid))
        print(f"submitted {submitted} of {len(uuids)} alerts to the search indexer")
        if submitted < len(uuids):
            print("is service_search_indexer enabled?")

    return 0


index_parser = search_sp.add_parser("index", help="Index one alert, every alert, or the alert in a storage directory.")
index_parser.add_argument("-u", "--uuid", help="The UUID of an alert to index.")
index_parser.add_argument("--all", action="store_true", default=False, help="Index every alert in the database.")
index_parser.add_argument("--sync", action="store_true", default=False, help="Index in this process instead of queueing for the indexer service.")
index_parser.add_argument("-v", "--verbose", action="store_true", default=False, help="With --sync: print the extracted documents.")
index_parser.add_argument("storage_dir", nargs="?", help="The storage directory of an alert.")
index_parser.set_defaults(func=cli_index)


def _print_response(response, as_json: bool):
    if as_json:
        data = dataclasses.asdict(response)
        data["lanes_used"] = sorted(response.lanes_used)
        for result in data["results"]:
            result["lanes"] = sorted(result["lanes"])
        print(json.dumps(data, indent=2, default=str))
        return

    from saq.database.model import Alert
    descriptions = {}
    if response.results:
        for alert_uuid, description, disposition in get_db().query(Alert.uuid, Alert.description, Alert.disposition).filter(Alert.uuid.in_(response.alert_uuids)):
            descriptions[alert_uuid] = (description, disposition)

    print(f"{response.total} result(s) for {response.query!r} (lanes: {', '.join(sorted(response.lanes_used))}; {response.timings_ms})")
    for result in response.results:
        description, disposition = descriptions.get(result.alert_uuid, ("?", "?"))
        print(f"{result.rank:>3}. [{result.tier:<6}] {result.alert_uuid} {disposition} {description}")
        for hit in result.hits:
            snippet = hit.text.replace("\n", " ")[:160]
            print(f"       {hit.lane}/{hit.kind} {hit.title or ''}: {snippet}")


def cli_query(args):
    from saq.search.query import search_alerts
    from saq.search.types import ALL_LANES, SearchRequest

    lanes = frozenset([args.lane]) if args.lane else ALL_LANES
    response = search_alerts(SearchRequest(query=args.query, limit=args.limit, lanes=lanes))
    _print_response(response, args.json)
    return 0


query_parser = search_sp.add_parser("query", help="Search alerts.")
query_parser.add_argument("query", help="The search text.")
query_parser.add_argument("--limit", type=int, default=20)
query_parser.add_argument("--lane", choices=["semantic", "lexical"], default=None, help="Run only one lane.")
query_parser.add_argument("--json", action="store_true", default=False)
query_parser.set_defaults(func=cli_query)


def cli_similar(args):
    from saq.search.query import similar_alerts

    _print_response(similar_alerts(args.uuid, limit=args.limit), args.json)
    return 0


similar_parser = search_sp.add_parser("similar", help="Find alerts similar to an alert.")
similar_parser.add_argument("uuid", help="The UUID of the alert.")
similar_parser.add_argument("--limit", type=int, default=10)
similar_parser.add_argument("--json", action="store_true", default=False)
similar_parser.set_defaults(func=cli_similar)


def cli_status(args):
    from saq.constants import REDIS_DB_BG_TASKS
    from saq.redis_client import get_redis_connection
    from saq.search.index import status
    from saq.search.tasks import FAILED_TASK_KEY, TASK_KEY

    result = status()
    redis_connection = get_redis_connection(REDIS_DB_BG_TASKS)
    result["queued_tasks"] = redis_connection.llen(TASK_KEY)
    result["failed_tasks"] = redis_connection.llen(FAILED_TASK_KEY)
    print(json.dumps(result, indent=2, default=str))
    return 0


status_parser = search_sp.add_parser("status", help="Show the state of the search index and its queues.")
status_parser.set_defaults(func=cli_status)


def cli_reset(args):
    from saq.constants import REDIS_DB_BG_TASKS
    from saq.redis_client import get_redis_connection
    from saq.search.index import collection_name, drop_collection
    from saq.search.tasks import FAILED_TASK_KEY, TASK_KEY

    name = collection_name()
    if not args.yes:
        answer = input(f"drop collection {name} and purge the indexer queues? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("aborted")
            return 1

    dropped = drop_collection()
    redis_connection = get_redis_connection(REDIS_DB_BG_TASKS)
    redis_connection.delete(TASK_KEY)
    redis_connection.delete(FAILED_TASK_KEY)
    print(f"collection {name} {'dropped' if dropped else 'did not exist'}; queues purged")
    print("run `ace search index --all` to rebuild")
    return 0


reset_parser = search_sp.add_parser("reset", help="Drop the search collection and purge the indexer queues.")
reset_parser.add_argument("--yes", action="store_true", default=False, help="Do not ask for confirmation.")
reset_parser.set_defaults(func=cli_reset)
