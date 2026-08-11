from saq.analysis.root import RootAnalysis
from saq.cli.cli_main import get_cli_subparsers

llm_parser = get_cli_subparsers().add_parser("llm", help="LLM operations for ACE.")
llm_sp = llm_parser.add_subparsers(dest="llm_cmd")

def cli_vectorize(args):
    # keeping this here for now because the imports take a long time to load
    from saq.llm.embedding.vector import vectorize
    from saq.database.pool import get_db

    context_records = []
    if args.all:
        from saq.database.model import Alert
        alerts = get_db().query(Alert).all()
        for alert in alerts:
            alert.load()
            context_records = vectorize(alert)
            for context_record in context_records:
                print(f"🧠 {context_record}")
    else:
        root = RootAnalysis(storage_dir=args.storage_dir)
        root.load()
        context_records = vectorize(root)
        for context_record in context_records:
            print(f"🧠 {context_record}")


cli_vectorize_parser = llm_sp.add_parser("vectorize", help="Vectorize a root analysis.")
cli_vectorize_parser.add_argument("--clear", action="store_true", help="Clear the context records before vectorizing.")
cli_vectorize_parser.add_argument("--all", action="store_true", help="Vectorize all alerts.")
cli_vectorize_parser.add_argument("storage_dir", nargs="?", type=str, help="The path to the root analysis.")
cli_vectorize_parser.set_defaults(func=cli_vectorize)

def cli_create_index(args):
    from saq.llm.embedding.vector import ROOT_UUID_FIELD, create_root_uuid_index, get_alert_collection_name
    from saq.qdrant_client import get_qdrant_client

    client = get_qdrant_client()
    collection_name = get_alert_collection_name()

    if not client.collection_exists(collection_name=collection_name):
        print(f"collection {collection_name} does not exist - nothing to do")
        return

    if not args.status:
        result = create_root_uuid_index(client, wait=args.wait)
        print(f"create_payload_index: {result.status}")

    payload_schema = client.get_collection(collection_name=collection_name).payload_schema
    print(f"payload schema for {collection_name}: {payload_schema}")
    if ROOT_UUID_FIELD not in (payload_schema or {}):
        print(f"NOTE: {ROOT_UUID_FIELD} index is not present yet (it may still be building)")

cli_create_index_parser = llm_sp.add_parser("create-index", help="Creates the root_uuid payload index on the alert collection.")
cli_create_index_parser.add_argument("--wait", action="store_true", default=False, help="Block until the index has finished building.")
cli_create_index_parser.add_argument("--status", action="store_true", default=False, help="Only report the current payload schema without creating the index.")
cli_create_index_parser.set_defaults(func=cli_create_index)

def cli_search(args):
    from saq.llm.embedding.search import search
    print(search(args.search_term))

cli_search_parser = llm_sp.add_parser("search", help="Search for alerts.")
cli_search_parser.add_argument("search_term", type=str, help="The search term.")
cli_search_parser.set_defaults(func=cli_search)

llm_service_parser = llm_sp.add_parser("service", help="LLM service operations.")
llm_service_sp = llm_service_parser.add_subparsers(dest="llm_service_cmd")

def cli_service_vectorize(args):
    from saq.llm.embedding.service import submit_embedding_task
    if args.uuid:
        submit_embedding_task(args.uuid)
    elif args.all:
        from saq.database.pool import get_db_connection
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("SELECT uuid FROM alerts")
            for row in cursor:
                submit_embedding_task(row[0])

cli_service_vectorize_parser = llm_service_sp.add_parser("vectorize", help="Vectorize one or more alerts.")
cli_service_vectorize_parser.add_argument("-u", "--uuid", help="The UUID of an alert to vectorize.")
cli_service_vectorize_parser.add_argument( "--all", action="store_true", default=False, help="Submit all alerts to the embedding service.")
cli_service_vectorize_parser.set_defaults(func=cli_service_vectorize)
