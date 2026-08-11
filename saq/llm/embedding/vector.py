import hashlib
import logging
import time
from typing import Optional, Union
import uuid

from qdrant_client.http.models import FilterSelector
from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis
from saq.analysis.search import recurse_tree

from qdrant_client.models import FieldCondition, Filter, HasIdCondition, MatchValue, PayloadSchemaType, PointStruct, UpdateStatus, VectorParams, Distance

from saq.configuration.config import get_config
from saq.database.model import Alert, Comment
from saq.database.pool import get_db
from saq.llm.embedding.model import load_model
from saq.qdrant_client import get_qdrant_client

# the payload field every point carries identifying the root analysis it belongs to
ROOT_UUID_FIELD = "root_uuid"

class VectorizeError(Exception):
    """Raised when a qdrant operation performed by vectorize() did not complete."""

def _generate_point_id(root: RootAnalysis, context_document: str) -> str:
    key = f"{root.storage_dir}/{context_document}"
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    return str(uuid.UUID(bytes=digest[:16]))

def get_embedding_model() -> str:
    """Returns the configured embedding model name."""
    return get_config().llm.embedding_model

def get_alert_collection_name() -> str:
    """Returns the configured collection name for ace3 alert data."""
    return get_config().qdrant.collection_alerts

def clear_vectors():
    """Clears ALL vectors fro Qrant for the ace collection."""
    client = get_qdrant_client()
    if client.collection_exists(collection_name=get_alert_collection_name()):
        client.delete_collection(collection_name=get_alert_collection_name())

def create_root_uuid_index(client, wait: bool = False):
    """Creates the payload index on ROOT_UUID_FIELD for the alert collection.

    Without this index every filtered delete or count against root_uuid is a full scan of
    the collection, which grows without bound. This is idempotent: qdrant treats a repeat
    request for an identical index as a no-op.

    Args:
        client: the qdrant client to use.
        wait: when True, block until the index has finished building. On a collection that
            already holds a large number of points the build can take a while, so callers
            operating on an existing collection should leave this False and poll instead.
    """
    return client.create_payload_index(
        collection_name=get_alert_collection_name(),
        field_name=ROOT_UUID_FIELD,
        field_schema=PayloadSchemaType.KEYWORD,
        wait=wait,
    )

def get_context_records(target: Union[Alert, RootAnalysis]) -> list[str]:
    """Returns the list of context records for the root analysis."""

    context_records: list[str] = []
    alert: Optional[Alert] = target if isinstance(target, Alert) else None
    root: Optional[RootAnalysis] = target.root_analysis if isinstance(target, Alert) else target

    if alert is not None:
        context_record = (
            "# ALERT SUMMARY\n"
            f"- description: {alert.description}\n"
            f"- tool: {alert.tool}\n"
            f"- tool instance: {alert.tool_instance}\n"
            f"- alert type: {alert.alert_type}\n"
        )

        if alert.disposition is not None:
            context_record += f"- disposition: {alert.disposition}\n"

        if alert.owner is not None:
            context_record += f"- owner: {alert.owner.gui_display}\n"

        context_records.append(context_record)

        for comment in get_db().query(Comment).filter(Comment.uuid == alert.uuid).order_by(Comment.insert_date.asc()):
            context_records.append(f"user {comment.user.gui_display} commented {comment.comment}\n")

    context_records.append(
        "# ROOT ANALYSIS SUMMARY\n"
        f"- description: {root.description}\n"
        f"- tool: {root.tool}\n"
        f"- tool instance: {root.tool_instance}\n"
        f"- analysis mode: {root.analysis_mode}\n"
    )

    def _callback(target: Union[Analysis, Observable]):
        if isinstance(target, Analysis):
            if target.summary is not None and target.observable is not None:
                # by default the summary of the analysis is a record (if it has a summary)
                summary = f"{target.observable.type} {target.observable.display_value} {target.summary}"
                context_records.append(summary)

            for observable in target.observables:
                if target.observable is not None:
                    context_records.append(f"{target.display_name} observed {observable.type} {observable.display_value} while analyzing {target.observable.type} {target.observable.display_value}")
                else:
                    context_records.append(f"observed {observable.type} {observable.display_value}")

            for context_document in target.llm_context_documents:
                context_records.append(context_document)
            
        if isinstance(target, Observable):
            for context_document in target.llm_context_documents:
                context_records.append(context_document)

    # populate the list of context records
    recurse_tree(root, _callback)
    return context_records

def vectorize(target: Union[Alert, RootAnalysis]) -> list[str]:
    """Generates the vectors fo the given alert or root analysis and uploads them to Qdrant."""

    start = time.time()

    context_records = get_context_records(target)
    model = load_model(get_embedding_model())

    vectors = model.encode(context_records, show_progress_bar=False)
    #np.save("vectors.npy", vectors, allow_pickle=False)

    client = get_qdrant_client()
    if not client.collection_exists(collection_name=get_alert_collection_name()):
        client.create_collection(
            collection_name=get_alert_collection_name(),
            vectors_config=VectorParams(size=model.get_sentence_embedding_dimension(), distance=Distance.COSINE),
        )
        # a brand new collection is empty so this returns immediately
        create_root_uuid_index(client, wait=True)

    points = []
    for i, context_record in enumerate(context_records):
        points.append(
            PointStruct(
                id=_generate_point_id(target, context_record),
                vector=vectors[i].tolist(),
                payload={
                    ROOT_UUID_FIELD: target.uuid,
                    "text": context_record
                }
            )
        )

    # upload the current points BEFORE removing the stale ones. point ids are deterministic
    # (see _generate_point_id) so this is an idempotent upsert, and doing it in this order
    # means a failure part way through leaves the target with a mix of old and new points
    # rather than with none at all. wait=True so that a failed batch is not swallowed and
    # so the delete below runs against a known state.
    client.upload_points(
        collection_name=get_alert_collection_name(),
        points=points,
        wait=True,
    )

    # now remove any point still carrying this root_uuid that is not part of the current
    # analysis: context records that have disappeared since the last time we ran
    delete_result = client.delete(collection_name=get_alert_collection_name(), points_selector=FilterSelector(filter=Filter(
        must=[
            FieldCondition(
                key=ROOT_UUID_FIELD,
                match=MatchValue(value=target.uuid)
            ),
        ],
        must_not=[
            HasIdCondition(has_id=[point.id for point in points]),
        ],
    )), wait=True)

    if delete_result.status != UpdateStatus.COMPLETED:
        raise VectorizeError(f"stale point delete for {target.uuid} returned {delete_result.status}")

    end = time.time()
    logging.info(f"vectorized {target.uuid} ({len(points)} points) in {end - start} seconds")

    return context_records
