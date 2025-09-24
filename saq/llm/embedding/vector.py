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
import numpy as np

from qdrant_client import QdrantClient
from qdrant_client.models import FieldCondition, Filter, MatchValue, UpdateStatus, VectorParams, Distance

from saq.configuration.config import get_config_value
from saq.constants import CONFIG_LLM, CONFIG_LLM_EMBEDDING_MODEL, CONFIG_QDRANT, CONFIG_QDRANT_COLLECTION_ALERTS, CONFIG_QDRANT_URL
from saq.database.model import Alert, Comment
from saq.database.pool import get_db
from saq.llm.embedding.model import load_model

def _generate_point_id(root: RootAnalysis, context_document: str) -> str:
    key = f"{root.storage_dir}/{context_document}"
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    return str(uuid.UUID(bytes=digest[:16]))

def get_embedding_model() -> str:
    """Returns the configured embedding model name."""
    return get_config_value(CONFIG_LLM, CONFIG_LLM_EMBEDDING_MODEL)

def get_alert_collection_name() -> str:
    """Returns the configured collection name for ace3 alert data."""
    return get_config_value(CONFIG_QDRANT, CONFIG_QDRANT_COLLECTION_ALERTS)

def clear_vectors():
    """Clears ALL vectors fro Qrant for the ace collection."""
    client = QdrantClient(url=get_config_value(CONFIG_QDRANT, CONFIG_QDRANT_URL))
    if client.collection_exists(collection_name=get_alert_collection_name()):
        client.delete_collection(collection_name=get_alert_collection_name())

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

    client = QdrantClient(url=get_config_value(CONFIG_QDRANT, CONFIG_QDRANT_URL))
    if not client.collection_exists(collection_name=get_alert_collection_name()):
        client.create_collection(
            collection_name=get_alert_collection_name(),
            vectors_config=VectorParams(size=model.get_sentence_embedding_dimension(), distance=Distance.COSINE),
        )

    # remove all the existing points for this target
    delete_result = client.delete(collection_name=get_alert_collection_name(), points_selector=FilterSelector(filter=Filter(must=[
        FieldCondition(
            key="root_uuid",
            match=MatchValue(value=target.uuid)
        ),
    ])), wait=True)

    assert delete_result.status == UpdateStatus.COMPLETED

    # make sure all existing points for this target are deleted
    count_result = client.count(collection_name=get_alert_collection_name(), count_filter=Filter(must=[
        FieldCondition(
            key="root_uuid",
            match=MatchValue(value=target.uuid)
        ),
    ]))

    assert count_result.count == 0, f"count_result is {count_result.count} for target {target.uuid}"

    points = []
    for i, context_record in enumerate(context_records):
        from qdrant_client.models import PointStruct
        points.append(
            PointStruct(
                id=_generate_point_id(target, context_record),
                vector=vectors[i].tolist(),
                payload={
                    "root_uuid": target.uuid,
                    "text": context_record
                }
            )
        )

    client.upload_points(
        collection_name=get_config_value(CONFIG_QDRANT, CONFIG_QDRANT_COLLECTION_ALERTS),
        points=points
    )

    end = time.time()
    logging.info(f"vectorized {target.uuid} in {end - start} seconds")

    return context_records
