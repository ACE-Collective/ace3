"""Alert search: a hybrid (dense + sparse + exact) index over alerts backed by qdrant and mysql.

See docs/SEARCH.md. This package deliberately does not import the embedding model at import
time: every ACE process imports saq.search.tasks (to submit index tasks) and only the indexer
service, the CLI and the API/GUI query paths ever load the model.
"""

from saq.search.tasks import submit_delete_task, submit_index_task, submit_payload_task
from saq.search.types import (
    AlertSearchResult,
    SearchFilters,
    SearchHit,
    SearchRequest,
    SearchResponse,
)

__all__ = [
    "AlertSearchResult",
    "SearchFilters",
    "SearchHit",
    "SearchRequest",
    "SearchResponse",
    "submit_delete_task",
    "submit_index_task",
    "submit_payload_task",
]
