"""Base schema definitions for ACE API v2."""

from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class ListResponse(BaseModel, Generic[T]):
    """Generic wrapper for list responses.

    Wrapping list responses in an object allows adding metadata
    (like pagination) without breaking API compatibility.

    Example response:
        {"data": [{"name": "ipv4"}, {"name": "domain"}]}

    Future extension:
        {"data": [...], "total": 150, "page": 1, "per_page": 50}
    """

    data: list[T]
