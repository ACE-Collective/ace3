"""Observable type schemas for ACE API v2."""

from pydantic import BaseModel


class ObservableTypeRead(BaseModel):
    """Response model for reading an observable type."""

    name: str


# Future schemas for CRUD operations:
#
# class ObservableTypeCreate(BaseModel):
#     """Request model for creating an observable type."""
#     name: str
#     description: str | None = None
#
# class ObservableTypeUpdate(BaseModel):
#     """Request model for updating an observable type."""
#     description: str | None = None
