"""Observable comment schemas for ACE API v2."""

from datetime import datetime

from pydantic import BaseModel, Field


class ObservableCommentRead(BaseModel):
    id: int
    insert_date: datetime
    edited_at: datetime | None = Field(description="when the text last changed; null if never edited")
    user_id: int
    user_display_name: str
    observable_id: int
    comment: str


class ObservableCommentCreate(BaseModel):
    observable_type: str
    observable_value: str
    comment: str


class ObservableCommentUpdate(BaseModel):
    comment: str
