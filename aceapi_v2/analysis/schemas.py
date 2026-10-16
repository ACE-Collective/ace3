"""Schemas for the analysis API (ACE API v2)."""

from pydantic import BaseModel, Field


class SubmitResult(BaseModel):
    uuid: str = Field(description="the uuid of the new root (and of its alert, in correlation mode)")
