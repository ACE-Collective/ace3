"""Threat type schemas for ACE API v2."""

from pydantic import BaseModel


class ThreatTypeRead(BaseModel):
    id: int
    name: str


class ThreatTypeCreate(BaseModel):
    name: str


class ThreatTypeUpdate(BaseModel):
    name: str | None = None
