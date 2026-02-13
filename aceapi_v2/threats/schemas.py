"""Threat (malware-threat mapping) schemas for ACE API v2."""

from pydantic import BaseModel


class ThreatRead(BaseModel):
    malware_id: int
    threat_type_id: int
    threat_type_name: str


class ThreatCreate(BaseModel):
    malware_id: int
    threat_type_id: int
