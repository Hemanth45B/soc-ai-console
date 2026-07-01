from typing import List, Optional
from pydantic import BaseModel


class LogEntry(BaseModel):
    timestamp: str
    source_ip: Optional[str] = None
    host: Optional[str] = None
    log_type: Optional[str] = None
    raw_log: str


class IngestRequest(BaseModel):
    logs: List[LogEntry]


class DecisionRequest(BaseModel):
    note: Optional[str] = None


class OverrideRequest(BaseModel):
    verdict: str
    note: Optional[str] = None
