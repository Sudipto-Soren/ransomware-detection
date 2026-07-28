"""
backend/schemas.py

Pydantic models for API request/response validation.

FastAPI uses these to:
  - Validate incoming JSON (400 if a required field is missing)
  - Serialize outgoing JSON (automatic, no manual .dict() calls)
  - Generate the OpenAPI spec shown at /docs
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ─── Raw event (matches docs/event-schema.json) ───────────────────────────────

class RawEvent(BaseModel):
    event_id:              str
    session_id:            str
    timestamp:             str
    pid:                   int
    process_name:          str
    process_path:          Optional[str] = None
    operation:             str
    file_path:             str
    file_extension_before: Optional[str] = None
    file_extension_after:  Optional[str] = None
    file_size_bytes:       Optional[int] = None
    source:                str = "simulator"
    label:                 Optional[int] = None
    entropy_before:        Optional[float] = None
    entropy_after:         Optional[float] = None
    entropy_delta:         Optional[float] = None


# ─── Session ingest ───────────────────────────────────────────────────────────

class SessionIngest(BaseModel):
    """
    Body for POST /api/sessions/ingest.
    Send all events for one session in one request.
    The backend extracts features, runs inference, stores the result.
    """
    events: list[RawEvent] = Field(
        ..., min_length=1, description="All events for this session"
    )


class SessionIngestResponse(BaseModel):
    session_id:    str
    process_name:  Optional[str]
    is_ransomware: bool
    risk_score:    float          # 0–100
    features:      dict           # the extracted feature vector
    message:       str


# ─── Session / threat read models ─────────────────────────────────────────────

class SessionOut(BaseModel):
    id:                    int
    session_id:            str
    process_name:          Optional[str]
    pid:                   Optional[int]
    source:                str
    ingested_at:           datetime
    files_modified_per_sec: float
    overwrite_ratio:       float
    extension_change_ratio: float
    sequential_score:      float
    is_ransomware:         bool
    risk_score:            float

    class Config:
        from_attributes = True   # allow ORM objects directly


class ThreatOut(BaseModel):
    id:             int
    session_id:     str
    process_name:   Optional[str]
    pid:            Optional[int]
    detected_at:    datetime
    risk_score:     float
    files_affected: int
    status:         str
    notes:          Optional[str]

    class Config:
        from_attributes = True


class RecoveryActionOut(BaseModel):
    id:              int
    session_id:      str
    triggered_at:    datetime
    files_restored:  int
    status:          str
    notes:           Optional[str]

    class Config:
        from_attributes = True


# ─── Dashboard summary ────────────────────────────────────────────────────────

class DashboardStatus(BaseModel):
    model_loaded:        bool
    model_name:          str
    total_sessions:      int
    total_threats:       int
    active_threats:      int
    sessions_last_hour:  int
    monitoring_active:   bool


class StatsOut(BaseModel):
    total_sessions:      int
    total_threats:       int
    benign_sessions:     int
    ransomware_sessions: int
    avg_risk_score:      float
    top_processes:       list[dict]
