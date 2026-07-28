"""
backend/main.py

FastAPI application — the central API server.

Endpoints:
  GET  /api/status                  — system health, model loaded, counts
  GET  /api/stats                   — summary stats for dashboard cards
  POST /api/sessions/ingest         — receive events, run inference, store result
  GET  /api/sessions                — list all monitored sessions
  GET  /api/threats                 — list detected ransomware sessions
  POST /api/recovery/restore/{id}   — trigger rollback for a session
  GET  /api/recovery/actions        — list all restore operations
  GET  /api/cloud/quarantine        — list quarantined files
  GET  /api/cloud/staging           — list files pending sync
  POST /api/cloud/staging/add       — simulate a file entering the sync folder
  GET  /docs                        — auto-generated Swagger UI (free from FastAPI)

Run:
  cd backend
  uvicorn main:app --reload --port 8000

Then open: http://localhost:8000/docs
"""

from datetime import datetime, timedelta

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

import database as db
import schemas
from config import RISK_THRESHOLD
from services import cloud, detection, recovery

# ─── App setup ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Ransomware Detection API",
    description=(
        "AI-Assisted Cloud-Aware Kernel-Level Ransomware Detection System — "
        "Batch B31, SIT Tumakuru"
    ),
    version="1.0.0",
)

# CORS: allow the React dashboard (localhost:5173 = Vite default) to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    """Runs once when the server starts."""
    db.create_tables()
    ok = detection.load_model()
    if not ok:
        print("[startup] ⚠  Running without a model — ingest will return risk_score=0")
    cloud.ensure_dirs()
    recovery.ensure_dirs()
    print("[startup] ✓  API ready at http://localhost:8000/docs")


# ─── Status & stats ───────────────────────────────────────────────────────────

@app.get("/api/status", response_model=schemas.DashboardStatus)
def get_status(session: Session = Depends(db.get_db)):
    """System health check — the dashboard polls this every few seconds."""
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    return {
        "model_loaded":       detection.is_loaded(),
        "model_name":         detection.get_model_name(),
        "total_sessions":     session.query(db.MonitoredSession).count(),
        "total_threats":      session.query(db.Threat).count(),
        "active_threats":     session.query(db.Threat).filter(db.Threat.status == "active").count(),
        "sessions_last_hour": session.query(db.MonitoredSession)
                                     .filter(db.MonitoredSession.ingested_at >= one_hour_ago)
                                     .count(),
        "monitoring_active":  True,  # always true while the server is running
    }


@app.get("/api/stats", response_model=schemas.StatsOut)
def get_stats(session: Session = Depends(db.get_db)):
    """Summary statistics for the dashboard's metric cards."""
    sessions_all = session.query(db.MonitoredSession).all()
    benign       = [s for s in sessions_all if not s.is_ransomware]
    ransomware   = [s for s in sessions_all if s.is_ransomware]

    avg_risk = (
        sum(s.risk_score for s in sessions_all) / len(sessions_all)
        if sessions_all else 0.0
    )

    # Top processes by number of sessions
    from collections import Counter
    proc_counts = Counter(s.process_name for s in sessions_all if s.process_name)
    top = [{"process": p, "sessions": c} for p, c in proc_counts.most_common(5)]

    return {
        "total_sessions":      len(sessions_all),
        "total_threats":       len(ransomware),
        "benign_sessions":     len(benign),
        "ransomware_sessions": len(ransomware),
        "avg_risk_score":      round(avg_risk, 1),
        "top_processes":       top,
    }


# ─── Session ingest ───────────────────────────────────────────────────────────

@app.post("/api/sessions/ingest", response_model=schemas.SessionIngestResponse)
def ingest_session(
    body: schemas.SessionIngest,
    db_session: Session = Depends(db.get_db),
):
    """
    Receive all events for one monitoring session.
    Runs feature extraction + ML inference + stores the result.
    If ransomware is detected, triggers cloud protection and recovery.

    This is the endpoint the monitor service (or the simulator replay
    script) calls after collecting events for one time window.
    """
    raw_events = [e.model_dump() for e in body.events]
    session_id = raw_events[0].get("session_id", "unknown")

    # Check for duplicate session
    existing = db_session.query(db.MonitoredSession).filter_by(session_id=session_id).first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Session {session_id} already ingested",
        )

    # ── ML inference ──────────────────────────────────────────────────────────
    verdict = detection.predict(raw_events)
    features = verdict.get("features", {})

    process_name = raw_events[0].get("process_name", "unknown")
    pid          = raw_events[0].get("pid")
    source       = raw_events[0].get("source", "simulator")
    true_label   = raw_events[0].get("label")      # present for labeled simulator runs

    # ── Store in database ─────────────────────────────────────────────────────
    record = db.MonitoredSession(
        session_id=session_id,
        process_name=process_name,
        pid=pid,
        source=source,
        is_ransomware=verdict["is_ransomware"],
        risk_score=verdict["risk_score"],
        true_label=int(true_label) if true_label is not None else None,
        **{k: features.get(k, 0) for k in [
            "session_duration_sec", "total_events", "write_count", "read_count",
            "rename_count", "delete_count", "files_modified_per_sec",
            "unique_files_touched", "unique_dirs_touched", "overwrite_ratio",
            "extension_change_count", "extension_change_ratio",
            "mean_entropy_delta", "max_entropy_delta",
            "sequential_score", "max_files_per_10sec",
        ]},
    )
    db_session.add(record)

    # ── If ransomware detected ────────────────────────────────────────────────
    if verdict["is_ransomware"]:
        # 1. Log threat
        threat = db.Threat(
            session_id=session_id,
            process_name=process_name,
            pid=pid,
            risk_score=verdict["risk_score"],
            files_affected=features.get("unique_files_touched", 0),
            status="active",
        )
        db_session.add(threat)

        # 2. Quarantine any staged cloud files
        cloud.quarantine_session(session_id, process_name, verdict["risk_score"])

        print(f"[ingest] ⚠  RANSOMWARE DETECTED — {session_id} "
              f"(risk {verdict['risk_score']:.0f}/100, process: {process_name})")
    else:
        print(f"[ingest] ✓  Benign — {session_id} "
              f"(risk {verdict['risk_score']:.0f}/100, process: {process_name})")

    db_session.commit()

    return {
        "session_id":    session_id,
        "process_name":  process_name,
        "is_ransomware": verdict["is_ransomware"],
        "risk_score":    verdict["risk_score"],
        "features":      features,
        "message": (
            "🚨 Ransomware pattern detected. Cloud sync blocked. "
            "Use POST /api/recovery/restore/{session_id} to rollback."
            if verdict["is_ransomware"] else
            "✅ Session classified as benign."
        ),
    }


# ─── Sessions & threats ───────────────────────────────────────────────────────

@app.get("/api/sessions", response_model=list[schemas.SessionOut])
def list_sessions(
    limit: int = 50,
    session: Session = Depends(db.get_db),
):
    return (
        session.query(db.MonitoredSession)
        .order_by(db.MonitoredSession.ingested_at.desc())
        .limit(limit)
        .all()
    )


@app.get("/api/threats", response_model=list[schemas.ThreatOut])
def list_threats(
    status: str = None,
    session: Session = Depends(db.get_db),
):
    q = session.query(db.Threat).order_by(db.Threat.detected_at.desc())
    if status:
        q = q.filter(db.Threat.status == status)
    return q.limit(100).all()


# ─── Recovery ─────────────────────────────────────────────────────────────────

@app.post("/api/recovery/restore/{session_id}")
def restore_session(
    session_id: str,
    db_session: Session = Depends(db.get_db),
):
    """
    Trigger rollback for a flagged session.
    This is what the dashboard's 'Restore' button calls.
    """
    threat = db_session.query(db.Threat).filter_by(session_id=session_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail=f"No threat found for session {session_id}")

    result = recovery.restore_session(session_id, affected_paths=[])

    # Log the recovery action
    action = db.RecoveryAction(
        session_id=session_id,
        files_restored=result["files_restored"],
        status=result["status"],
        notes=f"Triggered via dashboard. {result['files_failed']} files failed.",
    )
    db_session.add(action)

    # Update threat status
    threat.status = "recovered"
    db_session.commit()

    return result


@app.get("/api/recovery/actions", response_model=list[schemas.RecoveryActionOut])
def list_recovery_actions(session: Session = Depends(db.get_db)):
    return (
        session.query(db.RecoveryAction)
        .order_by(db.RecoveryAction.triggered_at.desc())
        .limit(50)
        .all()
    )


# ─── Cloud protection ─────────────────────────────────────────────────────────

@app.get("/api/cloud/quarantine")
def list_quarantine():
    return cloud.list_quarantined()


@app.get("/api/cloud/staging")
def list_staging():
    return {"files": cloud.get_staging_files()}


@app.post("/api/cloud/staging/add")
def add_to_staging(filename: str, content: str = "dummy file content"):
    """
    Simulate a file being queued for cloud upload.
    Used by the demo replay script.
    """
    cloud.add_to_staging(filename, content.encode())
    return {"status": "added", "file": filename}


# ─── Root ─────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "project": "AI-Assisted Ransomware Detection System",
        "batch":   "B31 — SIT Tumakuru",
        "docs":    "/docs",
        "status":  "/api/status",
    }
