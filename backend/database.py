"""
backend/database.py

Database setup using SQLAlchemy ORM.

Three tables:
  sessions       — one row per ingested monitoring session
  threats        — one row per session flagged as ransomware
  recovery_actions — one row per restore operation performed

Why SQLite for dev?
  Zero setup. The file (ransomdb.sqlite) is created automatically
  the first time the app starts. Switch to PostgreSQL by setting
  DB_URL in your .env before deploying.
"""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from config import DB_URL

# ─── Engine ───────────────────────────────────────────────────────────────────
# check_same_thread=False is SQLite-specific: needed because FastAPI
# runs handlers on different threads. Has no effect on PostgreSQL.
connect_args = {"check_same_thread": False} if DB_URL.startswith("sqlite") else {}
engine = create_engine(DB_URL, connect_args=connect_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


# ─── ORM models ───────────────────────────────────────────────────────────────

class MonitoredSession(Base):
    """
    One row per monitoring session — either a simulator run or a
    real process monitored by the kernel driver.
    Stores the aggregated feature vector alongside the ML verdict.
    """
    __tablename__ = "sessions"

    id                    = Column(Integer, primary_key=True, index=True)
    session_id            = Column(String, unique=True, index=True)
    process_name          = Column(String, nullable=True)
    pid                   = Column(Integer, nullable=True)
    source                = Column(String, default="simulator")  # or kernel_driver
    ingested_at           = Column(DateTime, default=datetime.utcnow)

    # ── Feature vector ────────────────────────────────────────────────────────
    session_duration_sec  = Column(Float, default=0)
    total_events          = Column(Integer, default=0)
    write_count           = Column(Integer, default=0)
    read_count            = Column(Integer, default=0)
    rename_count          = Column(Integer, default=0)
    delete_count          = Column(Integer, default=0)
    files_modified_per_sec = Column(Float, default=0)
    unique_files_touched  = Column(Integer, default=0)
    unique_dirs_touched   = Column(Integer, default=0)
    overwrite_ratio       = Column(Float, default=0)
    extension_change_count = Column(Integer, default=0)
    extension_change_ratio = Column(Float, default=0)
    mean_entropy_delta    = Column(Float, default=0)
    max_entropy_delta     = Column(Float, default=0)
    sequential_score      = Column(Float, default=0)
    max_files_per_10sec   = Column(Integer, default=0)

    # ── ML verdict ────────────────────────────────────────────────────────────
    is_ransomware         = Column(Boolean, default=False)
    risk_score            = Column(Float, default=0.0)   # 0–100
    true_label            = Column(Integer, nullable=True)  # 0/1 if known (lab)


class Threat(Base):
    """
    One row per session flagged as ransomware.
    Used by the dashboard's threats table.
    """
    __tablename__ = "threats"

    id              = Column(Integer, primary_key=True, index=True)
    session_id      = Column(String, index=True)
    process_name    = Column(String, nullable=True)
    pid             = Column(Integer, nullable=True)
    detected_at     = Column(DateTime, default=datetime.utcnow)
    risk_score      = Column(Float)
    files_affected  = Column(Integer, default=0)
    status          = Column(String, default="active")  # active / quarantined / recovered
    notes           = Column(Text, nullable=True)


class RecoveryAction(Base):
    """
    One row per restore operation — tracks what was recovered, when, and status.
    """
    __tablename__ = "recovery_actions"

    id              = Column(Integer, primary_key=True, index=True)
    session_id      = Column(String, index=True)
    triggered_at    = Column(DateTime, default=datetime.utcnow)
    files_restored  = Column(Integer, default=0)
    status          = Column(String, default="pending")  # pending / success / failed
    notes           = Column(Text, nullable=True)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def create_tables() -> None:
    """Create all tables if they don't exist yet."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """
    FastAPI dependency — yields a database session and closes it after
    the request completes (even if an exception is raised).

    Usage in a route:
        @router.get("/something")
        def my_route(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
