"""
backend/services/cloud.py

Simulates a cloud-aware protection layer.

In production this would hook into:
  - OneDrive:  Microsoft Graph API (file activity webhooks)
  - Dropbox:   Dropbox API v2 (list_folder/longpoll)
  - Google Drive: Drive API push notifications

For the demo / academic project, we simulate the same logic
using local folders:
  sync-staging/  ← files waiting to be uploaded (monitored)
  quarantine/    ← files blocked from upload (moved here)

When the ML model flags a session as ransomware:
  1. All files currently in sync-staging/ are moved to quarantine/
  2. A quarantine manifest is written (what was quarantined, when, why)
  3. The dashboard shows the quarantined files list

This prevents ransomware-encrypted files from overwriting
the legitimate cloud backup — exactly Objective 3 from the synopsis.
"""

import json
import shutil
from datetime import datetime
from pathlib import Path

from config import QUARANTINE_DIR, SYNC_STAGING_DIR


def ensure_dirs() -> None:
    SYNC_STAGING_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)


def add_to_staging(file_path: str, content: bytes = b"dummy") -> Path:
    """
    Simulate a file being queued for cloud upload.
    In a real system, the cloud client's local sync folder fills
    this role — we replicate that with a local staging folder.
    """
    ensure_dirs()
    dest = SYNC_STAGING_DIR / Path(file_path).name
    dest.write_bytes(content)
    return dest


def quarantine_session(session_id: str, process_name: str, risk_score: float) -> dict:
    """
    Move all files currently in sync-staging/ to quarantine/.
    Returns a manifest of what was quarantined.
    """
    ensure_dirs()
    staged_files = list(SYNC_STAGING_DIR.iterdir())

    if not staged_files:
        return {
            "session_id":        session_id,
            "quarantined_count": 0,
            "files":             [],
            "timestamp":         datetime.utcnow().isoformat(),
            "note":              "No files were in the sync staging folder",
        }

    quarantine_session_dir = QUARANTINE_DIR / session_id
    quarantine_session_dir.mkdir(parents=True, exist_ok=True)

    quarantined = []
    for f in staged_files:
        dest = quarantine_session_dir / f.name
        shutil.move(str(f), str(dest))
        quarantined.append(str(dest))

    # Write a manifest so investigators know why these files were blocked
    manifest = {
        "session_id":        session_id,
        "process_name":      process_name,
        "risk_score":        risk_score,
        "quarantined_at":    datetime.utcnow().isoformat(),
        "quarantined_count": len(quarantined),
        "files":             quarantined,
        "reason":            "ML model flagged session as ransomware pattern",
    }
    manifest_path = quarantine_session_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    print(f"[cloud] Quarantined {len(quarantined)} files for session {session_id}")
    return manifest


def list_quarantined() -> list[dict]:
    """Return all quarantine manifests — for the dashboard's cloud-protection panel."""
    ensure_dirs()
    manifests = []
    for manifest_file in QUARANTINE_DIR.rglob("manifest.json"):
        try:
            manifests.append(json.loads(manifest_file.read_text()))
        except json.JSONDecodeError:
            pass
    return sorted(manifests, key=lambda m: m.get("quarantined_at", ""), reverse=True)


def get_staging_files() -> list[str]:
    """List files currently pending in the sync staging folder."""
    ensure_dirs()
    return [f.name for f in SYNC_STAGING_DIR.iterdir() if f.is_file()]
