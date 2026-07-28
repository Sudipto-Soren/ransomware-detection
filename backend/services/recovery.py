"""
backend/services/recovery.py

Copy-on-write version store — Objective 4 from the synopsis.

How it works:
  Before any file write is committed, we stash a copy of the
  CURRENT (clean) version in version-store/<filename>/<timestamp>/
  If ransomware is detected, we restore from the most recent
  pre-attack snapshot.

Why not VSS?
  Windows Volume Shadow Copy Service (VSS) is the production path
  and is mentioned in the synopsis. The report covers both:
    - VSS: OS-level, more comprehensive, Windows-only
    - This custom store: portable Python, cross-platform for dev
  The custom store is what runs in the demo; VSS integration is
  called out as the production upgrade path.

In a real deployment the kernel driver would call the version
store service on every WRITE interception, before allowing the
write to proceed. Here we simulate that flow.
"""

import json
import shutil
from datetime import datetime
from pathlib import Path

from config import VERSION_STORE_DIR


def ensure_dirs() -> None:
    VERSION_STORE_DIR.mkdir(parents=True, exist_ok=True)


def _version_dir(file_path: str) -> Path:
    """
    Returns the version store directory for a given file path.
    We flatten the path into a safe directory name.
    """
    safe_name = Path(file_path).name
    return VERSION_STORE_DIR / safe_name


def snapshot_file(file_path: str) -> dict:
    """
    Save a copy of the current file before it is written.
    Called by the monitor service whenever it sees a WRITE event.

    Returns a snapshot record dict.
    """
    ensure_dirs()
    src = Path(file_path)
    if not src.exists():
        return {"status": "skipped", "reason": "source file not found"}

    ts        = datetime.utcnow().strftime("%Y%m%dT%H%M%S%f")
    ver_dir   = _version_dir(file_path) / ts
    ver_dir.mkdir(parents=True, exist_ok=True)

    dest = ver_dir / src.name
    shutil.copy2(src, dest)

    record = {
        "original_path": str(src),
        "snapshot_path": str(dest),
        "snapshot_at":   datetime.utcnow().isoformat(),
        "size_bytes":    src.stat().st_size,
    }
    (ver_dir / "record.json").write_text(json.dumps(record, indent=2))
    return record


def list_snapshots(file_path: str) -> list[dict]:
    """Return all saved versions for a file, newest first."""
    ensure_dirs()
    ver_dir = _version_dir(file_path)
    if not ver_dir.exists():
        return []

    records = []
    for record_file in ver_dir.rglob("record.json"):
        try:
            records.append(json.loads(record_file.read_text()))
        except json.JSONDecodeError:
            pass
    return sorted(records, key=lambda r: r.get("snapshot_at", ""), reverse=True)


def restore_file(file_path: str) -> dict:
    """
    Restore the most recent clean snapshot for a single file.
    Returns the restore result dict.
    """
    snapshots = list_snapshots(file_path)
    if not snapshots:
        return {"status": "failed", "reason": f"No snapshots found for {file_path}"}

    latest   = snapshots[0]
    src      = Path(latest["snapshot_path"])
    dest     = Path(latest["original_path"])

    if not src.exists():
        return {"status": "failed", "reason": "Snapshot file missing from version store"}

    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)

    return {
        "status":           "success",
        "original_path":    str(dest),
        "restored_from":    str(src),
        "snapshot_at":      latest["snapshot_at"],
        "restored_at":      datetime.utcnow().isoformat(),
    }


def restore_session(session_id: str, affected_paths: list[str]) -> dict:
    """
    Restore all affected files for a session flagged as ransomware.
    This is what the dashboard's 'Restore' button triggers.
    """
    results      = []
    success_count = 0
    failed_count  = 0

    if not affected_paths:
        # If we don't have specific paths, restore everything in the version store
        ensure_dirs()
        affected_paths = [
            str(Path(d.name))               # approximate — real system tracks exact paths
            for d in VERSION_STORE_DIR.iterdir()
            if d.is_dir()
        ]

    for path in affected_paths:
        result = restore_file(path)
        results.append(result)
        if result.get("status") == "success":
            success_count += 1
        else:
            failed_count += 1

    summary = {
        "session_id":     session_id,
        "restored_at":    datetime.utcnow().isoformat(),
        "files_restored": success_count,
        "files_failed":   failed_count,
        "status":         "success" if failed_count == 0 else "partial",
        "details":        results,
    }

    print(f"[recovery] Session {session_id}: "
          f"{success_count} restored, {failed_count} failed")
    return summary


def get_store_stats() -> dict:
    """Summary of what's in the version store — for the dashboard."""
    ensure_dirs()
    dirs = [d for d in VERSION_STORE_DIR.iterdir() if d.is_dir()]
    total_versions = sum(
        len(list(d.rglob("record.json"))) for d in dirs
    )
    return {
        "tracked_files":  len(dirs),
        "total_versions": total_versions,
        "store_path":     str(VERSION_STORE_DIR),
    }
