"""
utils/event_logger.py — shared event factory and logger.

Both generators (benign and ransomware-pattern) import this.
Every event they emit conforms to docs/event-schema.json so that
feature-extraction/ and the real kernel driver output are
interchangeable downstream.

One event = one file-system operation.
One session = one generator run, identified by session_id.
The session_id is how feature-extraction groups events into
per-process time-windows and assigns a single label to the whole batch.
"""

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psutil


def _get_process_info() -> tuple[str, str | None]:
    """
    Returns (process_name, process_path) for the current process.
    Wrapped in a try/except because psutil.Process().exe() can raise
    AccessDenied on some macOS/Linux configs — we degrade gracefully.
    """
    try:
        proc = psutil.Process()
        exe_path = proc.exe()
        return Path(exe_path).name, exe_path
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        # Fall back to the Python interpreter name
        return Path(sys.executable).name, sys.executable


def make_event(
    operation: str,
    file_path: str,
    session_id: str,
    label: int,                          # 0 = benign, 1 = ransomware-pattern
    file_extension_before: str | None = None,
    file_extension_after:  str | None = None,
    file_size_bytes:       int | None = None,
    source: str = "simulator",
    extra: dict | None = None,           # for any bonus fields (e.g. entropy)
) -> dict:
    """
    Build one schema-conforming event dict.

    `extra` lets individual generators attach additional fields
    (e.g. entropy_before / entropy_after) without breaking the shared contract.
    """
    process_name, process_path = _get_process_info()
    event = {
        "event_id":              str(uuid.uuid4()),
        "session_id":            session_id,
        "timestamp":             datetime.now(timezone.utc).isoformat(),
        "pid":                   os.getpid(),
        "process_name":          process_name,
        "process_path":          process_path,
        "operation":             operation,
        "file_path":             str(file_path),
        "file_extension_before": file_extension_before,
        "file_extension_after":  file_extension_after,
        "file_size_bytes":       file_size_bytes,
        "source":                source,
        "label":                 label,
    }
    if extra:
        event.update(extra)
    return event


class EventLogger:
    """
    Appends events to a newline-delimited JSON (NDJSON) file.

    NDJSON means one JSON object per line — easy to stream, easy to
    read back with pandas.read_json(lines=True) or a simple for-loop.
    It's also append-friendly, so multiple sessions can write to the
    same log file without any locking overhead.
    """

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.log_path, "a", encoding="utf-8")

    def log(self, event: dict) -> None:
        self._fh.write(json.dumps(event) + "\n")
        self._fh.flush()   # flush per event so data isn't lost on a crash

    def close(self) -> None:
        self._fh.close()

    # Context-manager support: with EventLogger(...) as logger: logger.log(...)
    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
