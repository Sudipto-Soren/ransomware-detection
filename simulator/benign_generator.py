"""
benign_generator.py — realistic user file-activity simulator.

What it teaches your model (by contrast with ransomware_pattern_generator.py):
  ┌─────────────────────────┬──────────────────────────────┐
  │ Feature                 │ Benign signature              │
  ├─────────────────────────┼──────────────────────────────┤
  │ files modified/sec      │ < 0.5  (human pace)           │
  │ overwrite ratio         │ low    (mostly reads/appends) │
  │ extension changes       │ none                          │
  │ directory access spread │ scattered, NOT sorted         │
  │ entropy delta           │ near zero (content stays sim) │
  │ sequential pattern      │ absent                        │
  └─────────────────────────┴──────────────────────────────┘

Session label: 0  (benign)

Usage:
  python benign_generator.py \\
      --sandbox  ./test-sandbox \\
      --log      ./logs/events.ndjson \\
      --duration 120

  # or let run_dataset_collection.sh call it automatically
"""

import argparse
import random
import sys
import time
import uuid
from pathlib import Path

# Allow running as: python benign_generator.py (not just python -m ...)
sys.path.insert(0, str(Path(__file__).parent))
from utils.event_logger import EventLogger, make_event

LABEL = 0   # ground truth for this generator

# ─── Operation mix ────────────────────────────────────────────────────────────
# READ 60% / WRITE(append) 30% / RENAME 10%
# Humans mostly read; occasional edits; rare renames.
_OPS    = ["read", "write", "rename"]
_WEIGHTS = [0.60,   0.30,   0.10]


# ─── Individual operations ────────────────────────────────────────────────────

def _do_read(fpath: Path, session_id: str, logger: EventLogger) -> None:
    """Simulate opening and reading a file."""
    try:
        _ = fpath.read_bytes()          # triggers an actual OS read
        ext = fpath.suffix
        logger.log(make_event(
            operation="READ",
            file_path=str(fpath),
            session_id=session_id,
            label=LABEL,
            file_extension_before=ext,
            file_extension_after=ext,
            file_size_bytes=fpath.stat().st_size,
        ))
    except (PermissionError, FileNotFoundError, OSError):
        pass


def _do_write(fpath: Path, session_id: str, logger: EventLogger) -> None:
    """
    Simulate editing a file — appends a small timestamped note.
    Appending (not overwriting) keeps overwrite_ratio low for benign
    sessions, which is exactly the contrast the model needs to learn.
    """
    try:
        ext = fpath.suffix
        edit = f"\n[edit {time.time():.3f}]\n".encode()
        with open(fpath, "ab") as f:
            f.write(edit)
        logger.log(make_event(
            operation="WRITE",
            file_path=str(fpath),
            session_id=session_id,
            label=LABEL,
            file_extension_before=ext,
            file_extension_after=ext,    # extension unchanged
            file_size_bytes=fpath.stat().st_size,
        ))
    except (PermissionError, FileNotFoundError, OSError):
        pass


def _do_rename(fpath: Path, session_id: str, logger: EventLogger) -> None:
    """
    Rename a file — same extension.
    Real users rename "draft_v1.docx" → "draft_v2.docx", not
    "document.docx" → "document.docx.locked".
    """
    try:
        ext = fpath.suffix
        new_path = fpath.parent / f"renamed_{random.randint(1000, 9999)}{ext}"
        if new_path.exists():
            return
        logger.log(make_event(
            operation="RENAME",
            file_path=str(fpath),
            session_id=session_id,
            label=LABEL,
            file_extension_before=ext,
            file_extension_after=ext,   # extension unchanged — key distinction
            file_size_bytes=fpath.stat().st_size,
        ))
        fpath.rename(new_path)
    except (PermissionError, FileNotFoundError, OSError):
        pass


# ─── Session runner ───────────────────────────────────────────────────────────

def run_session(
    sandbox: Path,
    session_id: str,
    log_path: Path,
    duration_seconds: int,
) -> None:
    ops_done = 0
    end_time = time.time() + duration_seconds

    print(f"[benign] {session_id} | {duration_seconds}s | {sandbox}")

    with EventLogger(log_path) as logger:
        while time.time() < end_time:
            all_files = [f for f in sandbox.rglob("*") if f.is_file()]
            if not all_files:
                break

            # KEY POINT: random.choice — scattered, not sorted.
            # Compare with ransomware_pattern_generator which uses sorted().
            fpath = random.choice(all_files)
            op    = random.choices(_OPS, weights=_WEIGHTS, k=1)[0]

            if   op == "read":   _do_read(fpath, session_id, logger)
            elif op == "write":  _do_write(fpath, session_id, logger)
            elif op == "rename": _do_rename(fpath, session_id, logger)

            ops_done += 1

            # Human-like pause: variable, never machine-fast.
            # This is the single most distinguishing benign feature.
            time.sleep(random.uniform(0.5, 8.0))

    rate = ops_done / duration_seconds if duration_seconds else 0
    print(f"[benign] Done. {ops_done} ops in {duration_seconds}s "
          f"→ {rate:.2f} ops/sec  (expect < 2.0)")


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benign file-activity simulator")
    parser.add_argument("--sandbox",    required=True, type=Path)
    parser.add_argument("--log",        required=True, type=Path)
    parser.add_argument("--session-id", default=None,  type=str)
    parser.add_argument("--duration",   default=120,   type=int,
                        help="Session duration in seconds (default 120)")
    args = parser.parse_args()

    if not args.sandbox.exists():
        print(f"Sandbox not found: {args.sandbox}. Run create_sandbox.py first.")
        sys.exit(1)

    session_id = args.session_id or f"benign-{uuid.uuid4().hex[:8]}"
    run_session(args.sandbox, session_id, args.log, args.duration)
