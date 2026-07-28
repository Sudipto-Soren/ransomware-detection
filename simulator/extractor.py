"""
feature_extraction/extractor.py

Converts the raw NDJSON event log produced by the simulator into a
labeled CSV of feature vectors — one row per session.

That CSV is what the ML model trains and evaluates on.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WHY ONE ROW PER SESSION (not per event)?

Your model classifies PROCESSES, not individual file operations.
A single WRITE event tells you almost nothing. But "this process
wrote 60 files per second, changed every extension, accessed
directories in sorted order, and had a positive entropy delta
across all written files" — that tells you a lot.

Aggregating per session is exactly what the Windows kernel driver
will do in the final system: it watches a process for a rolling
time window and feeds the aggregate features to the model for
a verdict.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Features extracted (explained in FEATURE_GUIDE below):
  session_id, label,
  session_duration_sec, total_events,
  write_count, read_count, rename_count, delete_count,
  files_modified_per_sec, unique_files_touched, unique_dirs_touched,
  overwrite_ratio, extension_change_count, extension_change_ratio,
  mean_entropy_delta, max_entropy_delta,
  sequential_score, max_files_per_10sec

Usage:
  python extractor.py --log ../simulator/logs/events.ndjson
  python extractor.py --log ../simulator/logs/events.ndjson --out ./output/features.csv
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

# ─── Constants ────────────────────────────────────────────────────────────────

FEATURE_GUIDE = """
Feature Reference
─────────────────────────────────────────────────────────────────
session_duration_sec
    Time from the first to the last event in the session (seconds).
    Benign: long (human pace). Ransomware: short (machine pace).

files_modified_per_sec
    WRITE events / session_duration_sec.
    The single strongest feature. Ransomware modifies files orders
    of magnitude faster than any human.

overwrite_ratio
    WRITE / (WRITE + READ). A human mostly reads.
    Ransomware almost only writes.

extension_change_count / extension_change_ratio
    Number/proportion of RENAME events where extension_before ≠
    extension_after. Ransomware's defining move: .docx → .docx.locked.
    Benign renames keep the same extension.

sequential_score
    Spearman rank correlation between the order files were accessed
    and their alphabetical sort order. Range [-1, 1].
    Ransomware iterates the filesystem sorted → score ≈ 1.
    Humans access files randomly → score ≈ 0.

mean_entropy_delta / max_entropy_delta
    Average / maximum change in Shannon entropy (bits/byte) of files
    after a WRITE. Near zero for human edits (text stays text).
    Positive for the XOR transform (shifts byte distribution).

max_files_per_10sec
    Maximum number of WRITE operations in any rolling 10-second
    window. Captures burst behavior that a session-level average
    might smooth over.

unique_dirs_touched
    Number of distinct parent directories touched.
    Ransomware walks every directory; humans stay in one or two.
─────────────────────────────────────────────────────────────────
"""


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _parse_ts(iso: str) -> float:
    """ISO 8601 timestamp → Unix epoch float (seconds)."""
    try:
        return datetime.fromisoformat(iso).timestamp()
    except (ValueError, TypeError):
        return 0.0


def _spearman_r(x: list[float], y: list[float]) -> float:
    """
    Spearman rank correlation — how monotonically related x and y are.
    We use this to measure sequential_score without needing scipy.
    """
    n = len(x)
    if n < 3:
        return 0.0
    rx = np.argsort(np.argsort(x)).astype(float)
    ry = np.argsort(np.argsort(y)).astype(float)
    rx -= rx.mean()
    ry -= ry.mean()
    denom = np.sqrt((rx ** 2).sum()) * np.sqrt((ry ** 2).sum())
    return float(np.dot(rx, ry) / denom) if denom > 0 else 0.0


def _max_in_window(timestamps: list[float], window_sec: float = 10.0) -> int:
    """
    Sliding-window max: how many timestamps fall in any window_sec span?
    Used for max_files_per_10sec — captures burst intensity.
    """
    if not timestamps:
        return 0
    ts = sorted(timestamps)
    max_count = 0
    left = 0
    for right in range(len(ts)):
        while ts[right] - ts[left] > window_sec:
            left += 1
        max_count = max(max_count, right - left + 1)
    return max_count


# ─── Per-session feature extraction ───────────────────────────────────────────

def extract_session_features(events: list[dict]) -> dict:
    """
    Takes all events for one session and returns a feature dict.
    Each event is one dict from the NDJSON log.
    """
    if not events:
        return {}

    # Sort by timestamp — events should already be in order but be safe
    events = sorted(events, key=lambda e: _parse_ts(e.get("timestamp", "")))
    timestamps = [_parse_ts(e["timestamp"]) for e in events]

    # ── Basic counts ──────────────────────────────────────────────────────────
    total      = len(events)
    ops        = [e.get("operation", "") for e in events]
    write_cnt  = ops.count("WRITE")
    read_cnt   = ops.count("READ")
    rename_cnt = ops.count("RENAME")
    delete_cnt = ops.count("DELETE")

    # ── Time span ─────────────────────────────────────────────────────────────
    duration = max(timestamps[-1] - timestamps[0], 0.001)   # avoid div/0

    # ── File / directory spread ───────────────────────────────────────────────
    paths         = [e.get("file_path", "") for e in events]
    unique_files  = len(set(paths))
    unique_dirs   = len({str(Path(p).parent) for p in paths if p})

    # ── Rate features ─────────────────────────────────────────────────────────
    write_timestamps = [
        _parse_ts(e["timestamp"]) for e in events if e.get("operation") == "WRITE"
    ]
    files_per_sec    = write_cnt / duration
    max_per_10sec    = _max_in_window(write_timestamps, window_sec=10.0)

    # ── Overwrite ratio ───────────────────────────────────────────────────────
    # Writes as proportion of all non-delete activity
    denominator   = write_cnt + read_cnt
    overwrite_ratio = write_cnt / denominator if denominator > 0 else 0.0

    # ── Extension churn ───────────────────────────────────────────────────────
    rename_events = [e for e in events if e.get("operation") == "RENAME"]
    ext_changes   = sum(
        1 for e in rename_events
        if e.get("file_extension_before") != e.get("file_extension_after")
    )
    ext_change_ratio = ext_changes / rename_cnt if rename_cnt > 0 else 0.0

    # ── Entropy delta ─────────────────────────────────────────────────────────
    entropy_deltas = [
        e["entropy_delta"]
        for e in events
        if "entropy_delta" in e and e["entropy_delta"] is not None
    ]
    mean_entropy_delta = float(np.mean(entropy_deltas)) if entropy_deltas else 0.0
    max_entropy_delta  = float(np.max(entropy_deltas))  if entropy_deltas else 0.0

    # ── Sequential score ──────────────────────────────────────────────────────
    # Spearman correlation between access order (0, 1, 2 …) and
    # alphabetical rank of each accessed path.
    # Ransomware iterates sorted  → correlation ≈ 1.0
    # Human access is random       → correlation ≈ 0.0
    access_order   = list(range(len(paths)))
    sorted_paths   = sorted(paths)
    alpha_ranks    = [sorted_paths.index(p) for p in paths]   # alphabetical rank
    sequential_score = _spearman_r(access_order, alpha_ranks)

    # ── Label (consistent within a session by design) ─────────────────────────
    labels = [e.get("label") for e in events if e.get("label") is not None]
    label  = int(labels[0]) if labels else -1

    return {
        "session_id":             events[0].get("session_id", ""),
        "label":                  label,
        "session_duration_sec":   round(duration, 3),
        "total_events":           total,
        "write_count":            write_cnt,
        "read_count":             read_cnt,
        "rename_count":           rename_cnt,
        "delete_count":           delete_cnt,
        "files_modified_per_sec": round(files_per_sec, 4),
        "unique_files_touched":   unique_files,
        "unique_dirs_touched":    unique_dirs,
        "overwrite_ratio":        round(overwrite_ratio, 4),
        "extension_change_count": ext_changes,
        "extension_change_ratio": round(ext_change_ratio, 4),
        "mean_entropy_delta":     round(mean_entropy_delta, 4),
        "max_entropy_delta":      round(max_entropy_delta, 4),
        "sequential_score":       round(sequential_score, 4),
        "max_files_per_10sec":    max_per_10sec,
    }


# ─── Main pipeline ────────────────────────────────────────────────────────────

def load_events(log_path: Path) -> dict[str, list[dict]]:
    """Read NDJSON log and group events by session_id."""
    sessions: dict[str, list[dict]] = defaultdict(list)
    skipped = 0

    with open(log_path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                sid   = event.get("session_id")
                if sid:
                    sessions[sid].append(event)
                else:
                    skipped += 1
            except json.JSONDecodeError as e:
                print(f"  Warning: skipping malformed event on line {line_no}: {e}")
                skipped += 1

    if skipped:
        print(f"  Skipped {skipped} events (missing session_id or malformed JSON)")
    return dict(sessions)


def run(log_path: Path, out_path: Path) -> pd.DataFrame:
    print(f"\nReading events from: {log_path}")
    sessions = load_events(log_path)
    print(f"Found {len(sessions)} sessions")

    rows = []
    for sid, events in sessions.items():
        features = extract_session_features(events)
        if features:
            rows.append(features)

    df = pd.DataFrame(rows)
    if df.empty:
        print("No features extracted — is the log file empty?")
        return df

    # ── Summary ───────────────────────────────────────────────────────────────
    label_counts = df["label"].value_counts().to_dict()
    print(f"\nExtracted {len(df)} session rows")
    print(f"  Label 0 (benign):              {label_counts.get(0, 0)}")
    print(f"  Label 1 (ransomware-pattern):  {label_counts.get(1, 0)}")
    print(f"\nFeature summary:")
    print(df[df.columns.difference(["session_id"])].describe().round(3).to_string())

    # ── Save ──────────────────────────────────────────────────────────────────
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)
    print(f"\nSaved: {out_path}")
    print(f"\nNext step:")
    print(f"  cd ../ml-model && python train.py --features {out_path}")
    return df


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract features from raw event log")
    parser.add_argument(
        "--log", required=True, type=Path,
        help="Path to the NDJSON event log from simulator/",
    )
    parser.add_argument(
        "--out", default="./output/features.csv", type=Path,
        help="Output CSV path (default: ./output/features.csv)",
    )
    parser.add_argument(
        "--guide", action="store_true",
        help="Print the feature guide and exit",
    )
    args = parser.parse_args()

    if args.guide:
        print(FEATURE_GUIDE)
        sys.exit(0)

    if not args.log.exists():
        print(f"Log file not found: {args.log}")
        sys.exit(1)

    run(args.log, args.out)
