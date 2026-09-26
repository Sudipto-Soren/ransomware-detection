"""
simulator/diverse_dataset_generator.py

Generates a properly diverse dataset focused on WRITE BEHAVIOR,
not on the final state (extension changes).

The key design principle:
  A real detection system must catch ransomware during the WRITE phase
  — before the rename to .locked completes. This means the model must
  learn from write rates, overwrite ratios, and access patterns, NOT
  from extension changes.

This generator produces sessions where:
  - Benign and ransomware OVERLAP on some features (no easy splits)
  - The only reliable signal is the COMBINATION of behavioral features
  - Extension change events are NOT generated (write-phase only)

Classes generated:
  Label 0 — Benign variants:
    normal_user     : slow, scattered, low overwrite
    log_writer      : fast writes, sequential, but same files repeatedly
    database_backup : burst of large sequential writes, no overwrites
    media_encoder   : very fast writes, high entropy, large files
    build_system    : many small fast writes, scattered dirs

  Label 1 — Ransomware variants:
    fast_ransomware : classic high-speed, sequential, high overwrite
    slow_ransomware : throttled to 1-3/sec to evade rate detection
    burst_ransomware: alternates fast bursts with pauses
    targeted_ransom : only hits certain dirs (low dir count)
    partial_ransom  : encrypts 25-40% of files slowly

Usage:
  python diverse_dataset_generator.py --out ../feature-extraction/output/features_diverse.csv
  python diverse_dataset_generator.py --out ../feature-extraction/output/features_diverse.csv --n 300
"""

import argparse
import random
from pathlib import Path

import numpy as np
import pandas as pd

rng = np.random.default_rng(42)

# ─── BEHAVIORAL features only — NO extension features ─────────────────────────
# This is the critical design decision.
# We exclude extension_change_count and extension_change_ratio because:
#   1. A real system must detect ransomware BEFORE renames complete
#   2. Including them makes the problem trivially easy (perfect split)
#   3. The goal is to learn write-phase behavioral signals

FEATURES = [
    "session_duration_sec",
    "files_modified_per_sec",
    "overwrite_ratio",
    "sequential_score",
    "max_files_per_10sec",
    "unique_dirs_touched",
    "write_count",
    "read_count",
    "unique_files_touched",
    "mean_entropy_delta",
]


def clip(val, lo=0.0, hi=None):
    val = max(lo, val)
    if hi is not None:
        val = min(hi, val)
    return val


# ─── BENIGN generators ────────────────────────────────────────────────────────

def normal_user(n):
    """Typical human using files: slow, scattered, mostly reads."""
    rows = []
    for _ in range(n):
        duration = rng.uniform(60, 180)
        writes   = int(rng.uniform(1, 8))
        reads    = int(rng.uniform(5, 20))
        rows.append({
            "session_duration_sec":   duration,
            "files_modified_per_sec": clip(writes / duration, 0, 0.3),
            "overwrite_ratio":        clip(rng.uniform(0.0, 0.3)),
            "sequential_score":       clip(rng.uniform(-0.3, 0.35)),
            "max_files_per_10sec":    int(rng.uniform(0, 2)),
            "unique_dirs_touched":    int(rng.uniform(1, 3)),
            "write_count":            writes,
            "read_count":             reads,
            "unique_files_touched":   writes + reads,
            "mean_entropy_delta":     rng.uniform(-0.02, 0.02),
            "label": 0,
        })
    return rows


def log_writer(n):
    """
    Application writing logs: fast sequential writes to the SAME files.
    HIGH files/sec — but low unique files and low overwrite ratio.
    This is a HARD benign case: fast + sequential looks like ransomware.
    """
    rows = []
    for _ in range(n):
        duration = rng.uniform(10, 60)
        rate     = rng.uniform(5, 20)          # fast — similar to ransomware
        writes   = int(rate * duration)
        unique   = int(rng.uniform(2, 6))      # writing to same few log files
        rows.append({
            "session_duration_sec":   duration,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(rng.uniform(0.7, 1.0)),  # always overwriting same files
            "sequential_score":       clip(rng.uniform(0.5, 0.9)),  # somewhat sequential
            "max_files_per_10sec":    int(rate * 10),
            "unique_dirs_touched":    int(rng.uniform(1, 2)),       # only 1-2 dirs
            "write_count":            writes,
            "read_count":             int(rng.uniform(0, 3)),
            "unique_files_touched":   unique,                        # KEY: very few unique files
            "mean_entropy_delta":     rng.uniform(-0.01, 0.01),     # same content appended
            "label": 0,
        })
    return rows


def database_backup(n):
    """
    DB backup: large burst of sequential writes, then stops.
    HIGH rate, HIGH sequential — but no overwrites (new backup files).
    """
    rows = []
    for _ in range(n):
        duration = rng.uniform(5, 30)
        rate     = rng.uniform(8, 25)
        writes   = int(rate * duration)
        rows.append({
            "session_duration_sec":   duration,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(rng.uniform(0.0, 0.15)),  # KEY: creating new files, not overwriting
            "sequential_score":       clip(rng.uniform(0.6, 0.95)),
            "max_files_per_10sec":    int(rate * 10),
            "unique_dirs_touched":    int(rng.uniform(1, 3)),
            "write_count":            writes,
            "read_count":             int(rng.uniform(2, 10)),
            "unique_files_touched":   writes,
            "mean_entropy_delta":     rng.uniform(0.1, 0.5),        # high entropy (compressed backup)
            "label": 0,
        })
    return rows


def media_encoder(n):
    """
    Video/audio encoder writing large output files.
    Very fast writes, high entropy output, few files.
    """
    rows = []
    for _ in range(n):
        duration = rng.uniform(30, 300)
        n_files  = int(rng.uniform(1, 8))
        rate     = n_files / duration
        rows.append({
            "session_duration_sec":   duration,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(rng.uniform(0.0, 0.2)),
            "sequential_score":       clip(rng.uniform(-0.2, 0.4)),
            "max_files_per_10sec":    int(rng.uniform(0, 2)),
            "unique_dirs_touched":    int(rng.uniform(1, 2)),
            "write_count":            n_files,
            "read_count":             int(rng.uniform(1, 5)),
            "unique_files_touched":   n_files,
            "mean_entropy_delta":     rng.uniform(0.5, 1.5),        # encoding = high entropy output
            "label": 0,
        })
    return rows


def build_system(n):
    """
    Compiler / npm install: many small files written fast to many dirs.
    HIGH files/sec, many dirs, scattered — another hard benign case.
    """
    rows = []
    for _ in range(n):
        duration = rng.uniform(5, 60)
        rate     = rng.uniform(10, 40)
        writes   = int(rate * duration)
        rows.append({
            "session_duration_sec":   duration,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(rng.uniform(0.0, 0.1)),  # creating new files
            "sequential_score":       clip(rng.uniform(-0.1, 0.3)), # NOT sequential (scattered)
            "max_files_per_10sec":    int(rate * 10),
            "unique_dirs_touched":    int(rng.uniform(5, 20)),      # many dirs
            "write_count":            writes,
            "read_count":             int(rng.uniform(5, 30)),
            "unique_files_touched":   writes,
            "mean_entropy_delta":     rng.uniform(-0.05, 0.1),
            "label": 0,
        })
    return rows


# ─── RANSOMWARE generators ────────────────────────────────────────────────────

def fast_ransomware(n):
    """Classic ransomware: fast, sequential, high overwrite, many dirs."""
    rows = []
    for _ in range(n):
        duration = rng.uniform(2, 15)
        rate     = rng.uniform(15, 50)
        writes   = int(rate * duration)
        rows.append({
            "session_duration_sec":   duration,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(rng.uniform(0.85, 1.0)),  # fully overwrites
            "sequential_score":       clip(rng.uniform(0.80, 1.0)),  # sorted traversal
            "max_files_per_10sec":    int(rate * 10),
            "unique_dirs_touched":    int(rng.uniform(5, 7)),
            "write_count":            writes,
            "read_count":             int(rng.uniform(0, 3)),
            "unique_files_touched":   writes,
            "mean_entropy_delta":     rng.uniform(0.0, 0.05),
            "label": 1,
        })
    return rows


def slow_ransomware(n):
    """
    Throttled ransomware: deliberately slow to evade rate-based detection.
    HARD TO DETECT: files/sec overlaps with normal user activity.
    The signal is: slow PLUS high overwrite PLUS sequential.
    """
    rows = []
    for _ in range(n):
        duration = rng.uniform(30, 120)
        rate     = rng.uniform(0.5, 3.0)         # overlaps with normal user!
        writes   = int(rate * duration)
        rows.append({
            "session_duration_sec":   duration,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(rng.uniform(0.85, 1.0)),  # KEY signal
            "sequential_score":       clip(rng.uniform(0.75, 0.98)), # KEY signal
            "max_files_per_10sec":    int(rng.uniform(2, 8)),
            "unique_dirs_touched":    int(rng.uniform(4, 7)),
            "write_count":            writes,
            "read_count":             int(rng.uniform(0, 2)),
            "unique_files_touched":   writes,
            "mean_entropy_delta":     rng.uniform(-0.01, 0.04),
            "label": 1,
        })
    return rows


def burst_ransomware(n):
    """
    Ransomware that alternates fast bursts with pauses (evades sustained-rate detection).
    Session-level rate looks moderate, but max_files_per_10sec is very high.
    """
    rows = []
    for _ in range(n):
        duration = rng.uniform(20, 60)
        # Burst rate is high but overall rate is moderate
        burst_rate = rng.uniform(20, 60)
        actual_rate = burst_rate * rng.uniform(0.25, 0.45)  # only active 25-45% of time
        writes = int(actual_rate * duration)
        rows.append({
            "session_duration_sec":   duration,
            "files_modified_per_sec": clip(actual_rate),
            "overwrite_ratio":        clip(rng.uniform(0.85, 1.0)),
            "sequential_score":       clip(rng.uniform(0.70, 0.95)),
            "max_files_per_10sec":    int(burst_rate * 10),  # KEY: burst max is high
            "unique_dirs_touched":    int(rng.uniform(4, 7)),
            "write_count":            writes,
            "read_count":             int(rng.uniform(0, 3)),
            "unique_files_touched":   writes,
            "mean_entropy_delta":     rng.uniform(-0.01, 0.04),
            "label": 1,
        })
    return rows


def targeted_ransomware(n):
    """
    Targeted ransomware: only encrypts specific directories (e.g. Documents only).
    LOW unique_dirs_touched — might look like benign single-dir activity.
    """
    rows = []
    for _ in range(n):
        duration = rng.uniform(5, 25)
        rate     = rng.uniform(5, 20)
        writes   = int(rate * duration)
        rows.append({
            "session_duration_sec":   duration,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(rng.uniform(0.85, 1.0)),
            "sequential_score":       clip(rng.uniform(0.75, 0.98)),
            "max_files_per_10sec":    int(rate * 10),
            "unique_dirs_touched":    int(rng.uniform(1, 3)),  # KEY: low, like benign
            "write_count":            writes,
            "read_count":             int(rng.uniform(0, 2)),
            "unique_files_touched":   writes,
            "mean_entropy_delta":     rng.uniform(-0.01, 0.04),
            "label": 1,
        })
    return rows


def partial_ransomware(n):
    """
    Partial encryption: only touches 20-40% of files.
    Moderate rate, moderate counts — hardest to detect.
    """
    rows = []
    for _ in range(n):
        duration  = rng.uniform(10, 60)
        rate      = rng.uniform(1, 8)
        writes    = int(rate * duration * rng.uniform(0.2, 0.4))
        rows.append({
            "session_duration_sec":   duration,
            "files_modified_per_sec": clip(rate * rng.uniform(0.2, 0.4)),
            "overwrite_ratio":        clip(rng.uniform(0.85, 1.0)),  # still fully overwrites
            "sequential_score":       clip(rng.uniform(0.65, 0.92)),
            "max_files_per_10sec":    int(rng.uniform(3, 15)),
            "unique_dirs_touched":    int(rng.uniform(3, 7)),
            "write_count":            max(5, writes),
            "read_count":             int(rng.uniform(0, 3)),
            "unique_files_touched":   max(5, writes),
            "mean_entropy_delta":     rng.uniform(-0.01, 0.04),
            "label": 1,
        })
    return rows


# ─── Build and save ───────────────────────────────────────────────────────────

def generate(n_per_class: int, out_path: Path):
    share = n_per_class // 5

    benign_rows = (
        normal_user(share)      +
        log_writer(share)       +
        database_backup(share)  +
        media_encoder(share)    +
        build_system(share)
    )

    ransom_rows = (
        fast_ransomware(share)     +
        slow_ransomware(share)     +
        burst_ransomware(share)    +
        targeted_ransomware(share) +
        partial_ransomware(share)
    )

    all_rows = benign_rows + ransom_rows
    random.shuffle(all_rows)

    df = pd.DataFrame(all_rows)
    df = df[FEATURES + ["label"]]

    # Add tiny gaussian noise so no two rows are identical
    for col in FEATURES:
        noise = np.random.normal(0, df[col].std() * 0.02, len(df))
        df[col] = (df[col] + noise).clip(lower=0)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)

    label_counts = df["label"].value_counts().to_dict()
    print(f"\n  Dataset written to: {out_path}")
    print(f"  Total rows : {len(df)}")
    print(f"  Benign (0) : {label_counts.get(0, 0)}")
    print(f"  Ransom (1) : {label_counts.get(1, 0)}")
    print(f"\n  Feature distributions:")
    print(df.groupby("label")[FEATURES[:5]].mean().round(3).to_string())
    print(f"\n  Next:")
    print(f"    cd ../ml-model")
    print(f"    python3 train_behavioral.py --features {out_path}")
    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path,
                        help="Output CSV path")
    parser.add_argument("--n", default=250, type=int,
                        help="Sessions per class (default 250, total=500)")
    args = parser.parse_args()
    generate(args.n, args.out)
