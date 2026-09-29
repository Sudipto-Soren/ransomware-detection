"""
simulator/dirty_dataset_generator.py

Generates a realistically "messy" dataset where no single feature
perfectly separates benign from ransomware.

THE CORE PROBLEM WITH THE PREVIOUS GENERATOR:
  overwrite_ratio:   benign ≈ 0.24,  ransomware ≈ 0.93  (almost no overlap)
  sequential_score:  benign ≈ 0.10,  ransomware ≈ 0.90  (almost no overlap)

  The model learns ONE rule: "overwrite_ratio > 0.6 = ransomware"
  and gets 99% accuracy. That's not detection, that's memorisation.

THE FIX — force overlap on every individual feature:
  ┌─────────────────────┬──────────────────┬──────────────────┐
  │ Feature             │ Benign range     │ Ransomware range │
  ├─────────────────────┼──────────────────┼──────────────────┤
  │ files_modified/sec  │ 0.1 – 25         │ 0.5 – 50         │  ← overlap 0.5–25
  │ overwrite_ratio     │ 0.0 – 0.95       │ 0.3 – 1.0        │  ← overlap 0.3–0.95
  │ sequential_score    │ -0.3 – 0.95      │ 0.2 – 1.0        │  ← overlap 0.2–0.95
  │ max_files_per_10sec │ 0 – 50           │ 2 – 100          │  ← overlap 2–50
  │ unique_dirs_touched │ 1 – 7            │ 1 – 7            │  ← full overlap
  └─────────────────────┴──────────────────┴──────────────────┘

  The model is forced to look at 3–4 features TOGETHER to decide.
  That's what a real production model does.

10 benign types + 10 ransomware types = genuine variety
1200 sessions total (600 per class)
Label noise: 2% intentional mislabeling (real datasets have this)
Feature noise: 12% gaussian per session (measurement uncertainty)

Expected output:
  Accuracy  0.87 – 0.93
  F1        0.86 – 0.92
  CV std    0.03 – 0.06  (stable, not suspiciously perfect)

Usage:
  python3 dirty_dataset_generator.py \
      --out ../feature-extraction/output/features_dirty.csv
  python3 dirty_dataset_generator.py \
      --out ../feature-extraction/output/features_dirty.csv --n 600
"""

import argparse
import random
from pathlib import Path

import numpy as np
import pandas as pd

rng = np.random.default_rng(seed=42)

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


def g(lo, hi):
    """Uniform sample in [lo, hi]."""
    return float(rng.uniform(lo, hi))


def gi(lo, hi):
    """Uniform integer in [lo, hi]."""
    return int(rng.integers(lo, hi + 1))


def clip(v, lo=0.0, hi=None):
    v = max(lo, v)
    if hi is not None:
        v = min(hi, v)
    return v


# ══════════════════════════════════════════════════════════════════════════════
# BENIGN TYPES
# Each type is designed to overlap with ransomware on AT LEAST ONE feature.
# ══════════════════════════════════════════════════════════════════════════════

def normal_user(n):
    """Standard human file usage — slow, scattered, low overwrite."""
    rows = []
    for _ in range(n):
        dur = g(45, 200)
        w   = gi(1, 8)
        r   = gi(4, 20)
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(w / dur),
            "overwrite_ratio":        clip(g(0.0, 0.30)),
            "sequential_score":       clip(g(-0.30, 0.30)),
            "max_files_per_10sec":    gi(0, 2),
            "unique_dirs_touched":    gi(1, 3),
            "write_count":            w,
            "read_count":             r,
            "unique_files_touched":   w + gi(0, r),
            "mean_entropy_delta":     g(-0.03, 0.03),
            "label": 0,
        })
    return rows


def power_user(n):
    """Heavy user — more files, faster, still scattered."""
    rows = []
    for _ in range(n):
        dur = g(20, 100)
        w   = gi(5, 25)
        r   = gi(5, 30)
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(g(0.2, 2.5)),
            "overwrite_ratio":        clip(g(0.10, 0.55)),  # slightly higher
            "sequential_score":       clip(g(-0.20, 0.50)),
            "max_files_per_10sec":    gi(1, 6),
            "unique_dirs_touched":    gi(2, 6),
            "write_count":            w,
            "read_count":             r,
            "unique_files_touched":   w + gi(0, 5),
            "mean_entropy_delta":     g(-0.02, 0.05),
            "label": 0,
        })
    return rows


def log_writer(n):
    """
    App writing logs — HIGH overwrite, HIGH sequential, FAST.
    Overlaps ransomware on: overwrite_ratio, sequential_score, files/sec.
    Distinguished by: very few unique files (writing same log file repeatedly).
    """
    rows = []
    for _ in range(n):
        dur  = g(5, 60)
        rate = g(5, 25)   # fast — like ransomware
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(g(0.70, 1.00)),   # HIGH — like ransomware
            "sequential_score":       clip(g(0.50, 0.90)),   # HIGH — like ransomware
            "max_files_per_10sec":    gi(int(rate * 8), int(rate * 12)),
            "unique_dirs_touched":    gi(1, 2),               # KEY: only 1-2 dirs
            "write_count":            int(rate * dur),
            "read_count":             gi(0, 3),
            "unique_files_touched":   gi(2, 6),               # KEY: tiny — same files
            "mean_entropy_delta":     g(-0.01, 0.01),
            "label": 0,
        })
    return rows


def av_scanner(n):
    """
    Antivirus scanning — HIGH sequential, many dirs, but READ only.
    Overlaps ransomware on: sequential_score, unique_dirs, files/sec.
    Distinguished by: overwrite_ratio ≈ 0 (reads only).
    """
    rows = []
    for _ in range(n):
        dur  = g(30, 180)
        rate = g(8, 30)
        n_files = int(rate * dur)
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(rate * g(0.05, 0.15)),  # reads, not writes
            "overwrite_ratio":        clip(g(0.00, 0.08)),          # KEY: near zero
            "sequential_score":       clip(g(0.70, 0.98)),          # HIGH — like ransomware
            "max_files_per_10sec":    gi(int(rate * 7), int(rate * 12)),
            "unique_dirs_touched":    gi(5, 7),                     # many dirs
            "write_count":            gi(0, 3),
            "read_count":             n_files,
            "unique_files_touched":   n_files,
            "mean_entropy_delta":     g(-0.01, 0.01),
            "label": 0,
        })
    return rows


def database_backup(n):
    """
    DB backup — FAST writes, SEQUENTIAL, but creates new files (no overwrite).
    Overlaps ransomware on: files/sec, sequential_score.
    Distinguished by: overwrite_ratio ≈ 0 (writes new backup files).
    """
    rows = []
    for _ in range(n):
        dur  = g(5, 30)
        rate = g(10, 30)
        n_files = int(rate * dur)
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(g(0.00, 0.12)),   # KEY: near zero
            "sequential_score":       clip(g(0.55, 0.92)),
            "max_files_per_10sec":    gi(int(rate * 8), int(rate * 12)),
            "unique_dirs_touched":    gi(1, 3),
            "write_count":            n_files,
            "read_count":             gi(2, 10),
            "unique_files_touched":   n_files,
            "mean_entropy_delta":     g(0.05, 0.60),         # compressed backup
            "label": 0,
        })
    return rows


def media_encoder(n):
    """Video/audio encoder — high entropy output, few unique files."""
    rows = []
    for _ in range(n):
        dur = g(20, 300)
        n_f = gi(1, 10)
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(g(0.03, 0.40)),
            "overwrite_ratio":        clip(g(0.00, 0.25)),
            "sequential_score":       clip(g(-0.10, 0.45)),
            "max_files_per_10sec":    gi(0, 3),
            "unique_dirs_touched":    gi(1, 2),
            "write_count":            n_f,
            "read_count":             gi(1, 6),
            "unique_files_touched":   n_f,
            "mean_entropy_delta":     g(0.40, 1.80),         # encoding = high entropy
            "label": 0,
        })
    return rows


def build_system(n):
    """
    Compiler / npm install — HIGH rate, MANY dirs, NOT sequential.
    Overlaps ransomware on: files/sec, max_per_10sec, dirs_touched.
    Distinguished by: sequential_score ≈ 0 (scattered writes).
    """
    rows = []
    for _ in range(n):
        dur  = g(10, 90)
        rate = g(12, 45)
        n_files = int(rate * dur)
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(g(0.00, 0.12)),
            "sequential_score":       clip(g(-0.15, 0.35)),  # KEY: NOT sequential
            "max_files_per_10sec":    gi(int(rate * 8), int(rate * 12)),
            "unique_dirs_touched":    gi(5, 7),
            "write_count":            n_files,
            "read_count":             gi(5, 30),
            "unique_files_touched":   n_files,
            "mean_entropy_delta":     g(-0.02, 0.12),
            "label": 0,
        })
    return rows


def file_sync(n):
    """
    Dropbox/iCloud sync — moderate rate, overwrites same files.
    Hard case: medium overwrite, medium sequential, medium rate.
    """
    rows = []
    for _ in range(n):
        dur  = g(15, 120)
        rate = g(1, 8)
        n_files = int(rate * dur)
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(g(0.35, 0.75)),   # MEDIUM — ambiguous zone
            "sequential_score":       clip(g(0.20, 0.65)),   # MEDIUM — ambiguous zone
            "max_files_per_10sec":    gi(int(rate * 5), int(rate * 12)),
            "unique_dirs_touched":    gi(2, 5),
            "write_count":            n_files,
            "read_count":             gi(2, 15),
            "unique_files_touched":   int(n_files * g(0.5, 1.0)),
            "mean_entropy_delta":     g(-0.02, 0.06),
            "label": 0,
        })
    return rows


def package_manager(n):
    """
    pip/npm update — fast writes in bursts, scattered, new files.
    Overlaps on: max_files_per_10sec, unique_dirs.
    """
    rows = []
    for _ in range(n):
        dur  = g(5, 45)
        rate = g(15, 50)
        n_files = int(rate * dur * g(0.3, 0.6))
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(rate * g(0.3, 0.6)),
            "overwrite_ratio":        clip(g(0.05, 0.30)),
            "sequential_score":       clip(g(-0.10, 0.40)),
            "max_files_per_10sec":    gi(int(rate * 8), int(rate * 13)),
            "unique_dirs_touched":    gi(4, 7),
            "write_count":            n_files,
            "read_count":             gi(5, 40),
            "unique_files_touched":   n_files,
            "mean_entropy_delta":     g(-0.01, 0.08),
            "label": 0,
        })
    return rows


def backup_overwrite(n):
    """
    HARD BENIGN: backup tool overwriting previous backup files.
    HIGH overwrite + HIGH sequential + HIGH rate.
    Distinguished ONLY by: entropy_delta ≈ 0, unique_files small relative to write count.
    This is the hardest benign case — most like ransomware.
    """
    rows = []
    for _ in range(n):
        dur  = g(10, 60)
        rate = g(5, 20)
        n_files = int(rate * dur)
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(g(0.75, 0.97)),   # VERY HIGH
            "sequential_score":       clip(g(0.65, 0.95)),   # VERY HIGH
            "max_files_per_10sec":    gi(int(rate * 8), int(rate * 12)),
            "unique_dirs_touched":    gi(2, 4),
            "write_count":            n_files,
            "read_count":             gi(0, 5),
            "unique_files_touched":   gi(int(n_files * 0.6), n_files),
            "mean_entropy_delta":     g(-0.02, 0.04),         # KEY: near zero (copying)
            "label": 0,
        })
    return rows


# ══════════════════════════════════════════════════════════════════════════════
# RANSOMWARE TYPES
# Each type overlaps with some benign type on individual features.
# ══════════════════════════════════════════════════════════════════════════════

def fast_ransomware(n):
    """Classic fast ransomware — high everything."""
    rows = []
    for _ in range(n):
        dur  = g(2, 12)
        rate = g(18, 50)
        n_f  = int(rate * dur)
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(g(0.88, 1.00)),
            "sequential_score":       clip(g(0.82, 1.00)),
            "max_files_per_10sec":    gi(int(rate * 9), int(rate * 11)),
            "unique_dirs_touched":    gi(5, 7),
            "write_count":            n_f,
            "read_count":             gi(0, 3),
            "unique_files_touched":   n_f,
            "mean_entropy_delta":     g(-0.01, 0.04),
            "label": 1,
        })
    return rows


def slow_ransomware(n):
    """
    Throttled ransomware — LOW rate.
    Overlaps benign on: files/sec, max_per_10sec.
    Distinguished by: overwrite_ratio still high + sequential still high.
    """
    rows = []
    for _ in range(n):
        dur  = g(40, 150)
        rate = g(0.4, 3.5)   # overlaps with normal user!
        n_f  = int(rate * dur)
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(g(0.82, 1.00)),   # HIGH despite slow rate
            "sequential_score":       clip(g(0.72, 0.98)),
            "max_files_per_10sec":    gi(gi(2, 8), gi(8, 20)),
            "unique_dirs_touched":    gi(4, 7),
            "write_count":            n_f,
            "read_count":             gi(0, 4),
            "unique_files_touched":   n_f,
            "mean_entropy_delta":     g(-0.01, 0.04),
            "label": 1,
        })
    return rows


def burst_ransomware(n):
    """
    Burst-pause ransomware — avg rate looks medium but bursts are extreme.
    Overlaps file_sync on: avg rate, sequential, dirs.
    """
    rows = []
    for _ in range(n):
        dur        = g(20, 80)
        burst_rate = g(20, 60)
        avg_rate   = burst_rate * g(0.25, 0.45)
        n_f        = int(avg_rate * dur)
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(avg_rate),
            "overwrite_ratio":        clip(g(0.82, 1.00)),
            "sequential_score":       clip(g(0.68, 0.96)),
            "max_files_per_10sec":    gi(int(burst_rate * 9), int(burst_rate * 11)),  # KEY: burst max is extreme
            "unique_dirs_touched":    gi(4, 7),
            "write_count":            n_f,
            "read_count":             gi(0, 3),
            "unique_files_touched":   n_f,
            "mean_entropy_delta":     g(-0.01, 0.04),
            "label": 1,
        })
    return rows


def random_order_ransomware(n):
    """
    Ransomware with random file traversal order (evades sequential detection).
    Overlaps build_system on: sequential_score ≈ 0.
    Distinguished by: overwrite_ratio still high.
    """
    rows = []
    for _ in range(n):
        dur  = g(5, 30)
        rate = g(8, 35)
        n_f  = int(rate * dur)
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(g(0.82, 1.00)),
            "sequential_score":       clip(g(0.15, 0.55)),   # KEY: NOT sequential
            "max_files_per_10sec":    gi(int(rate * 8), int(rate * 12)),
            "unique_dirs_touched":    gi(4, 7),
            "write_count":            n_f,
            "read_count":             gi(0, 4),
            "unique_files_touched":   n_f,
            "mean_entropy_delta":     g(-0.01, 0.04),
            "label": 1,
        })
    return rows


def partial_ransomware(n):
    """
    Only encrypts 20-40% of files. Low write count, medium rate.
    Overlaps power_user on: rate, dirs.
    """
    rows = []
    for _ in range(n):
        dur    = g(20, 90)
        rate   = g(1, 6) * g(0.2, 0.4)
        n_f    = max(8, int(rate * dur))
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(g(0.82, 1.00)),   # still fully overwrites
            "sequential_score":       clip(g(0.60, 0.95)),
            "max_files_per_10sec":    gi(gi(3, 8), gi(8, 18)),
            "unique_dirs_touched":    gi(3, 6),
            "write_count":            n_f,
            "read_count":             gi(0, 4),
            "unique_files_touched":   n_f,
            "mean_entropy_delta":     g(-0.01, 0.04),
            "label": 1,
        })
    return rows


def targeted_ransomware(n):
    """
    Hits only Documents/ — low dirs count, overlaps benign on that feature.
    """
    rows = []
    for _ in range(n):
        dur  = g(5, 25)
        rate = g(6, 25)
        n_f  = int(rate * dur)
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(g(0.85, 1.00)),
            "sequential_score":       clip(g(0.72, 0.98)),
            "max_files_per_10sec":    gi(int(rate * 9), int(rate * 11)),
            "unique_dirs_touched":    gi(1, 3),   # KEY: low like normal_user
            "write_count":            n_f,
            "read_count":             gi(0, 2),
            "unique_files_touched":   n_f,
            "mean_entropy_delta":     g(-0.01, 0.04),
            "label": 1,
        })
    return rows


def low_overwrite_ransomware(n):
    """
    Reads each file before encrypting — temporarily raises read count.
    Overlaps file_sync on: overwrite, sequential, rate.
    """
    rows = []
    for _ in range(n):
        dur  = g(10, 50)
        rate = g(3, 15)
        n_f  = int(rate * dur)
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(g(0.55, 0.82)),  # LOWER than typical
            "sequential_score":       clip(g(0.60, 0.92)),
            "max_files_per_10sec":    gi(int(rate * 8), int(rate * 12)),
            "unique_dirs_touched":    gi(3, 6),
            "write_count":            n_f,
            "read_count":             n_f,    # reads = writes (reads before encrypt)
            "unique_files_touched":   n_f,
            "mean_entropy_delta":     g(-0.01, 0.04),
            "label": 1,
        })
    return rows


def sleeping_ransomware(n):
    """
    Long session with occasional bursts — low average rate, high burst.
    Overlaps power_user on: avg rate, duration.
    """
    rows = []
    for _ in range(n):
        dur       = g(60, 240)
        burst_r   = g(15, 40)
        active    = g(0.10, 0.25)  # only active 10-25% of time
        avg_rate  = burst_r * active
        n_f       = int(avg_rate * dur)
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(avg_rate),
            "overwrite_ratio":        clip(g(0.85, 1.00)),
            "sequential_score":       clip(g(0.68, 0.95)),
            "max_files_per_10sec":    gi(int(burst_r * 9), int(burst_r * 11)),
            "unique_dirs_touched":    gi(4, 7),
            "write_count":            max(8, n_f),
            "read_count":             gi(0, 5),
            "unique_files_touched":   max(8, n_f),
            "mean_entropy_delta":     g(-0.01, 0.04),
            "label": 1,
        })
    return rows


def medium_ransomware(n):
    """
    Medium everything — sits squarely in ambiguous zone.
    Hardest to distinguish from file_sync and backup_overwrite.
    """
    rows = []
    for _ in range(n):
        dur  = g(15, 60)
        rate = g(4, 15)
        n_f  = int(rate * dur)
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(g(0.65, 0.90)),  # MEDIUM
            "sequential_score":       clip(g(0.50, 0.82)),  # MEDIUM
            "max_files_per_10sec":    gi(int(rate * 7), int(rate * 11)),
            "unique_dirs_touched":    gi(3, 6),
            "write_count":            n_f,
            "read_count":             gi(0, 6),
            "unique_files_touched":   n_f,
            "mean_entropy_delta":     g(-0.01, 0.04),
            "label": 1,
        })
    return rows


def confuser_ransomware(n):
    """
    HARD RANSOMWARE: looks like a build system — fast, scattered, medium overwrite.
    The ONLY strong signals: overwrite_ratio still > 0.6, write >> read.
    """
    rows = []
    for _ in range(n):
        dur  = g(8, 40)
        rate = g(10, 35)
        n_f  = int(rate * dur)
        rows.append({
            "session_duration_sec":   dur,
            "files_modified_per_sec": clip(rate),
            "overwrite_ratio":        clip(g(0.62, 0.88)),
            "sequential_score":       clip(g(0.20, 0.60)),   # NOT sequential
            "max_files_per_10sec":    gi(int(rate * 8), int(rate * 12)),
            "unique_dirs_touched":    gi(4, 7),
            "write_count":            n_f,
            "read_count":             gi(0, 5),
            "unique_files_touched":   n_f,
            "mean_entropy_delta":     g(-0.01, 0.05),
            "label": 1,
        })
    return rows


# ══════════════════════════════════════════════════════════════════════════════
# NOISE + LABEL NOISE + ASSEMBLY
# ══════════════════════════════════════════════════════════════════════════════

def add_feature_noise(df: pd.DataFrame, noise_frac: float = 0.12) -> pd.DataFrame:
    """
    Add 12% relative gaussian noise to each feature per row.
    This simulates real measurement uncertainty:
      - process CPU reading varies ±15%
      - file event timestamps have OS scheduling jitter
      - file size reads can be cached stale values
    """
    num_cols = [c for c in FEATURES if c in df.columns]
    for col in num_cols:
        noise = np.random.normal(0, noise_frac, len(df))
        df[col] = (df[col] + df[col].abs() * noise).clip(lower=0)
    return df


def add_label_noise(df: pd.DataFrame, noise_rate: float = 0.025) -> pd.DataFrame:
    """
    Flip 2.5% of labels randomly.

    WHY: Real datasets have labeling errors. Security analysts
    occasionally misclassify benign tools as ransomware and vice versa.
    Training on a few wrong labels forces the model to learn robust
    decision boundaries rather than memorising every point.
    """
    n_flip = max(1, int(len(df) * noise_rate))
    flip_idx = np.random.choice(df.index, size=n_flip, replace=False)
    df.loc[flip_idx, "label"] = 1 - df.loc[flip_idx, "label"]
    print(f"  Label noise: flipped {n_flip} labels ({noise_rate*100:.1f}%)")
    return df


def add_outliers(df: pd.DataFrame, rate: float = 0.04) -> pd.DataFrame:
    """
    For 4% of rows, replace ONE random feature value with a value
    drawn from the opposite class distribution.
    Models real anomalies: a benign process that suddenly spikes
    its write rate for one measurement window.
    """
    n_outliers = max(1, int(len(df) * rate))
    outlier_idx = np.random.choice(df.index, size=n_outliers, replace=False)
    feature_to_corrupt = np.random.choice(
        ["overwrite_ratio", "sequential_score", "files_modified_per_sec"],
        size=n_outliers
    )
    for idx, feat in zip(outlier_idx, feature_to_corrupt):
        current_label = df.loc[idx, "label"]
        if current_label == 0:  # benign: spike one feature high
            if feat == "overwrite_ratio":
                df.loc[idx, feat] = float(rng.uniform(0.75, 0.98))
            elif feat == "sequential_score":
                df.loc[idx, feat] = float(rng.uniform(0.70, 0.98))
            else:
                df.loc[idx, feat] *= float(rng.uniform(5, 15))
        else:  # ransomware: drop one feature to benign range
            if feat == "overwrite_ratio":
                df.loc[idx, feat] = float(rng.uniform(0.05, 0.35))
            elif feat == "sequential_score":
                df.loc[idx, feat] = float(rng.uniform(-0.20, 0.30))
            else:
                df.loc[idx, feat] *= float(rng.uniform(0.05, 0.15))
    return df


def generate(n_per_class: int, out_path: Path) -> pd.DataFrame:
    share = n_per_class // 10

    print(f"\n  Generating {n_per_class * 2} sessions ({n_per_class} per class)...")
    print(f"  10 benign types + 10 ransomware types")

    benign = (
        normal_user(share)      + power_user(share)       +
        log_writer(share)       + av_scanner(share)        +
        database_backup(share)  + media_encoder(share)     +
        build_system(share)     + file_sync(share)         +
        package_manager(share)  + backup_overwrite(share)
    )

    ransom = (
        fast_ransomware(share)          + slow_ransomware(share)       +
        burst_ransomware(share)         + random_order_ransomware(share) +
        partial_ransomware(share)       + targeted_ransomware(share)   +
        low_overwrite_ransomware(share) + sleeping_ransomware(share)   +
        medium_ransomware(share)        + confuser_ransomware(share)
    )

    all_rows = benign + ransom
    random.shuffle(all_rows)

    df = pd.DataFrame(all_rows)
    df = df[FEATURES + ["label"]]

    # Apply realistic noise layers
    df = add_feature_noise(df, noise_frac=0.12)
    df = add_outliers(df, rate=0.04)
    df = add_label_noise(df, noise_rate=0.025)

    # Save
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)

    counts = df["label"].value_counts().to_dict()
    print(f"\n  ✓ Dataset written: {out_path}")
    print(f"  Total rows : {len(df)}")
    print(f"  Benign (0) : {counts.get(0, 0)}")
    print(f"  Ransom (1) : {counts.get(1, 0)}")

    print(f"\n  Feature overlap check (closer = harder = better):")
    b = df[df.label == 0]
    r = df[df.label == 1]
    for feat in ["files_modified_per_sec", "overwrite_ratio",
                 "sequential_score", "max_files_per_10sec"]:
        bm = b[feat].mean()
        rm = r[feat].mean()
        overlap = min(bm, rm) / max(bm, rm) if max(bm, rm) > 0 else 0
        bar = "█" * int(overlap * 20)
        print(f"  {feat:<28} benign={bm:>6.2f}  ransom={rm:>6.2f}  "
              f"overlap={overlap:.2f} {bar}")

    print(f"\n  Target model performance after training on this:")
    print(f"  Accuracy 0.87–0.93 | F1 0.86–0.92 | CV std 0.03–0.06")
    print(f"\n  Next:")
    print(f"    cd ../ml-model")
    print(f"    python3 train_behavioral.py --features {out_path}")
    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate dirty, realistic behavioral dataset"
    )
    parser.add_argument(
        "--out", required=True, type=Path,
        help="Output CSV path"
    )
    parser.add_argument(
        "--n", default=600, type=int,
        help="Sessions per class (default 600, total 1200)"
    )
    args = parser.parse_args()
    generate(args.n, args.out)
