"""
backend/services/detection.py

Loads the trained model and runs inference.

This is the only place in the backend that touches ML code — keeping
it isolated means you can swap models (RF → XGBoost → a neural net)
without touching any router or database code.
"""

import json
import math
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np

from config import FEAT_COL_PATH, MIN_EVENTS_FOR_INFERENCE, MODEL_PATH, RISK_THRESHOLD


# ─── Model singleton ──────────────────────────────────────────────────────────
# Loaded once at startup, reused for every request.
# Avoids the ~200ms overhead of joblib.load() per request.

_model = None
_feature_cols: list[str] = []


def load_model() -> bool:
    """
    Load the model and feature column list from disk.
    Called once from main.py's startup event.
    Returns True if successful.
    """
    global _model, _feature_cols

    if not MODEL_PATH.exists():
        print(f"[detection] ⚠  Model not found at {MODEL_PATH}")
        print("  Run: cd ml-model && python train.py --features ...")
        return False

    if not FEAT_COL_PATH.exists():
        print(f"[detection] ⚠  Feature columns file not found at {FEAT_COL_PATH}")
        return False

    _model = joblib.load(MODEL_PATH)
    with open(FEAT_COL_PATH) as f:
        _feature_cols = json.load(f)

    model_type = type(_model).__name__
    print(f"[detection] ✓  Loaded {model_type} with {len(_feature_cols)} features")
    return True


def is_loaded() -> bool:
    return _model is not None


def get_model_name() -> str:
    if _model is None:
        return "not loaded"
    return type(_model).__name__


# ─── Feature extraction (mirrors feature-extraction/extractor.py) ─────────────

def _parse_ts(iso: str) -> float:
    try:
        return datetime.fromisoformat(iso).timestamp()
    except (ValueError, TypeError):
        return 0.0


def _spearman_r(x: list, y: list) -> float:
    n = len(x)
    if n < 3:
        return 0.0
    rx = np.argsort(np.argsort(x)).astype(float)
    ry = np.argsort(np.argsort(y)).astype(float)
    rx -= rx.mean(); ry -= ry.mean()
    denom = np.sqrt((rx**2).sum()) * np.sqrt((ry**2).sum())
    return float(np.dot(rx, ry) / denom) if denom > 0 else 0.0


def _max_in_window(timestamps: list[float], window: float = 10.0) -> int:
    if not timestamps:
        return 0
    ts = sorted(timestamps)
    max_c, left = 0, 0
    for right in range(len(ts)):
        while ts[right] - ts[left] > window:
            left += 1
        max_c = max(max_c, right - left + 1)
    return max_c


def extract_features(events: list[dict]) -> dict:
    """
    Same logic as feature-extraction/extractor.py — kept in sync.
    Takes a list of raw event dicts, returns a feature dict.
    """
    if not events:
        return {}

    events = sorted(events, key=lambda e: _parse_ts(e.get("timestamp", "")))
    timestamps = [_parse_ts(e["timestamp"]) for e in events]
    duration   = max(timestamps[-1] - timestamps[0], 0.001)

    ops        = [e.get("operation", "") for e in events]
    write_cnt  = ops.count("WRITE")
    read_cnt   = ops.count("READ")
    rename_cnt = ops.count("RENAME")
    delete_cnt = ops.count("DELETE")

    paths       = [e.get("file_path", "") for e in events]
    unique_files = len(set(paths))
    unique_dirs  = len({str(Path(p).parent) for p in paths if p})

    write_ts       = [_parse_ts(e["timestamp"]) for e in events if e.get("operation") == "WRITE"]
    files_per_sec  = write_cnt / duration
    max_per_10sec  = _max_in_window(write_ts)

    denom           = write_cnt + read_cnt
    overwrite_ratio = write_cnt / denom if denom > 0 else 0.0

    rename_events   = [e for e in events if e.get("operation") == "RENAME"]
    ext_changes     = sum(1 for e in rename_events
                          if e.get("file_extension_before") != e.get("file_extension_after"))
    ext_change_ratio = ext_changes / rename_cnt if rename_cnt > 0 else 0.0

    deltas             = [e["entropy_delta"] for e in events
                          if e.get("entropy_delta") is not None]
    mean_ent_delta     = float(np.mean(deltas)) if deltas else 0.0
    max_ent_delta      = float(np.max(deltas))  if deltas else 0.0

    access_order   = list(range(len(paths)))
    sorted_paths   = sorted(paths)
    alpha_ranks    = [sorted_paths.index(p) for p in paths]
    seq_score      = _spearman_r(access_order, alpha_ranks)

    return {
        "session_duration_sec":  round(duration, 3),
        "total_events":          len(events),
        "write_count":           write_cnt,
        "read_count":            read_cnt,
        "rename_count":          rename_cnt,
        "delete_count":          delete_cnt,
        "files_modified_per_sec": round(files_per_sec, 4),
        "unique_files_touched":  unique_files,
        "unique_dirs_touched":   unique_dirs,
        "overwrite_ratio":       round(overwrite_ratio, 4),
        "extension_change_count": ext_changes,
        "extension_change_ratio": round(ext_change_ratio, 4),
        "mean_entropy_delta":    round(mean_ent_delta, 4),
        "max_entropy_delta":     round(max_ent_delta, 4),
        "sequential_score":      round(seq_score, 4),
        "max_files_per_10sec":   max_per_10sec,
    }


# ─── Inference ────────────────────────────────────────────────────────────────

def predict(events: list[dict]) -> dict:
    """
    Main entry point.
    Takes a list of raw event dicts, returns a verdict dict.
    """
    if not is_loaded():
        return {"error": "Model not loaded", "is_ransomware": False, "risk_score": 0.0}

    if len(events) < MIN_EVENTS_FOR_INFERENCE:
        return {
            "is_ransomware": False,
            "risk_score":    0.0,
            "features":      {},
            "note":          f"Too few events ({len(events)} < {MIN_EVENTS_FOR_INFERENCE})",
        }

    features = extract_features(events)

    # Build feature vector in the exact column order the model expects
    X = np.array([[features.get(col, 0.0) for col in _feature_cols]])

    # Probability of ransomware class (class 1)
    try:
        prob = float(_model.predict_proba(X)[0][1])
    except AttributeError:
        # Isolation Forest doesn't have predict_proba — use decision_function
        raw_score = float(_model.decision_function(X)[0])
        # decision_function: more negative = more anomalous
        # map to [0, 1] probability-like score
        prob = 1.0 / (1.0 + math.exp(raw_score * 2))

    risk_score    = round(prob * 100, 1)
    is_ransomware = prob >= RISK_THRESHOLD

    return {
        "is_ransomware": is_ransomware,
        "risk_score":    risk_score,
        "probability":   round(prob, 4),
        "features":      features,
    }
