"""
backend/config.py

All configuration in one place.
Values come from environment variables with sensible defaults
so the app runs out of the box without any setup.

Copy .env.example to .env and edit for your environment.
"""
import os
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent
PROJECT_DIR = BASE_DIR.parent          # ransomware-detection/

# Where the trained model lives (produced by ml-model/train.py)
MODEL_PATH    = Path(os.getenv("MODEL_PATH",
    str(PROJECT_DIR / "ml-model" / "models" / "best_model.joblib")))
FEAT_COL_PATH = Path(os.getenv("FEAT_COL_PATH",
    str(PROJECT_DIR / "ml-model" / "models" / "feature_columns.json")))

# Simulated cloud sync staging folder (stands in for OneDrive/Drive/Dropbox)
SYNC_STAGING_DIR = Path(os.getenv("SYNC_STAGING_DIR",
    str(BASE_DIR / "sync-staging")))
QUARANTINE_DIR   = Path(os.getenv("QUARANTINE_DIR",
    str(BASE_DIR / "quarantine")))

# Recovery version store
VERSION_STORE_DIR = Path(os.getenv("VERSION_STORE_DIR",
    str(BASE_DIR / "version-store")))

# ─── Database ─────────────────────────────────────────────────────────────────
# Default: SQLite file in backend/ (zero setup, great for dev/demo)
# For production: set DB_URL=postgresql://user:pass@localhost/ransomdb
DB_URL = os.getenv("DB_URL", f"sqlite:///{BASE_DIR / 'ransomdb.sqlite'}")

# ─── Detection thresholds ─────────────────────────────────────────────────────
# Risk score = model's predicted probability * 100
# Sessions above this threshold are flagged as ransomware
RISK_THRESHOLD = float(os.getenv("RISK_THRESHOLD", "0.5"))

# Minimum events per session before inference runs
# (too few events = features are noisy)
MIN_EVENTS_FOR_INFERENCE = int(os.getenv("MIN_EVENTS_FOR_INFERENCE", "5"))
