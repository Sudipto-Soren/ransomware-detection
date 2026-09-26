"""
ml-model/train_behavioral.py

Trains on behavioral write-phase features ONLY.
Extension change features are intentionally excluded.

WHY NO EXTENSION FEATURES:
  extension_change_ratio is the RESULT of ransomware completing,
  not an early warning. Including it makes accuracy artificially
  100% — the model learns "renamed to .locked = bad" instead of
  "this process is writing too many files too fast in a sequential
  pattern with high overwrite ratio = bad."

  A real detection system must fire during the WRITE phase, before
  the rename completes. That's what this model does.

WHAT COUNTS AS A GOOD RESULT HERE:
  F1 = 0.88 - 0.96, std < 0.05  → healthy, generalising model
  F1 = 0.97 - 1.00, std = 0.00  → still overfitting, need more data
  F1 < 0.80                      → needs more diverse training data

Usage:
  python3 train_behavioral.py \
      --features ../feature-extraction/output/features_diverse.csv
"""

import argparse
import json
import sys
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    classification_report,
    f1_score,
)
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from xgboost import XGBClassifier

# ─── Behavioral features — NO extension features ──────────────────────────────
FEATURE_COLS = [
    "session_duration_sec",
    "files_modified_per_sec",     # rate of modification — PRIMARY signal
    "overwrite_ratio",            # are files being fully replaced? — PRIMARY signal
    "sequential_score",           # sorted traversal pattern — PRIMARY signal
    "max_files_per_10sec",        # burst intensity — catches slow-avg, fast-burst
    "unique_dirs_touched",        # directory spread
    "write_count",                # total write volume
    "read_count",                 # read volume (ransomware barely reads)
    "unique_files_touched",       # breadth of attack
    "mean_entropy_delta",         # entropy change (weak signal, keep for completeness)
]

# These are intentionally excluded:
#   extension_change_count   → outcome feature, not behavioral
#   extension_change_ratio   → outcome feature, makes problem trivially easy
#   rename_count             → also part of the outcome
#   total_events, delete_count — less informative for behavioral detection


def load(csv_path: Path):
    df = pd.read_csv(csv_path)
    available = [c for c in FEATURE_COLS if c in df.columns]
    missing   = [c for c in FEATURE_COLS if c not in df.columns]

    if missing:
        print(f"  Note: these columns not found, filling with 0: {missing}")

    df = df[df["label"].isin([0, 1])].copy()
    X  = df[available].fillna(0)

    for col in missing:
        X[col] = 0
    X = X[FEATURE_COLS]

    y = df["label"].astype(int)
    counts = y.value_counts().to_dict()
    print(f"  Dataset : {len(df)} rows | benign={counts.get(0,0)} | ransomware={counts.get(1,0)}")
    return X, y


def augment(X: pd.DataFrame, std: float = 0.05) -> pd.DataFrame:
    """Add relative gaussian noise to prevent memorisation."""
    noise = np.random.normal(0, std, X.shape)
    Xa = X + X.abs() * noise
    return pd.DataFrame(Xa.clip(lower=0).values, columns=X.columns)


def make_rf():
    return RandomForestClassifier(
        n_estimators=500,
        max_depth=6,              # shallow — forces generalisation
        min_samples_leaf=5,
        min_samples_split=10,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

def make_xgb(spw=1.0):
    return XGBClassifier(
        n_estimators=300,
        max_depth=3,              # very shallow
        learning_rate=0.03,       # slow learning
        subsample=0.75,
        colsample_bytree=0.75,
        min_child_weight=5,
        reg_alpha=0.3,
        reg_lambda=2.0,
        scale_pos_weight=spw,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )

def make_iso(contamination):
    return IsolationForest(
        n_estimators=300,
        contamination=float(np.clip(contamination, 0.01, 0.49)),
        random_state=42,
        n_jobs=-1,
    )


def cv_eval(model, X, y, name, k=5):
    cv      = StratifiedKFold(n_splits=k, shuffle=True, random_state=42)
    scoring = ["accuracy", "precision", "recall", "f1"]
    res     = cross_validate(model, X, y, cv=cv, scoring=scoring, n_jobs=-1)

    print(f"\n  {name} — {k}-fold CV:")
    all_stable = True
    for m in scoring:
        vals   = res[f"test_{m}"]
        stable = vals.std() < 0.06
        icon   = "✓" if stable else "⚠ high variance"
        if not stable:
            all_stable = False
        print(f"    {m:<12}  {vals.mean():.4f} ± {vals.std():.4f}  {icon}")

    if not all_stable:
        print(f"    → High variance means the model is still unstable.")
        print(f"      Generate more sessions with diverse_dataset_generator.py --n 400")

    return {m: float(res[f"test_{m}"].mean()) for m in scoring}


def plot_cms(results, out_path: Path):
    fig, axes = plt.subplots(1, len(results), figsize=(5 * len(results), 4))
    if len(results) == 1:
        axes = [axes]
    for ax, r in zip(axes, results):
        ConfusionMatrixDisplay(
            r["cm"], display_labels=["Benign", "Ransomware"]
        ).plot(ax=ax, colorbar=False, cmap="Blues")
        ax.set_title(f"{r['name']}\nCV F1={r['cv']['f1']:.3f}")
    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path}")


def plot_importance(rf, out_path: Path):
    imp = rf.feature_importances_
    idx = np.argsort(imp)
    clr = ["#e63946" if imp[i] > imp.mean() else "#457b9d" for i in idx]
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.barh([FEATURE_COLS[i] for i in idx], [imp[i] for i in idx], color=clr)
    ax.axvline(imp.mean(), color="gray", linestyle="--", linewidth=1)
    ax.set_title("Feature Importances — Behavioral Detection\n(no extension features)")
    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path}")


def run(csv_path: Path, out_dir: Path):
    print(f"\n{'═'*60}")
    print("  Behavioral Ransomware Detection — Write-Phase Training")
    print(f"  Features: {len(FEATURE_COLS)} behavioral (no extension features)")
    print(f"{'═'*60}\n")

    X, y = load(csv_path)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )
    X_train_aug = augment(X_train, std=0.05)
    contamination = float((y_train == 1).sum() / len(y_train))
    spw = float((y_train == 0).sum() / max((y_train == 1).sum(), 1))

    results = []

    print("\n── Random Forest ──────────────────────────────────────────")
    rf    = make_rf()
    cv_rf = cv_eval(rf, X_train_aug, y_train, "Random Forest")
    rf.fit(X_train_aug, y_train)
    from sklearn.metrics import confusion_matrix
    rf_pred = rf.predict(X_test)
    results.append({"name": "Random Forest", "model": rf,
                    "cv": cv_rf, "cm": confusion_matrix(y_test, rf_pred),
                    "pred": rf_pred})

    print("\n── XGBoost ────────────────────────────────────────────────")
    xgb    = make_xgb(spw)
    cv_xgb = cv_eval(xgb, X_train_aug, y_train, "XGBoost")
    xgb.fit(X_train_aug, y_train)
    xgb_pred = xgb.predict(X_test)
    results.append({"name": "XGBoost", "model": xgb,
                    "cv": cv_xgb, "cm": confusion_matrix(y_test, xgb_pred),
                    "pred": xgb_pred})

    print("\n── Isolation Forest ───────────────────────────────────────")
    iso      = make_iso(contamination)
    iso.fit(X_train_aug)
    iso_pred = (iso.predict(X_test) == -1).astype(int)
    iso_f1   = f1_score(y_test, iso_pred, zero_division=0)
    print(f"  Test F1: {iso_f1:.4f}")
    results.append({"name": "Isolation Forest", "model": iso,
                    "cv": {"f1": iso_f1}, "cm": confusion_matrix(y_test, iso_pred),
                    "pred": iso_pred})

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{'═'*60}")
    print(f"  {'Model':<24} {'CV F1':>8}   Interpretation")
    print(f"{'─'*60}")
    for r in results:
        f1   = r["cv"]["f1"]
        note = ("⚠ still overfitting" if f1 >= 0.995
                else "✓ healthy" if f1 >= 0.85
                else "⚠ too low — needs more data")
        print(f"  {r['name']:<24} {f1:>8.4f}   {note}")
    print(f"{'═'*60}")
    print("""
  Target range: F1 = 0.88 – 0.95  (realistic for behavioral detection)
  If still showing 1.0000: run diverse_dataset_generator.py --n 400
  If showing < 0.80: run diverse_dataset_generator.py --n 400 --harder
""")

    best_sup = max(results[:2], key=lambda r: r["cv"]["f1"])
    print(f"Detailed report — {best_sup['name']} (test set):")
    print(classification_report(y_test, best_sup["pred"],
                                target_names=["Benign", "Ransomware"]))

    plot_cms(results, out_dir / "plots" / "confusion_behavioral.png")
    plot_importance(rf, out_dir / "plots" / "importance_behavioral.png")

    # Save model + updated feature columns
    models_dir = out_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(best_sup["model"], models_dir / "best_model.joblib")
    with open(models_dir / "feature_columns.json", "w") as f:
        json.dump(FEATURE_COLS, f, indent=2)

    print(f"\n  Saved: {models_dir / 'best_model.joblib'}")
    print(f"  Restart backend to pick up new model.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--features", required=True, type=Path)
    parser.add_argument("--out-dir",  default=".", type=Path)
    args = parser.parse_args()
    if not args.features.exists():
        print(f"Not found: {args.features}")
        sys.exit(1)
    run(args.features, args.out_dir)
