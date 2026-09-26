"""
ml-model/train_robust.py

Replaces train.py with a version that actually resists overfitting.

THREE CHANGES FROM THE ORIGINAL:

1. Feature noise augmentation
   Adds small gaussian noise to training features before fitting.
   Forces the model to learn the TREND, not memorise exact values.
   Think of it as telling the model "files_modified_per_sec of 14.3
   and 14.7 are both ransomware" instead of learning one exact number.

2. Stricter model hyperparameters
   - Random Forest: max_depth=8, min_samples_leaf=4
     Without max_depth, trees grow until every training sample is
     perfectly separated — classic overfitting. Capping depth forces
     the model to learn general rules.
   - XGBoost: lower learning_rate, higher min_child_weight, subsample<1
     These are XGBoost's built-in regularization knobs.

3. Stratified K-fold cross-validation with variance reporting
   Instead of one train/test split (which can be lucky or unlucky),
   runs 5 folds and reports mean ± std. If std > 0.05 on F1, the
   model is still unstable — add more diverse data.

Usage:
  python train_robust.py --features ../feature-extraction/output/features.csv
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
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from xgboost import XGBClassifier

FEATURE_COLS = [
    "session_duration_sec", "total_events", "write_count", "read_count",
    "rename_count", "delete_count", "files_modified_per_sec",
    "unique_files_touched", "unique_dirs_touched", "overwrite_ratio",
    "extension_change_count", "extension_change_ratio",
    "mean_entropy_delta", "max_entropy_delta",
    "sequential_score", "max_files_per_10sec",
]


# ─── Data loading ─────────────────────────────────────────────────────────────

def load(csv_path: Path):
    df = pd.read_csv(csv_path)
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        print(f"ERROR: missing columns: {missing}")
        sys.exit(1)
    df = df[df["label"].isin([0, 1])].copy()
    X = df[FEATURE_COLS].fillna(0)
    y = df["label"].astype(int)
    label_counts = y.value_counts().to_dict()
    print(f"  Dataset: {len(df)} rows  |  "
          f"benign={label_counts.get(0,0)}  ransomware={label_counts.get(1,0)}")
    return X, y


# ─── Noise augmentation ───────────────────────────────────────────────────────

def augment(X: pd.DataFrame, noise_std: float = 0.03) -> pd.DataFrame:
    """
    Add small gaussian noise to training features.
    noise_std=0.03 means ±3% random perturbation per feature.

    Why this works: the model can no longer memorise exact feature
    values. It has to learn which REGION of feature space is ransomware,
    not which exact coordinates.
    """
    noise = np.random.normal(0, noise_std, X.shape)
    X_aug = X + X * noise   # relative noise (scales with feature magnitude)
    X_aug = X_aug.clip(lower=0)  # features can't be negative
    return pd.DataFrame(X_aug, columns=X.columns)


# ─── Models ───────────────────────────────────────────────────────────────────

def make_rf():
    return RandomForestClassifier(
        n_estimators=300,
        max_depth=8,              # WAS None (unlimited) — this was the main overfitting cause
        min_samples_leaf=4,       # each leaf must have at least 4 samples
        min_samples_split=8,      # each split needs at least 8 samples
        max_features="sqrt",      # each tree sees sqrt(n_features) features
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

def make_xgb(scale_pos_weight=1.0):
    return XGBClassifier(
        n_estimators=200,
        max_depth=4,              # shallower trees = less overfitting
        learning_rate=0.05,       # WAS 0.1 — slower learning = better generalisation
        subsample=0.8,            # each tree sees 80% of training rows
        colsample_bytree=0.8,     # each tree sees 80% of features
        min_child_weight=3,       # minimum sample weight per leaf
        reg_alpha=0.1,            # L1 regularisation
        reg_lambda=1.0,           # L2 regularisation
        scale_pos_weight=scale_pos_weight,
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


# ─── Cross-validation ─────────────────────────────────────────────────────────

def cv_report(model, X: pd.DataFrame, y: pd.Series, name: str, k: int = 5):
    """
    Stratified K-fold CV. Reports mean ± std for each metric.
    If std > 0.05 on F1, the model is still unstable.
    """
    cv = StratifiedKFold(n_splits=k, shuffle=True, random_state=42)
    scoring = ["accuracy", "precision", "recall", "f1"]
    results = cross_validate(model, X, y, cv=cv, scoring=scoring, n_jobs=-1)

    print(f"\n  {name} — {k}-fold CV (mean ± std):")
    for metric in scoring:
        vals = results[f"test_{metric}"]
        stable = "✓" if vals.std() < 0.05 else "⚠ unstable"
        print(f"    {metric:<12} {vals.mean():.4f} ± {vals.std():.4f}  {stable}")

    return {m: float(results[f"test_{m}"].mean()) for m in scoring}


# ─── Confusion matrix plot ─────────────────────────────────────────────────────

def plot_cms(results: list[dict], out_path: Path):
    n = len(results)
    fig, axes = plt.subplots(1, n, figsize=(5 * n, 4))
    if n == 1:
        axes = [axes]
    for ax, r in zip(axes, results):
        disp = ConfusionMatrixDisplay(r["cm"],
                                      display_labels=["Benign", "Ransomware"])
        disp.plot(ax=ax, colorbar=False, cmap="Blues")
        f1 = r["cv_metrics"]["f1"]
        ax.set_title(f"{r['name']}\nCV F1={f1:.3f}")
    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path}")


def plot_importance(rf, feature_cols: list[str], out_path: Path):
    imp = rf.feature_importances_
    idx = np.argsort(imp)
    colors = ["#e63946" if imp[i] > imp.mean() else "#457b9d" for i in idx]
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.barh([feature_cols[i] for i in idx], [imp[i] for i in idx], color=colors)
    ax.axvline(imp.mean(), color="gray", linestyle="--", linewidth=1,
               label=f"mean ({imp.mean():.3f})")
    ax.set_title("Random Forest Feature Importances (robust model)")
    ax.legend()
    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def run(csv_path: Path, out_dir: Path):
    print(f"\n{'═'*60}")
    print("  Robust Ransomware Detection — Anti-Overfitting Training")
    print(f"{'═'*60}\n")

    X, y = load(csv_path)

    # Train/test split — test set gets NO augmentation (real-world evaluation)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )
    print(f"  Train: {len(X_train)} rows | Test: {len(X_test)} rows")

    # Augment training data only
    X_train_aug = augment(X_train, noise_std=0.03)
    print(f"  Applied noise augmentation (noise_std=0.03) to training set")

    contamination = float((y_train == 1).sum() / len(y_train))
    neg = (y_train == 0).sum()
    pos = (y_train == 1).sum()

    results = []

    # ── Random Forest ──────────────────────────────────────────────────────
    print("\n── Random Forest (regularized) ────────────────────────────")
    rf = make_rf()
    cv_rf = cv_report(rf, X_train_aug, y_train, "Random Forest")
    rf.fit(X_train_aug, y_train)
    rf_pred = rf.predict(X_test)
    results.append({
        "name":       "Random Forest",
        "model":      rf,
        "cv_metrics": cv_rf,
        "cm":         confusion_matrix(y_test, rf_pred),
        "pred":       rf_pred,
    })

    # ── XGBoost ───────────────────────────────────────────────────────────
    print("\n── XGBoost (regularized) ──────────────────────────────────")
    xgb = make_xgb(scale_pos_weight=neg/pos if pos > 0 else 1.0)
    cv_xgb = cv_report(xgb, X_train_aug, y_train, "XGBoost")
    xgb.fit(X_train_aug, y_train)
    xgb_pred = xgb.predict(X_test)
    results.append({
        "name":       "XGBoost",
        "model":      xgb,
        "cv_metrics": cv_xgb,
        "cm":         confusion_matrix(y_test, xgb_pred),
        "pred":       xgb_pred,
    })

    # ── Isolation Forest ──────────────────────────────────────────────────
    print("\n── Isolation Forest (unsupervised) ────────────────────────")
    iso = make_iso(contamination)
    iso.fit(X_train_aug)
    iso_raw  = iso.predict(X_test)
    iso_pred = (iso_raw == -1).astype(int)
    iso_f1   = f1_score(y_test, iso_pred, zero_division=0)
    print(f"  Test F1: {iso_f1:.4f}  (no CV for unsupervised models)")
    results.append({
        "name":       "Isolation Forest",
        "model":      iso,
        "cv_metrics": {"f1": iso_f1, "accuracy": 0, "precision": 0, "recall": 0},
        "cm":         confusion_matrix(y_test, iso_pred),
        "pred":       iso_pred,
    })

    # ── Comparison table ──────────────────────────────────────────────────
    print(f"\n{'═'*60}")
    print(f"  {'Model':<22} {'F1 (CV)':>10} {'Stable?':>10}")
    print(f"{'─'*60}")
    best_f1 = max(r["cv_metrics"]["f1"] for r in results[:2])
    for r in results:
        f1  = r["cv_metrics"]["f1"]
        flag = " ← best" if f1 == best_f1 else ""
        print(f"  {r['name']:<22} {f1:>10.4f}{flag}")
    print(f"{'═'*60}")

    # ── Best model detailed report ─────────────────────────────────────────
    supervised = results[:2]
    best = max(supervised, key=lambda r: r["cv_metrics"]["f1"])
    print(f"\nDetailed report — {best['name']} (test set):")
    print(classification_report(y_test, best["pred"],
                                target_names=["Benign", "Ransomware"]))

    # ── Plots ──────────────────────────────────────────────────────────────
    plot_cms(results, out_dir / "plots" / "confusion_matrices_robust.png")
    plot_importance(rf, FEATURE_COLS, out_dir / "plots" / "feature_importance_robust.png")

    # ── Save ───────────────────────────────────────────────────────────────
    models_dir = out_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)

    joblib.dump(best["model"], models_dir / "best_model.joblib")
    with open(models_dir / "feature_columns.json", "w") as f:
        json.dump(FEATURE_COLS, f, indent=2)

    report = {
        "best_model": best["name"],
        "training_notes": "Robust model: noise augmentation + regularized hyperparameters",
        "models": [{"model": r["name"], "cv_f1": r["cv_metrics"]["f1"]} for r in results],
    }
    with open(models_dir / "evaluation_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n  Saved best model: {models_dir / 'best_model.joblib'}")
    print(f"\n  NEXT: restart the backend to load the new model")
    print(f"        uvicorn main:app --reload --port 8000")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--features", required=True, type=Path)
    parser.add_argument("--out-dir",  default=".",   type=Path)
    args = parser.parse_args()
    if not args.features.exists():
        print(f"Not found: {args.features}")
        sys.exit(1)
    run(args.features, args.out_dir)
