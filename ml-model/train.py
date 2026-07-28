"""
ml-model/train.py

Trains and compares three models on the labeled feature CSV produced
by feature-extraction/extractor.py:

  1. Random Forest    — supervised, strong baseline
  2. XGBoost          — supervised, usually best on tabular data
  3. Isolation Forest — unsupervised, zero-day detection capability

For each supervised model:
  - 5-fold stratified cross-validation  (reliable estimate, small dataset)
  - Single 80/20 train-test split        (for confusion matrix + export)

Outputs
  models/best_model.joblib        — best supervised model (by F1)
  models/feature_columns.json     — exact column order the model expects
  plots/confusion_matrices.png    — side-by-side confusion matrices
  plots/feature_importance.png    — top features by RF importance
  models/evaluation_report.json  — all metrics, machine-readable

Usage:
  python train.py --features ../feature-extraction/output/features.csv
  python train.py --features ../feature-extraction/output/features.csv --test-size 0.25
"""

import argparse
import json
import sys
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")          # non-interactive backend — works without a display
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from xgboost import XGBClassifier

# ─── Feature columns ──────────────────────────────────────────────────────────
# These must match exactly what extractor.py outputs.
# If you add a new feature in extractor.py, add it here too.
FEATURE_COLS = [
    "session_duration_sec",
    "total_events",
    "write_count",
    "read_count",
    "rename_count",
    "delete_count",
    "files_modified_per_sec",
    "unique_files_touched",
    "unique_dirs_touched",
    "overwrite_ratio",
    "extension_change_count",
    "extension_change_ratio",
    "mean_entropy_delta",
    "max_entropy_delta",
    "sequential_score",
    "max_files_per_10sec",
]


# ─── 1. Data loading ──────────────────────────────────────────────────────────

def load_data(csv_path: Path) -> tuple[pd.DataFrame, pd.Series, list[str]]:
    """
    Load the feature CSV, validate columns, return (X, y, feature_cols).
    Drops session_id (metadata) and label (target) from X.
    """
    df = pd.read_csv(csv_path)

    # Validate all expected feature columns are present
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        print(f"ERROR: These expected feature columns are missing from the CSV:\n  {missing}")
        print("  Re-run extractor.py to regenerate the CSV.")
        sys.exit(1)

    if "label" not in df.columns:
        print("ERROR: 'label' column not found in the CSV.")
        sys.exit(1)

    # Only keep rows with valid labels (0 or 1)
    df = df[df["label"].isin([0, 1])].copy()

    # Use only the declared feature columns (ignore any extras)
    X = df[FEATURE_COLS].copy()
    y = df["label"].astype(int)

    label_counts = y.value_counts().to_dict()
    print(f"  Loaded {len(df)} labeled rows  "
          f"(benign: {label_counts.get(0, 0)}, "
          f"ransomware-pattern: {label_counts.get(1, 0)})")

    if len(df) < 20:
        print("\n  ⚠  Dataset has fewer than 20 rows. Run more simulator sessions.")
        print("     Results will have very high variance — treat as a sanity check.")

    return X, y, FEATURE_COLS


# ─── 2. Metric helpers ────────────────────────────────────────────────────────

def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, name: str) -> dict:
    """Compute the full set of classification metrics for one model."""
    return {
        "model":     name,
        "accuracy":  round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall":    round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1":        round(f1_score(y_true, y_pred, zero_division=0), 4),
    }


# ─── 3. Model training ────────────────────────────────────────────────────────

def train_random_forest(X_train: pd.DataFrame, y_train: pd.Series) -> RandomForestClassifier:
    """
    Random Forest with 300 trees.
    n_estimators=300: more trees = more stable predictions at little extra cost.
    class_weight='balanced': handles class imbalance if your dataset is skewed.
    random_state=42: reproducible results.
    """
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,        # grow full trees; RF's bagging handles overfitting
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,             # use all CPU cores
    )
    rf.fit(X_train, y_train)
    return rf


def train_xgboost(X_train: pd.DataFrame, y_train: pd.Series) -> XGBClassifier:
    """
    XGBoost gradient-boosted trees.
    eval_metric='logloss' suppresses a deprecation warning.
    scale_pos_weight: auto-balances classes the way class_weight does for RF.
    """
    neg = (y_train == 0).sum()
    pos = (y_train == 1).sum()
    scale = neg / pos if pos > 0 else 1.0

    xgb = XGBClassifier(
        n_estimators=300,
        max_depth=4,
        learning_rate=0.1,
        scale_pos_weight=scale,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )
    xgb.fit(X_train, y_train)
    return xgb


def train_isolation_forest(
    X_train: pd.DataFrame, contamination: float
) -> IsolationForest:
    """
    Isolation Forest — unsupervised anomaly detector.

    contamination: expected fraction of anomalies (ransomware sessions).
    In a real deployment this would be very low (0.01–0.05) because
    ransomware is rare. In our balanced lab dataset it's ~0.5.

    Important: IF never sees labels. It learns the *shape* of normal
    data and flags points that are structurally isolated (easy to
    separate from the rest). That's why it can detect novel ransomware
    variants — their I/O pattern is still anomalous even if it doesn't
    match any training signature.
    """
    iso = IsolationForest(
        n_estimators=300,
        contamination=float(np.clip(contamination, 0.01, 0.49)),
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_train)   # no y — fully unsupervised
    return iso


def isolation_forest_predict(model: IsolationForest, X: pd.DataFrame) -> np.ndarray:
    """
    Convert IF's output to our label convention.
    IF returns: -1 = anomaly (ransomware), +1 = normal (benign)
    We want:     1 = ransomware,            0 = benign
    """
    raw = model.predict(X)
    return (raw == -1).astype(int)


# ─── 4. Cross-validation ──────────────────────────────────────────────────────

def cross_validate_supervised(
    model, X: pd.DataFrame, y: pd.Series, name: str, k: int = 5
) -> dict:
    """
    k-fold stratified CV — gives a more reliable metric estimate
    than a single split when the dataset is small.
    """
    cv = StratifiedKFold(n_splits=k, shuffle=True, random_state=42)
    scores = {
        "accuracy":  cross_val_score(model, X, y, cv=cv, scoring="accuracy",  n_jobs=-1),
        "precision": cross_val_score(model, X, y, cv=cv, scoring="precision", n_jobs=-1),
        "recall":    cross_val_score(model, X, y, cv=cv, scoring="recall",    n_jobs=-1),
        "f1":        cross_val_score(model, X, y, cv=cv, scoring="f1",        n_jobs=-1),
    }
    print(f"\n  {name} — {k}-fold cross-validation:")
    for metric, vals in scores.items():
        print(f"    {metric:<12} {vals.mean():.4f} ± {vals.std():.4f}")
    return {k: float(v.mean()) for k, v in scores.items()}


# ─── 5. Plots ─────────────────────────────────────────────────────────────────

def plot_confusion_matrices(
    results: list[dict],
    out_path: Path,
) -> None:
    """Side-by-side confusion matrices for all three models."""
    n = len(results)
    fig, axes = plt.subplots(1, n, figsize=(5 * n, 4))
    if n == 1:
        axes = [axes]

    for ax, res in zip(axes, results):
        cm = res["confusion_matrix"]
        sns.heatmap(
            cm, annot=True, fmt="d", cmap="Blues", ax=ax,
            xticklabels=["Benign", "Ransomware"],
            yticklabels=["Benign", "Ransomware"],
            cbar=False,
        )
        ax.set_title(f"{res['model']}\nF1={res['metrics']['f1']:.3f}", fontsize=12)
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")

    fig.suptitle("Confusion Matrices — Test Set", fontsize=14, y=1.02)
    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path}")


def plot_feature_importance(
    rf_model: RandomForestClassifier, feature_cols: list[str], out_path: Path
) -> None:
    """
    Horizontal bar chart of Random Forest feature importances.
    Feature importance = mean decrease in impurity across all trees.
    High importance → the model relies heavily on that feature to split.
    """
    importances = rf_model.feature_importances_
    indices = np.argsort(importances)[::-1]

    fig, ax = plt.subplots(figsize=(8, 6))
    colors = ["#e63946" if importances[i] > importances.mean() else "#457b9d"
              for i in indices]
    ax.barh(
        [feature_cols[i] for i in reversed(indices)],
        [importances[i] for i in reversed(indices)],
        color=list(reversed(colors)),
    )
    ax.axvline(importances.mean(), color="gray", linestyle="--", linewidth=1,
               label=f"mean ({importances.mean():.3f})")
    ax.set_xlabel("Feature Importance (mean decrease in impurity)")
    ax.set_title("Random Forest — Feature Importances")
    ax.legend(fontsize=9)
    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path}")


# ─── 6. Comparison table ──────────────────────────────────────────────────────

def print_comparison_table(results: list[dict]) -> None:
    """Print a clean aligned comparison table to stdout."""
    header = f"\n{'Model':<22} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>10}"
    print("\n" + "═" * 65)
    print("  MODEL COMPARISON — TEST SET")
    print("═" * 65)
    print(header)
    print("─" * 65)

    best_f1 = max(r["metrics"]["f1"] for r in results)
    for res in results:
        m = res["metrics"]
        flag = "  ← best" if m["f1"] == best_f1 else ""
        print(
            f"  {res['model']:<20} "
            f"{m['accuracy']:>10.4f} "
            f"{m['precision']:>10.4f} "
            f"{m['recall']:>10.4f} "
            f"{m['f1']:>10.4f}"
            f"{flag}"
        )

    print("═" * 65)
    print("""
  Metric guide:
    Accuracy  — proportion of correct predictions overall
    Precision — of everything flagged as ransomware, how much really is?
                (low precision = many false alarms)
    Recall    — of all actual ransomware, how much did we catch?
                (low recall = missed attacks — worse than false alarms)
    F1        — harmonic mean of precision and recall; best single summary
""")


# ─── 7. Main pipeline ─────────────────────────────────────────────────────────

def run(csv_path: Path, test_size: float, out_dir: Path) -> None:
    print(f"\n{'═'*55}")
    print("  Ransomware Detection — ML Training Pipeline")
    print(f"{'═'*55}")
    print(f"\nLoading: {csv_path}")

    X, y, feature_cols = load_data(csv_path)

    # ── Train/test split ──────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=42
    )
    print(f"\nSplit: {len(X_train)} train / {len(X_test)} test")

    contamination = float((y_train == 1).sum() / len(y_train))
    print(f"Contamination (for Isolation Forest): {contamination:.2f}")

    results = []

    # ── Random Forest ─────────────────────────────────────────────────────────
    print("\n── Random Forest ──────────────────────────────────────────")
    rf = train_random_forest(X_train, y_train)
    cross_validate_supervised(
        RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=42, n_jobs=-1),
        X, y, "Random Forest"
    )
    rf_pred = rf.predict(X_test)
    rf_metrics = compute_metrics(y_test.values, rf_pred, "Random Forest")
    results.append({
        "model":            "Random Forest",
        "model_object":     rf,
        "metrics":          rf_metrics,
        "confusion_matrix": confusion_matrix(y_test, rf_pred),
        "predictions":      rf_pred,
    })

    # ── XGBoost ───────────────────────────────────────────────────────────────
    print("\n── XGBoost ────────────────────────────────────────────────")
    xgb = train_xgboost(X_train, y_train)
    cross_validate_supervised(
        XGBClassifier(n_estimators=300, max_depth=4, learning_rate=0.1,
                      eval_metric="logloss", random_state=42, n_jobs=-1, verbosity=0),
        X, y, "XGBoost"
    )
    xgb_pred = xgb.predict(X_test)
    xgb_metrics = compute_metrics(y_test.values, xgb_pred, "XGBoost")
    results.append({
        "model":            "XGBoost",
        "model_object":     xgb,
        "metrics":          xgb_metrics,
        "confusion_matrix": confusion_matrix(y_test, xgb_pred),
        "predictions":      xgb_pred,
    })

    # ── Isolation Forest ──────────────────────────────────────────────────────
    print("\n── Isolation Forest (unsupervised) ────────────────────────")
    iso = train_isolation_forest(X_train, contamination)
    iso_pred = isolation_forest_predict(iso, X_test)
    iso_metrics = compute_metrics(y_test.values, iso_pred, "Isolation Forest")
    print(f"\n  Isolation Forest — test-set metrics (no CV; unsupervised):")
    for k, v in iso_metrics.items():
        if k != "model":
            print(f"    {k:<12} {v:.4f}")
    print("  (CV not applicable — IF has no concept of a training label)")
    results.append({
        "model":            "Isolation Forest",
        "model_object":     iso,
        "metrics":          iso_metrics,
        "confusion_matrix": confusion_matrix(y_test, iso_pred),
        "predictions":      iso_pred,
    })

    # ── Comparison table ──────────────────────────────────────────────────────
    print_comparison_table(results)

    # ── Detailed report for best supervised model ─────────────────────────────
    supervised = [r for r in results if r["model"] != "Isolation Forest"]
    best = max(supervised, key=lambda r: r["metrics"]["f1"])
    print(f"\nDetailed classification report — {best['model']}:")
    print(classification_report(y_test, best["predictions"],
                                target_names=["Benign", "Ransomware"]))

    # ── Plots ─────────────────────────────────────────────────────────────────
    print("\nGenerating plots ...")
    plot_confusion_matrices(results, out_dir / "plots" / "confusion_matrices.png")
    plot_feature_importance(rf, feature_cols, out_dir / "plots" / "feature_importance.png")

    # ── Save best model ───────────────────────────────────────────────────────
    models_dir = out_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)

    model_path = models_dir / "best_model.joblib"
    joblib.dump(best["model_object"], model_path)
    print(f"\nSaved best model ({best['model']}): {model_path}")

    # Save the feature column order — the backend must send features in this
    # exact order when calling model.predict() at inference time
    feat_path = models_dir / "feature_columns.json"
    with open(feat_path, "w") as f:
        json.dump(feature_cols, f, indent=2)
    print(f"Saved feature columns:           {feat_path}")

    # Save all metrics as JSON for the backend/dashboard to display
    report_path = models_dir / "evaluation_report.json"
    report = {
        "best_model": best["model"],
        "models": [
            {"model": r["model"], "metrics": r["metrics"]}
            for r in results
        ],
        "feature_cols": feature_cols,
        "dataset": {
            "total_rows": len(X),
            "train_rows": len(X_train),
            "test_rows":  len(X_test),
            "label_0_count": int((y == 0).sum()),
            "label_1_count": int((y == 1).sum()),
        }
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Saved evaluation report:         {report_path}")

    print(f"\n{'═'*55}")
    print("  Training complete.")
    print(f"  Best model: {best['model']}  (F1 = {best['metrics']['f1']:.4f})")
    print(f"{'═'*55}")
    print("\nNext step:")
    print("  The saved model + feature_columns.json are what the backend")
    print("  loads to score incoming events in real time.")
    print("  → cd ../backend && python main.py")


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train and compare ransomware detection models")
    parser.add_argument(
        "--features", required=True, type=Path,
        help="Path to labeled features CSV from feature-extraction/extractor.py",
    )
    parser.add_argument(
        "--test-size", default=0.20, type=float,
        help="Fraction of data to use as test set (default 0.20)",
    )
    parser.add_argument(
        "--out-dir", default=".", type=Path,
        help="Directory to write models/ and plots/ into (default: current dir)",
    )
    args = parser.parse_args()

    if not args.features.exists():
        print(f"Features CSV not found: {args.features}")
        print("Run feature-extraction/extractor.py first.")
        sys.exit(1)

    run(args.features, args.test_size, args.out_dir)
