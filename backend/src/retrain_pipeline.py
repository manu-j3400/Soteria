"""
Online retraining pipeline for Soteria RF ensemble.

Flow:
  1. Read labeled scan rows (user_label IS NOT NULL) from SQLite
  2. Join with training_data to recover code (matched on code_hash prefix)
  3. Derive ground truth: if user said verdict was correct → keep malicious flag;
     if user said verdict was wrong → flip malicious flag
  4. Re-extract full AST feature vector for each sample
  5. Merge with original numericFeatures.csv
  6. Retrain VotingClassifier on combined data
  7. Evaluate on 15% holdout — swap acidModel.pkl only if malicious F1 improves
"""

from __future__ import annotations

import sqlite3
import sys
import warnings
from pathlib import Path
from typing import Any

import pandas as pd

ROOT       = Path(__file__).resolve().parent.parent.parent  # ACID/
DB_PATH    = ROOT / 'middleware' / 'scan_history.db'
CSV_PATH   = ROOT / 'backend' / 'CSV_master' / 'numericFeatures.csv'
CVE_CSV    = ROOT / 'backend' / 'CSV_master' / 'cve_features.csv'
MODEL_PATH = ROOT / 'backend' / 'ML_master' / 'acidModel.pkl'

MIN_NEW_SAMPLES = 10   # refuse retrain below this threshold


# ── Feature extraction ────────────────────────────────────────────────────────

def _ensure_src_on_path() -> None:
    src = str(ROOT / 'backend' / 'src')
    if src not in sys.path:
        sys.path.insert(0, src)


def _extract_features(code: str) -> dict[str, Any] | None:
    """Run extractor_AST.get_Node_Counts() on a Python code string."""
    _ensure_src_on_path()
    try:
        from extractor_AST import get_Node_Counts  # type: ignore[import]
        result = get_Node_Counts(code)
        if isinstance(result, Exception):
            return None
        return result
    except Exception:
        return None


# ── Database helpers ──────────────────────────────────────────────────────────

def _get_labeled_scans(db_path: Path) -> list[dict[str, Any]]:
    """
    Return list of {code, label} for every labeled scan that has a matching
    code entry in training_data.

    user_label semantics:
      1 = "verdict was correct"  → ground truth = scans.malicious
      0 = "verdict was wrong"    → ground truth = 1 - scans.malicious
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            '''SELECT s.code_hash, s.user_label, s.malicious, t.code
               FROM scans s
               JOIN training_data t
                 ON SUBSTR(t.code_hash, 1, 16) = s.code_hash
               WHERE s.user_label IS NOT NULL
                 AND s.code_hash IS NOT NULL
                 AND t.code IS NOT NULL
                 AND LENGTH(t.code) > 0'''
        ).fetchall()
    finally:
        conn.close()

    samples = []
    for r in rows:
        is_malicious = int(r['malicious'])
        if r['user_label'] == 0:          # user said verdict was wrong
            is_malicious = 1 - is_malicious
        samples.append({'code': r['code'], 'label': is_malicious})
    return samples


# ── Feature DataFrame builder ─────────────────────────────────────────────────

def _build_features_df(
    samples: list[dict[str, Any]],
    feature_cols: list[str],
) -> tuple[pd.DataFrame, pd.Series]:
    """
    Extract features from each sample, align to feature_cols.
    Samples that fail feature extraction are silently dropped.
    Returns (X DataFrame, y Series).
    """
    rows: list[dict] = []
    labels: list[int] = []
    for s in samples:
        feats = _extract_features(s['code'])
        if feats is None:
            continue
        rows.append(feats)
        labels.append(int(s['label']))

    if not rows:
        return pd.DataFrame(columns=feature_cols), pd.Series(dtype=int)

    X = pd.DataFrame(rows).reindex(columns=feature_cols, fill_value=0)
    y = pd.Series(labels, dtype=int)
    return X, y


# ── Model builder (mirrors trainerModel_AST.py) ───────────────────────────────

def _build_ensemble():
    from sklearn.ensemble import (
        RandomForestClassifier,
        GradientBoostingClassifier,
        ExtraTreesClassifier,
        VotingClassifier,
    )
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    rf = RandomForestClassifier(
        n_estimators=300, max_depth=15,
        min_samples_leaf=1, min_samples_split=2,
        class_weight='balanced', random_state=42,
    )
    gb = GradientBoostingClassifier(
        n_estimators=200, max_depth=5,
        learning_rate=0.1, random_state=42,
    )
    et = ExtraTreesClassifier(
        n_estimators=300, max_depth=15,
        class_weight='balanced', random_state=42, n_jobs=-1,
    )
    lr_pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('lr', LogisticRegression(
            class_weight='balanced', max_iter=5000,
            random_state=42, solver='liblinear', C=0.5,
        )),
    ])
    return VotingClassifier(
        estimators=[('rf', rf), ('gb', gb), ('et', et), ('lr', lr_pipeline)],
        voting='soft', n_jobs=-1,
    )


# ── Main entry point ──────────────────────────────────────────────────────────

def run_retrain(
    db_path: Path = DB_PATH,
    csv_path: Path = CSV_PATH,
    cve_csv: Path = CVE_CSV,
    model_path: Path = MODEL_PATH,
    min_new_samples: int = MIN_NEW_SAMPLES,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Run the full retrain pipeline.  Returns a result dict:
      {
        status:       'done' | 'skipped' | 'error',
        new_samples:  int,
        old_f1:       float | None,
        new_f1:       float | None,
        swapped:      bool,
        reason:       str,
      }
    """
    from sklearn.metrics import f1_score
    from sklearn.model_selection import train_test_split
    from joblib import dump, load

    result: dict[str, Any] = {
        'status': 'error',
        'new_samples': 0,
        'old_f1': None,
        'new_f1': None,
        'swapped': False,
        'reason': '',
    }

    # 1. Load original CSV (+ optional CVE features CSV)
    if not csv_path.exists():
        result['reason'] = f'numericFeatures.csv not found: {csv_path}'
        return result

    orig_df = pd.read_csv(csv_path)
    # Merge CVE scraper output if available
    if cve_csv.exists():
        try:
            cve_df = pd.read_csv(cve_csv)
            orig_df = pd.concat([orig_df, cve_df], ignore_index=True)
            print(f'[retrain] Merged cve_features.csv: +{len(cve_df)} rows → {len(orig_df)} total')
        except Exception as e:
            print(f'[retrain] Warning: could not load cve_features.csv: {e}')

    feature_cols = [c for c in orig_df.columns if c not in ('LABEL', 'SOURCE')]
    X_orig = orig_df[feature_cols].fillna(0)
    y_orig = orig_df['LABEL'].astype(int)

    # 2. Load labeled scans
    labeled = _get_labeled_scans(db_path)
    result['new_samples'] = len(labeled)
    if len(labeled) < min_new_samples:
        result['status'] = 'skipped'
        result['reason'] = (
            f'Only {len(labeled)} labeled samples available '
            f'(minimum required: {min_new_samples})'
        )
        return result

    # 3. Extract features from new samples
    X_new, y_new = _build_features_df(labeled, feature_cols)
    if len(X_new) == 0:
        result['reason'] = 'Feature extraction failed for all new samples (non-Python code?)'
        return result
    result['new_samples'] = len(X_new)

    # 4. Merge
    X_combined = pd.concat([X_orig, X_new], ignore_index=True)
    y_combined = pd.concat([y_orig, y_new], ignore_index=True)

    # 5. Split — same ratio as original training
    X_train, X_test, y_train, y_test = train_test_split(
        X_combined, y_combined,
        test_size=0.15, random_state=42, stratify=y_combined,
    )

    # 6. Baseline: evaluate current model on same test split
    try:
        current_model = load(model_path)
        y_pred_old = current_model.predict(X_test)
        old_f1 = round(float(f1_score(y_test, y_pred_old, pos_label=1, zero_division=0)), 4)
        result['old_f1'] = old_f1
    except Exception as e:
        result['reason'] = f'Could not evaluate current model: {e}'
        return result

    # 7. Train new model
    new_model = _build_ensemble()
    with warnings.catch_warnings():
        warnings.filterwarnings('ignore', category=RuntimeWarning)
        new_model.fit(X_train, y_train)

    y_pred_new = new_model.predict(X_test)
    new_f1 = round(float(f1_score(y_test, y_pred_new, pos_label=1, zero_division=0)), 4)
    result['new_f1'] = new_f1

    # 8. Swap only if malicious-class F1 improved
    improved = new_f1 > old_f1
    if improved and not dry_run:
        dump(new_model, model_path)
        result['swapped'] = True
        result['reason'] = f'Malicious F1 improved: {old_f1:.4f} → {new_f1:.4f}'
    elif dry_run:
        result['reason'] = (
            f'Dry run — would {"SWAP" if improved else "keep"} '
            f'({old_f1:.4f} → {new_f1:.4f})'
        )
    else:
        result['reason'] = f'No improvement ({old_f1:.4f} → {new_f1:.4f}); keeping current model'

    result['status'] = 'done'
    return result


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == '__main__':
    import argparse, json

    parser = argparse.ArgumentParser(description='Soteria RF online retraining pipeline')
    parser.add_argument('--dry-run', action='store_true',
                        help='Evaluate but do not write model file')
    parser.add_argument('--min-samples', type=int, default=MIN_NEW_SAMPLES,
                        help=f'Minimum new labeled samples (default: {MIN_NEW_SAMPLES})')
    args = parser.parse_args()

    result = run_retrain(min_new_samples=args.min_samples, dry_run=args.dry_run)
    print(json.dumps(result, indent=2))
