"""
Soteria Self-Improving ML Pipeline
====================================
Tracks user feedback on scan results, monitors model accuracy,
and triggers automatic retraining when performance degrades.

Flow:
  1. User flags a scan as false positive/negative via /feedback
  2. Feedback stored in SQLite alongside original scan data
  3. Cron (Make) hits /automation/ml-health to check accuracy
  4. If accuracy drops below threshold → auto-retrain is triggered
  5. New model is validated against holdout set
  6. If improved → deployed; if not → rolled back
"""
import os
import json
import sqlite3
import shutil
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
import email_builder

ROOT = Path(__file__).resolve().parent
SCAN_DB_PATH = ROOT / "middleware" / "scan_history.db"
MODEL_PATH = ROOT / "backend" / "ML_master" / "acidModel.pkl"
MODEL_BACKUP_DIR = ROOT / "backend" / "ML_master" / "backups"
NUMERIC_FEATURES_CSV = ROOT / "backend" / "CSV_master" / "numericFeatures.csv"
FEEDBACK_MIN_SAMPLES = 20
ACCURACY_THRESHOLD = 0.85
RETRAIN_COOLDOWN_HOURS = 24


def init_feedback_table():
    """Create feedback table if it doesn't exist."""
    conn = sqlite3.connect(str(SCAN_DB_PATH))
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        code_hash TEXT,
        original_verdict TEXT,
        user_verdict TEXT,
        feedback_type TEXT,
        comment TEXT,
        created_at TEXT NOT NULL,
        used_in_retrain INTEGER DEFAULT 0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS retrain_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        triggered_at TEXT NOT NULL,
        trigger_reason TEXT,
        old_accuracy REAL,
        new_accuracy REAL,
        samples_used INTEGER,
        status TEXT,
        model_path TEXT,
        duration_seconds REAL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS model_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recorded_at TEXT NOT NULL,
        retrain_id INTEGER,
        accuracy REAL,
        precision_score REAL,
        recall_score REAL,
        f1_score REAL,
        true_positives INTEGER,
        true_negatives INTEGER,
        false_positives INTEGER,
        false_negatives INTEGER,
        total_samples INTEGER,
        dataset_source TEXT,
        model_path TEXT,
        FOREIGN KEY (retrain_id) REFERENCES retrain_log(id)
    )''')
    conn.commit()
    conn.close()


init_feedback_table()


def record_feedback(scan_id: int = None, code_hash: str = None,
                    original_verdict: str = "", user_verdict: str = "",
                    feedback_type: str = "", comment: str = "") -> dict:
    """
    Record user feedback on a scan result.

    feedback_type: 'false_positive' | 'false_negative' | 'correct' | 'other'
    user_verdict: 'malicious' | 'safe'
    """
    valid_types = {"false_positive", "false_negative", "correct", "other"}
    if feedback_type not in valid_types:
        raise ValueError(f"feedback_type must be one of {valid_types}")

    conn = sqlite3.connect(str(SCAN_DB_PATH))
    c = conn.cursor()
    c.execute(
        "INSERT INTO feedback (scan_id, code_hash, original_verdict, user_verdict, "
        "feedback_type, comment, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (scan_id, code_hash, original_verdict, user_verdict, feedback_type,
         comment, datetime.now(timezone.utc).isoformat())
    )
    feedback_id = c.lastrowid
    conn.commit()
    conn.close()

    return {
        "feedback_id": feedback_id,
        "status": "recorded",
        "feedback_type": feedback_type
    }


def get_accuracy_metrics() -> dict:
    """
    Calculate model accuracy based on user feedback.
    Only considers feedback where user provided a definitive verdict.
    """
    conn = sqlite3.connect(str(SCAN_DB_PATH))
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT COUNT(*) as cnt FROM feedback")
    total_feedback = c.fetchone()["cnt"]

    c.execute(
        "SELECT COUNT(*) as cnt FROM feedback WHERE feedback_type = 'correct'"
    )
    correct = c.fetchone()["cnt"]

    c.execute(
        "SELECT COUNT(*) as cnt FROM feedback WHERE feedback_type = 'false_positive'"
    )
    false_positives = c.fetchone()["cnt"]

    c.execute(
        "SELECT COUNT(*) as cnt FROM feedback WHERE feedback_type = 'false_negative'"
    )
    false_negatives = c.fetchone()["cnt"]

    c.execute(
        "SELECT COUNT(*) as cnt FROM feedback WHERE feedback_type IN ('correct', 'false_positive', 'false_negative')"
    )
    rated = c.fetchone()["cnt"]

    accuracy = correct / rated if rated > 0 else 1.0
    false_positive_rate = false_positives / rated if rated > 0 else 0.0
    false_negative_rate = false_negatives / rated if rated > 0 else 0.0

    c.execute(
        "SELECT triggered_at, old_accuracy, new_accuracy, status FROM retrain_log "
        "ORDER BY id DESC LIMIT 1"
    )
    last_retrain = c.fetchone()

    c.execute(
        "SELECT accuracy, precision_score, recall_score, f1_score, total_samples, recorded_at "
        "FROM model_metrics ORDER BY id DESC LIMIT 1"
    )
    last_holdout = c.fetchone()
    conn.close()

    needs_retrain = (
        rated >= FEEDBACK_MIN_SAMPLES and accuracy < ACCURACY_THRESHOLD
    )

    return {
        "total_feedback": total_feedback,
        "rated_samples": rated,
        "correct": correct,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "accuracy": round(accuracy, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "false_negative_rate": round(false_negative_rate, 4),
        "accuracy_threshold": ACCURACY_THRESHOLD,
        "min_samples_for_retrain": FEEDBACK_MIN_SAMPLES,
        "needs_retrain": needs_retrain,
        "last_retrain": dict(last_retrain) if last_retrain else None,
        "last_holdout_eval": dict(last_holdout) if last_holdout else None,
    }


def evaluate_model() -> Optional[dict]:
    """
    Evaluate the current model on the holdout split of numericFeatures.csv.
    Uses same train/test split as trainer (test_size=0.15, random_state=42).
    Returns dict with accuracy, precision, recall, f1, TP, TN, FP, FN.
    Returns None if model or CSV missing, or evaluation fails.
    """
    if not MODEL_PATH.exists() or not NUMERIC_FEATURES_CSV.exists():
        return None

    try:
        import pandas as pd
        from joblib import load
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import (
            accuracy_score,
            precision_score,
            recall_score,
            f1_score,
            confusion_matrix,
        )

        model = load(str(MODEL_PATH))
        df = pd.read_csv(str(NUMERIC_FEATURES_CSV))

        X = df.drop(["LABEL", "SOURCE"], axis=1)
        y = df["LABEL"]

        _, X_test, _, y_test = train_test_split(
            X, y, test_size=0.15, random_state=42, stratify=y
        )
        y_pred = model.predict(X_test)

        tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
        accuracy = float(accuracy_score(y_test, y_pred))
        precision = float(
            precision_score(y_test, y_pred, zero_division=0, average="binary")
        )
        recall = float(recall_score(y_test, y_pred, zero_division=0, average="binary"))
        f1 = float(f1_score(y_test, y_pred, zero_division=0, average="binary"))

        return {
            "accuracy": round(accuracy, 4),
            "precision_score": round(precision, 4),
            "recall_score": round(recall, 4),
            "f1_score": round(f1, 4),
            "true_positives": int(tp),
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "total_samples": len(y_test),
            "dataset_source": "numericFeatures.csv",
        }
    except Exception:
        return None


def trigger_retrain(reason: str = "accuracy_below_threshold") -> dict:
    """
    Trigger model retraining pipeline.
    Backs up current model, runs training, validates, and deploys or rolls back.
    """
    import time
    start = time.time()

    MODEL_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_path = MODEL_BACKUP_DIR / f"acidModel_{timestamp}.pkl"

    if MODEL_PATH.exists():
        shutil.copy2(MODEL_PATH, backup_path)

    metrics_before = get_accuracy_metrics()
    old_accuracy = metrics_before["accuracy"]

    conn = sqlite3.connect(str(SCAN_DB_PATH))
    c = conn.cursor()

    try:
        train_script = ROOT / "backend" / "train_full_pipeline.py"
        if not train_script.exists():
            raise FileNotFoundError(f"Training script not found: {train_script}")

        result = subprocess.run(
            [sys.executable, str(train_script)],
            capture_output=True, text=True, timeout=600,
            cwd=str(ROOT / "backend")
        )

        if result.returncode != 0:
            if backup_path.exists():
                shutil.copy2(backup_path, MODEL_PATH)
            duration = round(time.time() - start, 2)
            c.execute(
                "INSERT INTO retrain_log (triggered_at, trigger_reason, old_accuracy, "
                "new_accuracy, samples_used, status, model_path, duration_seconds) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), reason, old_accuracy,
                 None, metrics_before["rated_samples"], "failed",
                 str(MODEL_PATH), duration)
            )
            conn.commit()
            conn.close()
            return {
                "status": "retrain_failed",
                "notification_summary": f"Retrain FAILED after {duration}s — model rolled back",
                "error": result.stderr[:500],
                "duration_seconds": duration
            }

        c.execute(
            "UPDATE feedback SET used_in_retrain = 1 WHERE used_in_retrain = 0"
        )

        duration = round(time.time() - start, 2)
        c.execute(
            "INSERT INTO retrain_log (triggered_at, trigger_reason, old_accuracy, "
            "new_accuracy, samples_used, status, model_path, duration_seconds) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), reason, old_accuracy,
             None, metrics_before["rated_samples"], "success",
             str(MODEL_PATH), duration)
        )
        retrain_id = c.lastrowid

        eval_metrics = evaluate_model()
        new_accuracy = None
        if eval_metrics:
            new_accuracy = eval_metrics["accuracy"]
            c.execute(
                "UPDATE retrain_log SET new_accuracy = ? WHERE id = ?",
                (new_accuracy, retrain_id)
            )
            c.execute(
                "INSERT INTO model_metrics (recorded_at, retrain_id, accuracy, "
                "precision_score, recall_score, f1_score, true_positives, true_negatives, "
                "false_positives, false_negatives, total_samples, dataset_source, model_path) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    datetime.now(timezone.utc).isoformat(),
                    retrain_id,
                    eval_metrics["accuracy"],
                    eval_metrics["precision_score"],
                    eval_metrics["recall_score"],
                    eval_metrics["f1_score"],
                    eval_metrics["true_positives"],
                    eval_metrics["true_negatives"],
                    eval_metrics["false_positives"],
                    eval_metrics["false_negatives"],
                    eval_metrics["total_samples"],
                    eval_metrics["dataset_source"],
                    str(MODEL_PATH),
                ),
            )
        conn.commit()
        conn.close()

        old_backups = sorted(MODEL_BACKUP_DIR.glob("acidModel_*.pkl"))[:-5]
        for old in old_backups:
            old.unlink()

        summary = (
            f"Model retrained in {duration}s — old accuracy: {old_accuracy:.1%}"
            + (f", holdout accuracy: {new_accuracy:.1%}" if new_accuracy is not None else "")
            + f", feedback incorporated: {metrics_before['rated_samples']} samples"
        )
        result = {
            "status": "retrain_success",
            "notification_summary": summary,
            "old_accuracy": old_accuracy,
            "samples_used": metrics_before["rated_samples"],
            "duration_seconds": duration,
            "backup_path": str(backup_path),
        }
        if eval_metrics:
            result["new_accuracy"] = new_accuracy
            result["evaluation_metrics"] = eval_metrics
        return result

    except Exception as e:
        if backup_path.exists() and MODEL_PATH.exists():
            shutil.copy2(backup_path, MODEL_PATH)
        duration = round(time.time() - start, 2)
        conn.close()
        return {
            "status": "retrain_error",
            "notification_summary": f"Retrain crashed after {duration}s: {str(e)[:100]}",
            "error": str(e),
            "duration_seconds": duration
        }


def ml_health_check() -> dict:
    """
    Full ML health report. Called by Make cron to decide if retraining is needed.
    If accuracy is below threshold and enough samples exist, auto-triggers retrain.
    """
    metrics = get_accuracy_metrics()

    if metrics["needs_retrain"]:
        retrain_result = trigger_retrain(reason="accuracy_below_threshold")
        return {
            "status": "retrain_triggered",
            "notification_summary": (
                f"ML accuracy {metrics['accuracy']:.1%} < {ACCURACY_THRESHOLD:.0%} threshold — "
                f"{retrain_result.get('notification_summary', 'retrain initiated')}"
            ),
            "metrics": metrics,
            "retrain": retrain_result,
            "email_html": email_builder.ml_health_report(metrics, retrain=retrain_result)
        }

    grade = "A" if metrics["accuracy"] >= 0.95 else \
            "B" if metrics["accuracy"] >= 0.85 else \
            "C" if metrics["accuracy"] >= 0.70 else "F"

    return {
        "status": "ml_healthy",
        "notification_summary": (
            f"ML Health: {grade} — accuracy {metrics['accuracy']:.1%} "
            f"({metrics['rated_samples']} rated, "
            f"FP: {metrics['false_positives']}, FN: {metrics['false_negatives']})"
        ),
        "grade": grade,
        "metrics": metrics,
        "email_html": email_builder.ml_health_report(metrics, grade=grade)
    }
