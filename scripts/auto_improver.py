"""
Soteria Automation Task Queue

Manages a lightweight JSON task queue that Make writes to (via webhook)
and Cursor reads from when the user triggers "run the improvement queue".

No LLM calls — Cursor handles all code generation, debugging, and testing.
"""
import json
import os
import sys
import time
import uuid
from pathlib import Path
from datetime import datetime, timezone

QUEUE_PATH = Path(__file__).resolve().parent / "automation_queue.json"
MAX_QUEUE_SIZE = 100


def _load_queue() -> list:
    if not QUEUE_PATH.exists():
        return []
    try:
        data = json.loads(QUEUE_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save_queue(tasks: list):
    QUEUE_PATH.write_text(json.dumps(tasks, indent=2), encoding="utf-8")


def add_task(task_type: str, scope: dict = None, quality_gates: dict = None,
             metadata: dict = None, instruction: str = None) -> dict:
    """Append a new task to the queue. Returns the created task."""
    tasks = _load_queue()

    if len(tasks) >= MAX_QUEUE_SIZE:
        pending = [t for t in tasks if t.get("status") == "pending"]
        if len(pending) >= MAX_QUEUE_SIZE:
            raise ValueError(f"Queue full ({MAX_QUEUE_SIZE} pending tasks).")

    task = {
        "id": str(uuid.uuid4()),
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "task_type": task_type,
        "scope": scope or {},
        "quality_gates": quality_gates or {},
        "metadata": metadata or {},
        "instruction": instruction or "",
        "result": None,
        "completed_at": None
    }
    tasks.append(task)
    _save_queue(tasks)
    return task


def get_pending_tasks() -> list:
    """Return all pending tasks in FIFO order."""
    return [t for t in _load_queue() if t.get("status") == "pending"]


def mark_task(task_id: str, status: str, result: str = None):
    """Update a task's status (in_progress, completed, failed, skipped)."""
    tasks = _load_queue()
    for task in tasks:
        if task["id"] == task_id:
            task["status"] = status
            if result:
                task["result"] = result
            if status in ("completed", "failed", "skipped"):
                task["completed_at"] = datetime.now(timezone.utc).isoformat()
            _save_queue(tasks)
            return task
    return None


def cleanup_completed(max_age_hours: int = 168):
    """Remove completed/failed tasks older than max_age_hours (default 7 days)."""
    tasks = _load_queue()
    cutoff = time.time() - (max_age_hours * 3600)
    kept = []
    removed = 0
    for task in tasks:
        completed_at = task.get("completed_at")
        if completed_at and task.get("status") in ("completed", "failed", "skipped"):
            try:
                ts = datetime.fromisoformat(completed_at).timestamp()
                if ts < cutoff:
                    removed += 1
                    continue
            except (ValueError, TypeError):
                pass
        kept.append(task)
    _save_queue(kept)
    return removed


def queue_summary() -> dict:
    """Return counts by status."""
    tasks = _load_queue()
    summary = {"total": len(tasks), "pending": 0, "in_progress": 0,
               "completed": 0, "failed": 0, "skipped": 0}
    for task in tasks:
        s = task.get("status", "pending")
        if s in summary:
            summary[s] += 1
    return summary


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "summary"

    if action == "summary":
        print(json.dumps(queue_summary(), indent=2))
    elif action == "pending":
        for t in get_pending_tasks():
            print(f"[{t['id'][:8]}] {t['task_type']}: {t.get('instruction', '')[:80]}")
    elif action == "cleanup":
        n = cleanup_completed()
        print(f"Removed {n} old tasks.")
    else:
        print(f"Unknown action: {action}")
        sys.exit(1)
