"""
Soteria Dual-Loop Autonomous Agent
===================================
Two distinct autonomous workflows for continuous codebase improvement:

1. Reactive Healing Loop  — triggered by Render deploy failure webhooks
2. Proactive Improvement Loop — triggered by cron/GET to work through ROADMAP.md

Both loops enqueue tasks that Cursor executes autonomously on check-in.
No LLM API calls are made here — Cursor is the execution engine.
"""
import os
import re
import time
import hashlib
import threading
from pathlib import Path
from datetime import datetime, timezone

import sqlite3

from auto_improver import add_task, get_pending_tasks, queue_summary, _load_queue
import email_builder

ROOT = Path(__file__).resolve().parent
ROADMAP_PATH = ROOT / "ROADMAP.md"


# ══════════════════════════════════════════════════════════════════════════════
# CIRCUIT BREAKER
# Prevents infinite healing loops and token drain.
# Max N triggers per hour per unique error signature.
# ══════════════════════════════════════════════════════════════════════════════

class CircuitBreaker:
    def __init__(self, max_triggers: int = 2, window_seconds: int = 3600):
        self.max_triggers = max_triggers
        self.window_seconds = window_seconds
        self._events: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _error_key(self, error_text: str) -> str:
        """Hash error to a stable key (ignores timestamps/line numbers)."""
        cleaned = re.sub(r'\d+', '', error_text.strip().lower())[:500]
        return hashlib.sha256(cleaned.encode()).hexdigest()[:16]

    def allow(self, error_text: str) -> bool:
        """Return True if this error is allowed to trigger a healing attempt."""
        key = self._error_key(error_text)
        now = time.time()
        with self._lock:
            timestamps = self._events.get(key, [])
            timestamps = [t for t in timestamps if now - t < self.window_seconds]
            if len(timestamps) >= self.max_triggers:
                return False
            timestamps.append(now)
            self._events[key] = timestamps
            return True

    def status(self) -> dict:
        """Return current circuit breaker state for diagnostics."""
        now = time.time()
        with self._lock:
            active = {}
            for key, timestamps in self._events.items():
                recent = [t for t in timestamps if now - t < self.window_seconds]
                if recent:
                    active[key] = {
                        "triggers": len(recent),
                        "max": self.max_triggers,
                        "blocked": len(recent) >= self.max_triggers,
                        "resets_in_seconds": int(self.window_seconds - (now - min(recent)))
                    }
            return active


circuit_breaker = CircuitBreaker(max_triggers=2, window_seconds=3600)


# ══════════════════════════════════════════════════════════════════════════════
# LOOP 1: REACTIVE HEALING
# Listens for Render deploy failure webhooks. Extracts error logs and enqueues
# a healing task for Cursor to fix the build, run tests, and open a draft PR.
# ══════════════════════════════════════════════════════════════════════════════

def handle_render_failure(payload: dict) -> dict:
    """
    Process a Render deploy failure webhook payload.
    Returns a structured response dict with status and task info.

    Expected Render webhook payload shape:
    {
        "type": "deploy",
        "event": "deploy_failed",
        "deploy": {
            "id": "...",
            "status": "build_failed" | "update_failed",
            "commit": {"id": "...", "message": "..."},
            "createdAt": "..."
        },
        "service": {"name": "...", "id": "..."},
        "logs": "...build error output..."   # may need to be fetched separately
    }
    """
    event_type = payload.get("event", "")
    deploy = payload.get("deploy", {})
    service = payload.get("service", {})
    logs = payload.get("logs", "")

    deploy_status = deploy.get("status", "unknown")
    commit_info = deploy.get("commit", {})
    commit_id = commit_info.get("id", "unknown")[:8]
    commit_msg = commit_info.get("message", "unknown")[:120]
    service_name = service.get("name", "unknown")

    if not logs:
        logs = f"Deploy {deploy.get('id', 'unknown')} failed with status: {deploy_status}"

    if not circuit_breaker.allow(logs):
        err_key = circuit_breaker._error_key(logs)
        cb_status = circuit_breaker.status()
        return {
            "status": "circuit_breaker_open",
            "notification_summary": f"[BLOCKED] Healing suppressed for {service_name} — circuit breaker open (error repeated too often)",
            "message": f"Healing blocked: error seen too many times in the last hour.",
            "error_key": err_key,
            "breaker_status": cb_status,
            "email_html": email_builder.healing_blocked(service_name, err_key, cb_status)
        }

    error_excerpt = logs[:2000]

    instruction = (
        f"REACTIVE HEALING TASK — Render deploy failed.\n\n"
        f"Service: {service_name}\n"
        f"Deploy status: {deploy_status}\n"
        f"Failing commit: {commit_id} — {commit_msg}\n\n"
        f"Error logs:\n```\n{error_excerpt}\n```\n\n"
        f"Instructions:\n"
        f"1. Analyze the error logs and identify the root cause.\n"
        f"2. Find and fix the bug in the codebase.\n"
        f"3. Run any available tests to verify the fix.\n"
        f"4. Open a DRAFT Pull Request with the fix. Do NOT auto-merge.\n"
        f"5. Include the original error log excerpt in the PR description."
    )

    task = add_task(
        task_type="reactive_healing",
        scope={"trigger": "render_deploy_failure", "service": service_name},
        quality_gates={"require_tests_pass": True, "allow_only_draft_pr": True},
        metadata={
            "deploy_id": deploy.get("id"),
            "deploy_status": deploy_status,
            "commit": commit_id,
            "event": event_type
        },
        instruction=instruction
    )

    qs = queue_summary()
    return {
        "status": "healing_task_enqueued",
        "notification_summary": (
            f"[HEALING] {service_name} deploy failed ({deploy_status}, commit {commit_id}) "
            f"— task enqueued — {qs.get('pending', 0)} pending, {qs.get('in_progress', 0)} in progress"
        ),
        "task_id": task["id"],
        "service": service_name,
        "deploy_status": deploy_status,
        "commit": commit_id,
        "message": "Cursor will analyze and fix on next check-in.",
        "queue_summary": qs,
        "email_html": email_builder.healing_enqueued(task["id"], service_name, deploy_status, commit_id, error_excerpt, qs)
    }


# ══════════════════════════════════════════════════════════════════════════════
# LOOP 2: PROACTIVE IMPROVEMENT
# Reads ROADMAP.md, selects the highest-priority unassigned task, and enqueues
# it for Cursor to implement, test, and open a draft PR.
# ══════════════════════════════════════════════════════════════════════════════

def parse_roadmap() -> list[dict]:
    """
    Parse ROADMAP.md for actionable tasks.

    Expected format (each task is a checkbox line under a priority header):
        ## P0 — Critical
        - [ ] Task description here
        - [x] Already done task (skipped)

        ## P1 — High
        - [ ] Another task
        - [~] In progress task (skipped)
    """
    if not ROADMAP_PATH.exists():
        return []

    content = ROADMAP_PATH.read_text(encoding="utf-8")
    tasks = []
    current_priority = "P2"

    for line in content.splitlines():
        priority_match = re.match(r'^##\s+(P\d)', line, re.IGNORECASE)
        if priority_match:
            current_priority = priority_match.group(1).upper()
            continue

        task_match = re.match(r'^\s*-\s*\[\s*\]\s+(.+)$', line)
        if task_match:
            description = task_match.group(1).strip()
            tasks.append({
                "priority": current_priority,
                "description": description,
                "raw_line": line
            })

    return tasks


def select_next_task(roadmap_tasks: list[dict]) -> dict | None:
    """Select the highest-priority, unassigned task from the roadmap."""
    pending_instructions = {
        t.get("instruction", "")[:80]
        for t in get_pending_tasks()
        if t.get("task_type") == "proactive_improvement"
    }

    priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    sorted_tasks = sorted(
        roadmap_tasks,
        key=lambda t: priority_order.get(t["priority"], 99)
    )

    for task in sorted_tasks:
        if task["description"][:80] not in pending_instructions:
            return task

    return None


def mark_roadmap_in_progress(task_description: str):
    """Update ROADMAP.md to mark a task as in-progress [~]."""
    if not ROADMAP_PATH.exists():
        return

    content = ROADMAP_PATH.read_text(encoding="utf-8")
    old_pattern = f"- [ ] {task_description}"
    new_pattern = f"- [~] {task_description}"
    if old_pattern in content:
        content = content.replace(old_pattern, new_pattern, 1)
        ROADMAP_PATH.write_text(content, encoding="utf-8")


def handle_proactive_improvement() -> dict:
    """
    Select next roadmap task and enqueue it for Cursor execution.
    Returns structured response dict.
    """
    roadmap_tasks = parse_roadmap()
    if not roadmap_tasks:
        return {
            "status": "no_tasks",
            "notification_summary": "No roadmap tasks found — ROADMAP.md is empty or missing",
            "message": "ROADMAP.md is empty or not found. Nothing to improve.",
            "email_html": email_builder.improvement_no_tasks()
        }

    selected = select_next_task(roadmap_tasks)
    if not selected:
        qs = queue_summary()
        return {
            "status": "all_assigned",
            "notification_summary": (
                f"All roadmap tasks already assigned — "
                f"{qs.get('pending', 0)} pending, {qs.get('in_progress', 0)} in progress"
            ),
            "message": "All roadmap tasks are already assigned or in progress.",
            "queue_summary": qs,
            "email_html": email_builder.improvement_all_assigned(qs)
        }

    instruction = (
        f"PROACTIVE IMPROVEMENT TASK — from ROADMAP.md\n\n"
        f"Priority: {selected['priority']}\n"
        f"Task: {selected['description']}\n\n"
        f"Instructions:\n"
        f"1. Analyze the existing Soteria architecture and codebase.\n"
        f"2. Implement this feature/improvement.\n"
        f"3. Ensure it aligns with current codebase analysis standards.\n"
        f"4. Run available tests and fix any failures.\n"
        f"5. Open a DRAFT Pull Request. Do NOT auto-merge.\n"
        f"6. Include a clear description of what was changed and why."
    )

    task = add_task(
        task_type="proactive_improvement",
        scope={"source": "roadmap", "priority": selected["priority"]},
        quality_gates={"require_tests_pass": True, "require_lint_pass": True,
                       "allow_only_draft_pr": True},
        metadata={"roadmap_description": selected["description"]},
        instruction=instruction
    )

    mark_roadmap_in_progress(selected["description"])

    qs = queue_summary()
    return {
        "status": "improvement_task_enqueued",
        "notification_summary": (
            f"[{selected['priority']}] Enqueued: {selected['description'][:100]} "
            f"— {qs.get('pending', 0)} pending, {qs.get('in_progress', 0)} in progress"
        ),
        "task_id": task["id"],
        "priority": selected["priority"],
        "description": selected["description"],
        "message": "Cursor will implement on next check-in.",
        "queue_summary": qs,
        "email_html": email_builder.improvement_enqueued(task["id"], selected["priority"], selected["description"], qs)
    }


# ══════════════════════════════════════════════════════════════════════════════
# DAILY DIGEST
# Aggregates queue state, recent scan stats, circuit breaker health, and
# roadmap progress into a single morning-briefing payload.
# ══════════════════════════════════════════════════════════════════════════════

SCAN_DB_PATH = ROOT / "middleware" / "scan_history.db"


def _recent_scan_stats(hours: int = 24) -> dict:
    """Pull scan statistics from the last N hours."""
    if not SCAN_DB_PATH.exists():
        return {"total_scans": 0, "threats_found": 0, "risk_breakdown": {},
                "top_language": "N/A", "avg_confidence": 0.0}

    cutoff = datetime.now(timezone.utc).isoformat()
    try:
        conn = sqlite3.connect(str(SCAN_DB_PATH))
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute(
            "SELECT COUNT(*) as cnt FROM scans WHERE timestamp >= datetime('now', ?)",
            (f"-{hours} hours",)
        )
        total = c.fetchone()["cnt"]

        c.execute(
            "SELECT COUNT(*) as cnt FROM scans WHERE malicious = 1 AND timestamp >= datetime('now', ?)",
            (f"-{hours} hours",)
        )
        threats = c.fetchone()["cnt"]

        c.execute(
            "SELECT risk_level, COUNT(*) as cnt FROM scans "
            "WHERE timestamp >= datetime('now', ?) GROUP BY risk_level",
            (f"-{hours} hours",)
        )
        risk_breakdown = {row["risk_level"]: row["cnt"] for row in c.fetchall()}

        c.execute(
            "SELECT language, COUNT(*) as cnt FROM scans "
            "WHERE timestamp >= datetime('now', ?) GROUP BY language ORDER BY cnt DESC LIMIT 1",
            (f"-{hours} hours",)
        )
        top_lang_row = c.fetchone()
        top_language = top_lang_row["language"] if top_lang_row else "N/A"

        c.execute(
            "SELECT AVG(confidence) as avg_conf FROM scans WHERE timestamp >= datetime('now', ?)",
            (f"-{hours} hours",)
        )
        avg_conf_row = c.fetchone()
        avg_confidence = round(avg_conf_row["avg_conf"] or 0.0, 3)

        conn.close()
        return {
            "total_scans": total,
            "threats_found": threats,
            "risk_breakdown": risk_breakdown,
            "top_language": top_language,
            "avg_confidence": avg_confidence
        }
    except Exception:
        return {"total_scans": 0, "threats_found": 0, "risk_breakdown": {},
                "top_language": "N/A", "avg_confidence": 0.0}


def _roadmap_progress() -> dict:
    """Count roadmap tasks by status."""
    if not ROADMAP_PATH.exists():
        return {"done": 0, "in_progress": 0, "available": 0, "total": 0}

    content = ROADMAP_PATH.read_text(encoding="utf-8")
    done = len(re.findall(r'^\s*-\s*\[x\]', content, re.MULTILINE))
    in_prog = len(re.findall(r'^\s*-\s*\[~\]', content, re.MULTILINE))
    available = len(re.findall(r'^\s*-\s*\[ \]', content, re.MULTILINE))
    return {"done": done, "in_progress": in_prog, "available": available,
            "total": done + in_prog + available}


def _health_score(qs: dict, scan_stats: dict, cb_status: dict, roadmap: dict) -> dict:
    """Compute a simple 0-100 health score with component breakdown."""
    score = 100
    reasons = []

    pending = qs.get("pending", 0)
    if pending > 10:
        score -= 20
        reasons.append(f"Queue backlog: {pending} pending tasks")
    elif pending > 5:
        score -= 10
        reasons.append(f"Queue growing: {pending} pending tasks")

    blocked = sum(1 for v in cb_status.values() if v.get("blocked"))
    if blocked > 0:
        score -= 25
        reasons.append(f"Circuit breaker: {blocked} error(s) blocked")

    threats = scan_stats.get("threats_found", 0)
    if threats > 5:
        score -= 20
        reasons.append(f"High threat volume: {threats} threats in last 24h")
    elif threats > 0:
        score -= 5
        reasons.append(f"{threats} threat(s) detected in last 24h")

    total_roadmap = roadmap.get("total", 0)
    done_roadmap = roadmap.get("done", 0)
    if total_roadmap > 0 and done_roadmap / total_roadmap < 0.2:
        score -= 10
        reasons.append(f"Roadmap progress low: {done_roadmap}/{total_roadmap} complete")

    score = max(0, min(100, score))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"

    if not reasons:
        reasons.append("All systems healthy")

    return {"score": score, "grade": grade, "reasons": reasons}


def generate_daily_digest() -> dict:
    """Compile the full daily digest payload."""
    qs = queue_summary()
    cb = circuit_breaker.status()
    scan_stats = _recent_scan_stats(hours=24)
    roadmap = _roadmap_progress()
    health = _health_score(qs, scan_stats, cb, roadmap)

    # Gather actual task details for the digest
    available_roadmap_tasks = parse_roadmap()[:7]
    all_queue_tasks = _load_queue()
    queue_tasks = [t for t in all_queue_tasks if t.get("status") in ("pending", "in_progress")]

    summary_parts = [
        f"Health: {health['grade']} ({health['score']}/100)",
        f"Queue: {qs.get('pending', 0)}P/{qs.get('in_progress', 0)}IP/{qs.get('completed', 0)}C",
        f"Scans (24h): {scan_stats['total_scans']} total, {scan_stats['threats_found']} threats",
        f"Roadmap: {roadmap['done']}/{roadmap['total']} done",
    ]

    return {
        "status": "digest_ready",
        "notification_summary": " | ".join(summary_parts),
        "health": health,
        "queue": qs,
        "scans_24h": scan_stats,
        "roadmap_progress": roadmap,
        "circuit_breaker": cb,
        "available_roadmap_tasks": available_roadmap_tasks,
        "queue_tasks": queue_tasks,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "email_html": email_builder.daily_digest(
            health, qs, scan_stats, roadmap, cb,
            available_roadmap_tasks=available_roadmap_tasks,
            queue_tasks=queue_tasks
        )
    }


# ══════════════════════════════════════════════════════════════════════════════
# SCAN-ON-PUSH
# Accepts a GitHub push webhook payload, extracts changed files with raw
# content URLs, and returns them for scanning by the main analyze engine.
# ══════════════════════════════════════════════════════════════════════════════

def extract_push_files(payload: dict) -> dict:
    """
    Parse a GitHub push webhook payload and extract changed file info.

    Returns a structured dict with repo info, commit details, and
    file lists suitable for passing to the /analyze endpoint.
    """
    repo = payload.get("repository", {})
    repo_name = repo.get("full_name", "unknown/unknown")
    ref = payload.get("ref", "unknown")
    branch = ref.split("/")[-1] if "/" in ref else ref
    pusher = payload.get("pusher", {}).get("name", "unknown")

    commits = payload.get("commits", [])
    if not commits:
        return {
            "status": "no_commits",
            "notification_summary": f"Push to {repo_name}/{branch} by {pusher} — no commits to scan",
            "repo": repo_name,
            "branch": branch,
            "pusher": pusher,
            "files": []
        }

    added = set()
    modified = set()
    removed = set()
    commit_messages = []

    for commit in commits:
        added.update(commit.get("added", []))
        modified.update(commit.get("modified", []))
        removed.update(commit.get("removed", []))
        msg = commit.get("message", "")[:80]
        commit_messages.append(f"{commit.get('id', '')[:7]}: {msg}")

    scannable_extensions = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp',
        '.cs', '.go', '.rb', '.php', '.rs', '.sh', '.bash'
    }
    changed = (added | modified) - removed
    scannable = [f for f in changed if any(f.endswith(ext) for ext in scannable_extensions)]

    head_sha = payload.get("after", commits[-1].get("id", "unknown"))[:8]
    raw_url_base = f"https://raw.githubusercontent.com/{repo_name}/{head_sha}"
    file_entries = [{"path": f, "raw_url": f"{raw_url_base}/{f}"} for f in sorted(scannable)]

    total_changed = len(changed)
    total_scannable = len(scannable)

    return {
        "status": "files_extracted",
        "notification_summary": (
            f"Push to {repo_name}/{branch} by {pusher} — "
            f"{total_scannable} scannable file(s) out of {total_changed} changed"
        ),
        "repo": repo_name,
        "branch": branch,
        "pusher": pusher,
        "head_sha": head_sha,
        "commits": commit_messages,
        "files": file_entries,
        "stats": {
            "total_changed": total_changed,
            "scannable": total_scannable,
            "added": len(added),
            "modified": len(modified),
            "removed": len(removed)
        }
    }
