"""
Soteria Automated Lead Generation
====================================
Searches GitHub for public repositories with potential security vulnerabilities,
runs them through the scan engine, generates reports, and prepares outreach data.

Flow:
  1. Make cron hits /automation/lead-scan
  2. GitHub API searched for repos matching vulnerability patterns
  3. Top files from each repo fetched and scanned
  4. Results compiled into a lead report
  5. Make sends personalized outreach email with findings
"""
import os
import json
import sqlite3
import urllib.request
import urllib.parse
from pathlib import Path
from datetime import datetime, timezone
import email_builder

ROOT = Path(__file__).resolve().parent
SCAN_DB_PATH = ROOT / "middleware" / "scan_history.db"
LEADS_DB_PATH = ROOT / "middleware" / "leads.db"

GITHUB_SEARCH_QUERIES = [
    "eval(request language:python",
    "exec(input language:python",
    "subprocess.call(shell=True language:python",
    "dangerouslySetInnerHTML language:javascript",
    "innerHTML language:javascript",
    "child_process.exec language:javascript",
    "sql injection language:python stars:>10",
    "os.system language:python stars:>10",
    "pickle.loads language:python stars:>50",
]

SCANNABLE_EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php'}

MAX_REPOS_PER_RUN = 5
MAX_FILES_PER_REPO = 3


def init_leads_db():
    """Create leads database and tables."""
    conn = sqlite3.connect(str(LEADS_DB_PATH))
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS leads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_full_name TEXT UNIQUE,
        repo_url TEXT,
        owner TEXT,
        owner_email TEXT,
        stars INTEGER,
        language TEXT,
        description TEXT,
        vulnerabilities_found INTEGER DEFAULT 0,
        highest_risk TEXT,
        scan_summary TEXT,
        status TEXT DEFAULT 'new',
        created_at TEXT NOT NULL,
        contacted_at TEXT,
        response TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS lead_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        lead_id INTEGER,
        file_path TEXT,
        risk_level TEXT,
        confidence REAL,
        reason TEXT,
        vulnerabilities TEXT,
        scanned_at TEXT NOT NULL,
        FOREIGN KEY (lead_id) REFERENCES leads(id)
    )''')
    conn.commit()
    conn.close()


init_leads_db()


def _github_search(query: str, max_results: int = 5) -> list[dict]:
    """Search GitHub code API for repositories matching a query."""
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Soteria-LeadGen/1.0"
    }
    if token:
        headers["Authorization"] = f"token {token}"

    encoded = urllib.parse.quote(query)
    url = f"https://api.github.com/search/code?q={encoded}&per_page={max_results}&sort=indexed"

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("items", [])
    except Exception:
        return []


def _fetch_file_content(raw_url: str) -> str:
    """Fetch raw file content from GitHub."""
    try:
        req = urllib.request.Request(raw_url, headers={"User-Agent": "Soteria/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def _dedupe_repos(items: list[dict]) -> dict:
    """Group search results by repo, deduplicating."""
    repos = {}
    for item in items:
        repo = item.get("repository", {})
        full_name = repo.get("full_name", "")
        if not full_name or full_name in repos:
            if full_name in repos:
                repos[full_name]["files"].append(item)
            continue
        repos[full_name] = {
            "full_name": full_name,
            "url": repo.get("html_url", ""),
            "owner": repo.get("owner", {}).get("login", ""),
            "description": repo.get("description", ""),
            "stars": repo.get("stargazers_count", 0),
            "language": repo.get("language", ""),
            "files": [item]
        }
    return repos


def scan_for_leads(query_index: int = None) -> dict:
    """
    Run a lead generation scan.
    Picks a search query, finds repos, scans files, stores results.
    """
    if query_index is not None:
        queries = [GITHUB_SEARCH_QUERIES[query_index % len(GITHUB_SEARCH_QUERIES)]]
    else:
        import random
        queries = random.sample(GITHUB_SEARCH_QUERIES, min(2, len(GITHUB_SEARCH_QUERIES)))

    conn = sqlite3.connect(str(LEADS_DB_PATH))
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT repo_full_name FROM leads")
    existing = {row["repo_full_name"] for row in c.fetchall()}

    all_items = []
    for q in queries:
        items = _github_search(q, max_results=10)
        all_items.extend(items)

    repos = _dedupe_repos(all_items)

    new_leads = []
    for full_name, repo_data in list(repos.items())[:MAX_REPOS_PER_RUN]:
        if full_name in existing:
            continue

        c.execute(
            "INSERT OR IGNORE INTO leads (repo_full_name, repo_url, owner, stars, "
            "language, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (full_name, repo_data["url"], repo_data["owner"],
             repo_data.get("stars", 0), repo_data.get("language", ""),
             (repo_data.get("description") or "")[:200],
             datetime.now(timezone.utc).isoformat())
        )
        lead_id = c.lastrowid
        if not lead_id:
            continue

        vulns_found = 0
        highest_risk = "LOW"
        risk_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        file_results = []

        for file_item in repo_data["files"][:MAX_FILES_PER_REPO]:
            file_path = file_item.get("path", "")
            html_url = file_item.get("html_url", "")

            raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            content = _fetch_file_content(raw_url)
            if not content or len(content) > 50000:
                continue

            scan_result = _quick_scan(content)
            file_results.append({**scan_result, "file": file_path})

            if scan_result.get("malicious"):
                vulns_found += 1
            if risk_order.get(scan_result.get("risk_level", "LOW"), 0) > risk_order.get(highest_risk, 0):
                highest_risk = scan_result["risk_level"]

            c.execute(
                "INSERT INTO lead_scans (lead_id, file_path, risk_level, confidence, "
                "reason, vulnerabilities, scanned_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (lead_id, file_path, scan_result.get("risk_level", "UNKNOWN"),
                 scan_result.get("confidence", 0), scan_result.get("reason", ""),
                 json.dumps(scan_result.get("vulnerabilities", [])),
                 datetime.now(timezone.utc).isoformat())
            )

        c.execute(
            "UPDATE leads SET vulnerabilities_found = ?, highest_risk = ?, "
            "scan_summary = ? WHERE id = ?",
            (vulns_found, highest_risk,
             json.dumps(file_results)[:1000],
             lead_id)
        )

        new_leads.append({
            "repo": full_name,
            "owner": repo_data["owner"],
            "stars": repo_data.get("stars", 0),
            "vulnerabilities_found": vulns_found,
            "highest_risk": highest_risk,
            "files_scanned": len(file_results)
        })

    conn.commit()
    conn.close()

    total_vulns = sum(l["vulnerabilities_found"] for l in new_leads)
    high_value = [l for l in new_leads if l["highest_risk"] in ("HIGH", "CRITICAL")]

    stats = {
        "repos_scanned": len(new_leads),
        "total_vulnerabilities": total_vulns,
        "high_value_targets": len(high_value)
    }
    return {
        "status": "lead_scan_complete",
        "notification_summary": (
            f"Lead scan: {len(new_leads)} new repo(s) found, "
            f"{total_vulns} vulnerability(ies), "
            f"{len(high_value)} high-value target(s)"
        ),
        "leads": new_leads,
        "queries_used": queries,
        "stats": stats,
        "email_html": email_builder.lead_scan_report(new_leads, queries, stats)
    }


def _quick_scan(code: str) -> dict:
    """
    Lightweight vulnerability scan without the full ML pipeline.
    Uses keyword matching for lead generation speed.
    """
    from collections import Counter

    dangerous_patterns = {
        "eval(": {"severity": "HIGH", "cwe": "CWE-95", "desc": "Code injection via eval()"},
        "exec(": {"severity": "HIGH", "cwe": "CWE-95", "desc": "Code injection via exec()"},
        "os.system(": {"severity": "HIGH", "cwe": "CWE-78", "desc": "OS command injection"},
        "subprocess.call(": {"severity": "MEDIUM", "cwe": "CWE-78", "desc": "Subprocess execution"},
        "shell=True": {"severity": "HIGH", "cwe": "CWE-78", "desc": "Shell injection risk"},
        "pickle.loads": {"severity": "HIGH", "cwe": "CWE-502", "desc": "Insecure deserialization"},
        "yaml.load(": {"severity": "MEDIUM", "cwe": "CWE-502", "desc": "Unsafe YAML loading"},
        "innerHTML": {"severity": "MEDIUM", "cwe": "CWE-79", "desc": "XSS via innerHTML"},
        "dangerouslySetInnerHTML": {"severity": "HIGH", "cwe": "CWE-79", "desc": "XSS in React"},
        "document.write": {"severity": "MEDIUM", "cwe": "CWE-79", "desc": "DOM-based XSS"},
        "SELECT * FROM": {"severity": "MEDIUM", "cwe": "CWE-89", "desc": "Potential SQL injection"},
        "f\"SELECT": {"severity": "HIGH", "cwe": "CWE-89", "desc": "SQL injection via f-string"},
        "password": {"severity": "LOW", "cwe": "CWE-798", "desc": "Hardcoded credential reference"},
        "child_process": {"severity": "HIGH", "cwe": "CWE-78", "desc": "Child process execution"},
    }

    found = []
    lines = code.split("\n")
    for line_num, line in enumerate(lines, 1):
        for pattern, info in dangerous_patterns.items():
            if pattern in line:
                found.append({
                    "line": line_num,
                    "pattern": pattern,
                    "severity": info["severity"],
                    "cwe": info["cwe"],
                    "description": info["desc"],
                    "snippet": line.strip()[:100]
                })

    severity_counts = Counter(v["severity"] for v in found)
    is_malicious = severity_counts.get("HIGH", 0) >= 2 or severity_counts.get("CRITICAL", 0) > 0

    if severity_counts.get("HIGH", 0) >= 2 or severity_counts.get("CRITICAL", 0) > 0:
        risk = "HIGH"
    elif severity_counts.get("HIGH", 0) >= 1 or severity_counts.get("MEDIUM", 0) >= 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    confidence = min(0.95, 0.5 + len(found) * 0.1)

    return {
        "malicious": is_malicious,
        "risk_level": risk,
        "confidence": round(confidence, 3),
        "reason": f"Found {len(found)} suspicious pattern(s)" if found else "No suspicious patterns detected",
        "vulnerabilities": found
    }


def get_lead_pipeline_status() -> dict:
    """Summary of the lead pipeline."""
    conn = sqlite3.connect(str(LEADS_DB_PATH))
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT COUNT(*) as cnt FROM leads")
    total = c.fetchone()["cnt"]

    c.execute("SELECT COUNT(*) as cnt FROM leads WHERE status = 'new'")
    new = c.fetchone()["cnt"]

    c.execute("SELECT COUNT(*) as cnt FROM leads WHERE vulnerabilities_found > 0")
    with_vulns = c.fetchone()["cnt"]

    c.execute("SELECT COUNT(*) as cnt FROM leads WHERE highest_risk IN ('HIGH', 'CRITICAL')")
    high_value = c.fetchone()["cnt"]

    c.execute("SELECT COUNT(*) as cnt FROM leads WHERE status = 'contacted'")
    contacted = c.fetchone()["cnt"]

    c.execute(
        "SELECT repo_full_name, owner, stars, vulnerabilities_found, highest_risk "
        "FROM leads WHERE status = 'new' AND vulnerabilities_found > 0 "
        "ORDER BY CASE highest_risk WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
        "WHEN 'MEDIUM' THEN 2 ELSE 3 END, stars DESC LIMIT 5"
    )
    top_leads = [dict(row) for row in c.fetchall()]
    conn.close()

    return {
        "status": "pipeline_summary",
        "notification_summary": (
            f"Lead pipeline: {total} total, {new} new, {with_vulns} with vulns, "
            f"{high_value} high-value, {contacted} contacted"
        ),
        "total_leads": total,
        "new": new,
        "with_vulnerabilities": with_vulns,
        "high_value": high_value,
        "contacted": contacted,
        "top_leads": top_leads
    }
