"""
CVE Scraper: NVD + GitHub → labeled Python function pairs for RF retraining.

Pipeline:
  1. NVD API v2      → recent high/critical CVEs with GitHub commit references
  2. GitHub API      → commit diff → identify changed .py files
  3. GitHub contents → fetch file at parent SHA (before) and commit SHA (after)
  4. AST diff        → extract function pairs that changed
  5. Feature extract → run extractor_AST.get_Node_Counts() on each function
  6. CSV output      → same schema as numericFeatures.csv (LABEL + SOURCE + AST cols)

Setup:
  export GITHUB_TOKEN=ghp_...     # required: 5000 req/hr vs 60/hr unauthenticated
  export NVD_API_KEY=...          # optional: relaxes NVD rate limit

Usage:
  python cve_scraper.py --output cve_features.csv --limit 500
  python cve_scraper.py --start-date 2023-01-01 --end-date 2024-12-31 --output out.csv
  python cve_scraper.py --resume   # continues from state file
"""

from __future__ import annotations

import ast
import csv
import hashlib
import json
import os
import re
import sys
import time
from base64 import b64decode
from pathlib import Path
from typing import Any, Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent.parent

GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')
NVD_API_KEY  = os.environ.get('NVD_API_KEY', '')

# Rate-limit headroom (seconds between requests)
_NVD_DELAY    = 0.7   # NVD: ~100 req/30s without key; conservative
_GITHUB_DELAY = 0.8   # GitHub: 5000 req/hr auth → ~1.38 req/s; stay well below

# State file for resumability
_STATE_FILE = ROOT / 'backend' / 'CSV_master' / '.cve_scraper_state.json'

# ── HTTP helper ───────────────────────────────────────────────────────────────

def _get(url: str, headers: dict, retries: int = 3, delay: float = _GITHUB_DELAY) -> Any:
    """
    Rate-limited GET with retry on 429/5xx.
    Returns parsed JSON or raises on unrecoverable error.
    """
    time.sleep(delay)
    for attempt in range(retries):
        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=20) as resp:
                return json.loads(resp.read().decode())
        except HTTPError as e:
            if e.code == 404:
                return None
            if e.code in (429, 403, 503):
                wait = 60 * (attempt + 1)
                print(f'  [rate-limit] HTTP {e.code} — sleeping {wait}s', flush=True)
                time.sleep(wait)
                continue
            if e.code >= 500:
                time.sleep(10 * (attempt + 1))
                continue
            return None
        except (URLError, Exception):
            time.sleep(5 * (attempt + 1))
    return None


# ── NVD client ────────────────────────────────────────────────────────────────

_NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
_GITHUB_COMMIT_RE = re.compile(
    r'https://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})',
    re.IGNORECASE,
)
_GITHUB_PR_RE = re.compile(
    r'https://github\.com/([^/]+/[^/]+)/pull/(\d+)',
    re.IGNORECASE,
)


def iter_gh_advisories(
    severities: list[str] = None,
    page_size: int = 100,
) -> Iterator[dict]:
    """
    Yield CVE dicts from GitHub Security Advisories API (pip ecosystem = Python).
    Requires GITHUB_TOKEN. Much more reliable than NVD API.
    Each dict: {cve_id, severity, score, commit_urls: [(repo, sha), ...]}
    """
    if severities is None:
        severities = ['high', 'critical']

    headers = _gh_headers()
    # GitHub advisories API uses a different accept header
    headers['Accept'] = 'application/vnd.github+json'

    for severity in severities:
        page = 1
        while True:
            url = (
                f'https://api.github.com/advisories'
                f'?type=reviewed'
                f'&severity={severity}'
                f'&ecosystem=pip'
                f'&per_page={page_size}'
                f'&page={page}'
            )
            print(f'  [ghsa] {severity} page={page}', flush=True)
            data = _get(url, headers, delay=_GITHUB_DELAY)
            if not data or not isinstance(data, list) or len(data) == 0:
                print(f'  [ghsa] no more results for {severity}', flush=True)
                break

            for item in data:
                ghsa_id  = item.get('ghsa_id', '')
                cve_id   = item.get('cve_id') or ghsa_id
                sev      = item.get('severity', severity)
                score    = item.get('cvss', {}).get('score', 0.0) if item.get('cvss') else 0.0

                # Collect GitHub commit URLs from references
                commit_urls: list[tuple[str, str]] = []
                for ref_url in (item.get('references') or []):
                    m = _GITHUB_COMMIT_RE.search(ref_url)
                    if m:
                        commit_urls.append((m.group(1), m.group(2)))

                # Also check vulnerabilities → patched_versions have associated repo
                if not commit_urls:
                    for vuln in (item.get('vulnerabilities') or []):
                        repo_url = (vuln.get('package') or {}).get('ecosystem', '')
                        # repo info sometimes in advisory source_code_url
                    src_url = item.get('source_code_url') or ''
                    m = _GITHUB_COMMIT_RE.search(src_url)
                    if m:
                        commit_urls.append((m.group(1), m.group(2)))

                if not commit_urls:
                    continue

                yield {
                    'cve_id': cve_id,
                    'severity': sev,
                    'score': score,
                    'commit_urls': commit_urls,
                }

            print(f'  [ghsa] {severity} page {page}: {len(data)} advisories', flush=True)
            if len(data) < page_size:
                break
            page += 1


# ── GitHub client ─────────────────────────────────────────────────────────────

def _gh_headers() -> dict:
    h = {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }
    if GITHUB_TOKEN:
        h['Authorization'] = f'Bearer {GITHUB_TOKEN}'
    return h


def get_commit(repo: str, sha: str) -> dict | None:
    """Fetch commit metadata + file list from GitHub API."""
    url = f'https://api.github.com/repos/{repo}/commits/{sha}'
    return _get(url, _gh_headers())


def get_file_content(repo: str, path: str, ref: str) -> str | None:
    """Fetch decoded file content at a specific git ref. Returns None on missing."""
    url = f'https://api.github.com/repos/{repo}/contents/{quote(path)}?ref={ref}'
    data = _get(url, _gh_headers())
    if not data or data.get('encoding') != 'base64':
        return None
    try:
        return b64decode(data['content']).decode('utf-8', errors='replace')
    except Exception:
        return None


def get_pr_merge_sha(repo: str, pr_number: str) -> str | None:
    """Resolve a PR number to its merge commit SHA."""
    url = f'https://api.github.com/repos/{repo}/pulls/{pr_number}'
    data = _get(url, _gh_headers())
    if not data:
        return None
    mc = data.get('merge_commit_sha')
    return mc if mc else None


# ── AST function extractor ────────────────────────────────────────────────────

def _parse_functions(source: str) -> dict[str, str]:
    """
    Return {func_name: unparsed_source} for all top-level and nested functions.
    Returns empty dict on SyntaxError.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}
    funcs: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            try:
                funcs[node.name] = ast.unparse(node)
            except Exception:
                pass
    return funcs


def extract_changed_functions(before: str, after: str) -> list[tuple[str, str]]:
    """
    Compare two Python file versions.
    Returns list of (before_func_src, after_func_src) for functions whose body changed.
    Excludes trivial whitespace-only or comment-only diffs.
    """
    before_funcs = _parse_functions(before)
    after_funcs  = _parse_functions(after)

    pairs: list[tuple[str, str]] = []
    for name in set(before_funcs) & set(after_funcs):
        b = before_funcs[name]
        a = after_funcs[name]
        if b != a and len(b) > 30 and len(a) > 30:
            pairs.append((b, a))
    return pairs


# ── Feature extraction ────────────────────────────────────────────────────────

def _ensure_src_path() -> None:
    src = str(ROOT / 'backend' / 'src')
    if src not in sys.path:
        sys.path.insert(0, src)


def extract_features(code: str) -> dict[str, Any] | None:
    """Run extractor_AST.get_Node_Counts(). Returns None on failure."""
    _ensure_src_path()
    try:
        from extractor_AST import get_Node_Counts  # type: ignore[import]
        result = get_Node_Counts(code)
        return None if isinstance(result, Exception) else result
    except Exception:
        return None


# ── State / deduplication ─────────────────────────────────────────────────────

def _code_hash(code: str) -> str:
    return hashlib.sha256(code.encode('utf-8', errors='replace')).hexdigest()[:32]


def _load_state() -> dict:
    if _STATE_FILE.exists():
        try:
            return json.loads(_STATE_FILE.read_text())
        except Exception:
            pass
    return {'processed_cves': [], 'processed_hashes': [], 'total_pairs': 0}


def _save_state(state: dict) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(state, indent=2))


def _load_existing_hashes(csv_path: Path) -> set[str]:
    """Load code_hash column from existing CSV to avoid duplicates."""
    hashes: set[str] = set()
    if not csv_path.exists():
        return hashes
    try:
        with open(csv_path, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                src = row.get('SOURCE', '')
                # hashes in SOURCE column prefixed with 'cve_'
                if src and src.startswith('cve_'):
                    hashes.add(src.split('|')[0].replace('cve_', ''))
    except Exception:
        pass
    return hashes


# ── CSV writer ────────────────────────────────────────────────────────────────

def _write_rows(out_path: Path, rows: list[dict], append: bool = True) -> None:
    """Write feature rows to CSV. Auto-detects columns from existing file or rows."""
    if not rows:
        return

    # Determine column set
    all_keys: set[str] = set()
    for row in rows:
        all_keys.update(row.keys())
    all_keys.discard('LABEL')
    all_keys.discard('SOURCE')

    # If existing file present, union columns
    existing_cols: list[str] = []
    if out_path.exists() and append:
        with open(out_path, newline='', encoding='utf-8') as f:
            existing_cols = next(csv.reader(f), [])
        all_cols = existing_cols  # preserve existing order
        # add any new columns
        for k in sorted(all_keys):
            if k not in all_cols and k not in ('LABEL', 'SOURCE'):
                all_cols.append(k)
    else:
        all_cols = sorted(all_keys) + ['LABEL', 'SOURCE']

    mode = 'a' if (out_path.exists() and append) else 'w'
    with open(out_path, mode, newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=all_cols, extrasaction='ignore')
        if mode == 'w':
            writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, 0) for k in all_cols})


# ── Main scrape orchestrator ──────────────────────────────────────────────────

def scrape(
    output: Path,
    limit: int         = 1000,
    start_date: str    = '2022-01-01',
    end_date: str      = '2025-01-01',
    resume: bool       = False,
    min_func_len: int  = 50,
) -> dict[str, int]:
    """
    Run the full scrape pipeline. Returns stats dict.
    """
    if not GITHUB_TOKEN:
        print('WARNING: GITHUB_TOKEN not set — rate limited to 60 req/hr', flush=True)

    state        = _load_state() if resume else _load_state()
    done_cves    = set(state['processed_cves'])
    done_hashes  = set(state['processed_hashes'])
    done_hashes |= _load_existing_hashes(output)

    stats = {
        'cves_processed': 0,
        'commits_fetched': 0,
        'file_pairs_fetched': 0,
        'function_pairs_found': 0,
        'samples_written': 0,
        'skipped_duplicate': 0,
        'skipped_non_python': 0,
        'skipped_parse_error': 0,
    }

    batch: list[dict] = []
    BATCH_SIZE = 50

    def _flush():
        if batch:
            _write_rows(output, batch)
            stats['samples_written'] += len(batch)
            batch.clear()

    print(f'[cve_scraper] Output: {output}', flush=True)
    print(f'[cve_scraper] Limit: {limit} samples | {start_date} → {end_date}', flush=True)

    for cve in iter_gh_advisories():
        if stats['samples_written'] >= limit:
            break

        cve_id = cve['cve_id']
        if cve_id in done_cves:
            continue

        stats['cves_processed'] += 1
        print(f'[{cve_id}] {cve["severity"]} {cve["score"]} — {len(cve["commit_urls"])} commit(s)', flush=True)

        for repo, sha in cve['commit_urls']:
            if stats['samples_written'] >= limit:
                break

            stats['commits_fetched'] += 1
            commit = get_commit(repo, sha)
            if not commit:
                continue

            # Parent SHA for "before" content
            parents = commit.get('parents', [])
            if not parents:
                continue
            parent_sha = parents[0]['sha']

            # Filter to .py files only
            py_files = [
                f for f in commit.get('files', [])
                if f.get('filename', '').endswith('.py')
                and f.get('status') in ('modified', 'renamed')
                and f.get('changes', 0) > 0
            ]

            if not py_files:
                stats['skipped_non_python'] += 1
                continue

            for finfo in py_files:
                if stats['samples_written'] >= limit:
                    break

                path = finfo['filename']
                stats['file_pairs_fetched'] += 1

                before = get_file_content(repo, path, parent_sha)
                after  = get_file_content(repo, path, sha)

                if not before or not after:
                    continue

                pairs = extract_changed_functions(before, after)
                if not pairs:
                    stats['skipped_parse_error'] += 1
                    continue

                stats['function_pairs_found'] += len(pairs)

                for before_func, after_func in pairs:
                    if len(before_func) < min_func_len or len(after_func) < min_func_len:
                        continue

                    for code, label in [(before_func, 1), (after_func, 0)]:
                        h = _code_hash(code)
                        if h in done_hashes:
                            stats['skipped_duplicate'] += 1
                            continue

                        feats = extract_features(code)
                        if feats is None:
                            stats['skipped_parse_error'] += 1
                            continue

                        feats['LABEL']  = label
                        feats['SOURCE'] = f'cve_{h[:12]}|{cve_id}|{repo}'
                        batch.append(feats)
                        done_hashes.add(h)

                        if len(batch) >= BATCH_SIZE:
                            _flush()
                            print(
                                f'  written {stats["samples_written"]} samples | '
                                f'pairs found: {stats["function_pairs_found"]}',
                                flush=True,
                            )

        done_cves.add(cve_id)

        # Persist state periodically
        if stats['cves_processed'] % 20 == 0:
            _flush()
            state['processed_cves']  = list(done_cves)
            state['processed_hashes'] = list(done_hashes)
            state['total_pairs'] = stats['samples_written']
            _save_state(state)

    _flush()
    state['processed_cves']   = list(done_cves)
    state['processed_hashes'] = list(done_hashes)
    state['total_pairs']      = stats['samples_written']
    _save_state(state)

    return stats


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Soteria CVE scraper')
    parser.add_argument(
        '--output', default=str(ROOT / 'backend' / 'CSV_master' / 'cve_features.csv'),
        help='Output CSV path (default: backend/CSV_master/cve_features.csv)',
    )
    parser.add_argument('--limit',      type=int,   default=1000,
                        help='Max labeled samples to collect (default: 1000)')
    parser.add_argument('--start-date', default='2022-01-01',
                        help='NVD CVE publish start date YYYY-MM-DD (default: 2022-01-01)')
    parser.add_argument('--end-date',   default='2025-01-01',
                        help='NVD CVE publish end date YYYY-MM-DD (default: 2025-01-01)')
    parser.add_argument('--resume',     action='store_true',
                        help='Resume from state file (skip already-processed CVEs)')
    parser.add_argument('--min-func-len', type=int, default=50,
                        help='Minimum function source length in chars (default: 50)')
    args = parser.parse_args()

    stats = scrape(
        output       = Path(args.output),
        limit        = args.limit,
        start_date   = args.start_date,
        end_date     = args.end_date,
        resume       = args.resume,
        min_func_len = args.min_func_len,
    )

    print('\n── Results ──────────────────────────────')
    for k, v in stats.items():
        print(f'  {k:<28} {v}')
    print(f'  output                       {args.output}')
