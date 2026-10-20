"""
Pull new PyPI releases and store only their .py sources, without installing
or executing anything.

Two modes:
  backfill  enumerate releases from the last N days via the PyPI changelog
            (XML-RPC changelog_since_serial). Malware taken down before we
            download it shows up as status=unavailable, so a backfill
            undercounts true positives.
  live      poll the changelog every few minutes and download each release
            as it appears, so takedowns can't remove it before we see it.

Safety:
  - Archives are opened with tarfile/zipfile only. No setup.py, no pip,
    no build backend, nothing imported from the downloaded tree.
  - Only regular-file members ending in .py are written. Links, devices,
    absolute paths and '..' components are skipped.
  - Per-member and per-archive size caps guard against decompression bombs.
  - Archives are deleted after extraction; only .py text stays on disk.

Usage:
  python3 -I fetch_pypi.py backfill --days 7 --out ~/soteria_pypi_eval
  python3 -I fetch_pypi.py live --hours 168 --out ~/soteria_pypi_eval
"""
from __future__ import annotations

import argparse
import io
import json
import random
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.request
import xmlrpc.client
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath

PYPI_XMLRPC = "https://pypi.org/pypi"
UA = "soteria-precision-eval/0.1 (research; contact via github.com/manu-j3400/Soteria)"

MAX_ARCHIVE_BYTES = 30 * 1024 * 1024   # skip bigger dists
MAX_MEMBER_BYTES = 2 * 1024 * 1024     # skip bigger single .py files
MAX_TOTAL_PY_BYTES = 40 * 1024 * 1024  # stop extracting a dist past this
CHANGELOG_CHUNK = 20000
AV_SETTLE_SECONDS = 2  # give real-time antivirus a moment before checking files


def _http_get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _rpc() -> xmlrpc.client.ServerProxy:
    return xmlrpc.client.ServerProxy(PYPI_XMLRPC)


# ── Changelog enumeration ────────────────────────────────────────────────────

def serial_at(ts: int) -> int:
    """Binary-search the changelog serial whose event time is ~ts."""
    rpc = _rpc()
    hi = rpc.changelog_last_serial()
    lo = hi - 3_000_000
    while hi - lo > 2000:
        mid = (lo + hi) // 2
        ev = rpc.changelog_since_serial(mid)[:1]
        if not ev or ev[0][2] >= ts:
            hi = mid
        else:
            lo = mid
        time.sleep(0.2)
    return lo


def iter_events(since_serial: int, until_ts: int | None = None):
    rpc = _rpc()
    serial = since_serial
    while True:
        ev = rpc.changelog_since_serial(serial)
        if not ev:
            return
        for e in ev:
            if until_ts and e[2] > until_ts:
                return
            yield e
        serial = ev[-1][4]
        if len(ev) < 10:
            return
        time.sleep(0.5)


def releases_from_events(events) -> dict[tuple[str, str], dict]:
    """Collapse raw events into one record per (name, version)."""
    created: set[str] = set()
    out: dict[tuple[str, str], dict] = {}
    for name, version, ts, action, serial in events:
        action = action or ""
        if action == "create":
            created.add(name.lower())
        if version and (action.startswith("new release") or action.startswith("add ")):
            key = (name, version)
            if key not in out:
                out[key] = {"name": name, "version": version, "ts": ts, "serial": serial}
    for rec in out.values():
        rec["new_project_event"] = rec["name"].lower() in created
    return out


# ── Download + safe extraction ───────────────────────────────────────────────

def _choose_file(urls: list[dict]) -> dict | None:
    sdists = [u for u in urls if u.get("packagetype") == "sdist"]
    pure = [u for u in urls if u.get("packagetype") == "bdist_wheel" and u["filename"].endswith("-none-any.whl")]
    wheels = [u for u in urls if u.get("packagetype") == "bdist_wheel"]
    for group in (sdists, pure, wheels):
        if group:
            return min(group, key=lambda u: u.get("size", 0))
    return None


def _safe_rel(name: str) -> PurePosixPath | None:
    p = PurePosixPath(name.replace("\\", "/"))
    if p.is_absolute() or any(part in ("..", "") for part in p.parts):
        return None
    return p


def extract_py(blob: bytes, filename: str, dest: Path) -> tuple[int, int, list[str]]:
    """Write .py members of an archive under dest.

    Returns (n_unique_files, n_bytes, written_rel_paths). Duplicate member
    names overwrite, so files are counted by unique path.
    """
    written: dict[str, int] = {}

    def write(rel: str, data: bytes):
        safe = _safe_rel(rel)
        if safe is None:
            return
        target = dest / safe
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        written[str(safe)] = len(data)

    if filename.endswith((".whl", ".zip", ".egg")):
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.endswith(".py"):
                    continue
                if info.file_size > MAX_MEMBER_BYTES or sum(written.values()) > MAX_TOTAL_PY_BYTES:
                    continue
                # zip "symlinks" carry S_IFLNK in the high external_attr bits
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    continue
                write(info.filename, zf.read(info))
    else:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
            for m in tf:
                if not m.isreg() or not m.name.endswith(".py"):
                    continue
                if m.size > MAX_MEMBER_BYTES or sum(written.values()) > MAX_TOTAL_PY_BYTES:
                    continue
                f = tf.extractfile(m)
                if f is not None:
                    write(m.name, f.read(MAX_MEMBER_BYTES + 1)[:MAX_MEMBER_BYTES])
    return len(written), sum(written.values()), list(written)


def fetch_release(rec: dict, root: Path) -> dict:
    name, version = rec["name"], rec["version"]
    out = dict(rec)
    try:
        meta = json.loads(_http_get(f"https://pypi.org/pypi/{name}/{version}/json"))
    except urllib.error.HTTPError as e:
        out["status"] = "unavailable" if e.code == 404 else f"http_{e.code}"
        return out
    except Exception as e:  # network hiccup
        out["status"] = f"error:{type(e).__name__}"
        return out

    info = meta.get("info", {})
    out["summary"] = (info.get("summary") or "")[:200]
    out["home_page"] = info.get("home_page") or (info.get("project_urls") or {}).get("Homepage")
    out["n_releases"] = None
    try:
        proj = json.loads(_http_get(f"https://pypi.org/pypi/{name}/json"))
        out["n_releases"] = len(proj.get("releases", {}))
    except Exception:
        pass
    out["new_project"] = bool(rec.get("new_project_event")) or out["n_releases"] == 1

    f = _choose_file(meta.get("urls", []))
    if f is None:
        out["status"] = "no_files"
        return out
    out["dist_file"] = f["filename"]
    out["dist_size"] = f.get("size")
    if (f.get("size") or 0) > MAX_ARCHIVE_BYTES:
        out["status"] = "too_big"
        return out
    try:
        blob = _http_get(f["url"], timeout=120)
        dest = root / "pkgs" / name.lower() / version
        n_files, n_bytes, written = extract_py(blob, f["filename"], dest)
        # real-time antivirus removes known malware right after the write;
        # record it so the scorer can count it instead of silently skipping it
        time.sleep(AV_SETTLE_SECONDS)
        gone = [r for r in written if not (dest / r).exists()]
        out.update(status="ok" if n_files else "no_py", n_py=n_files, n_py_unique=n_files,
                   py_bytes=n_bytes, path=str(dest.relative_to(root)),
                   av_removed=gone[:50], n_av_removed=len(gone))
    except Exception as e:
        out["status"] = f"extract_error:{type(e).__name__}"
    return out


# ── Drivers ──────────────────────────────────────────────────────────────────

class Manifest:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.done: set[tuple[str, str]] = set()
        if path.exists():
            for line in path.read_text().splitlines():
                r = json.loads(line)
                self.done.add((r["name"], r["version"]))

    def write(self, rec: dict):
        with self.lock:
            with self.path.open("a") as fh:
                fh.write(json.dumps(rec) + "\n")
            self.done.add((rec["name"], rec["version"]))


def run_downloads(recs: list[dict], root: Path, workers: int):
    man = Manifest(root / "manifest.jsonl")
    todo = [r for r in recs if (r["name"], r["version"]) not in man.done]
    print(f"{len(todo)} releases to fetch ({len(recs) - len(todo)} already in manifest)")
    t0 = time.time()

    def job(r):
        res = fetch_release(r, root)
        man.write(res)
        return res["status"]

    with ThreadPoolExecutor(workers) as ex:
        for i, status in enumerate(ex.map(job, todo), 1):
            if i % 200 == 0:
                print(f"  {i}/{len(todo)}  {time.time() - t0:.0f}s  last={status}", flush=True)


def cmd_backfill(a):
    root = Path(a.out).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    end = int(time.time()) - a.lag_hours * 3600
    start = end - a.days * 86400
    print(f"Locating serial for {time.ctime(start)} ...")
    s0 = serial_at(start)
    print(f"Enumerating changelog from serial {s0} ...")
    rels = releases_from_events(iter_events(s0, until_ts=end))
    allrecs = list(rels.values())
    (root / "releases_all.jsonl").write_text("".join(json.dumps(r) + "\n" for r in allrecs))
    new = [r for r in allrecs if r["new_project_event"]]
    upd = [r for r in allrecs if not r["new_project_event"]]
    print(f"{len(allrecs)} releases in window: {len(new)} from new projects, {len(upd)} updates")

    rng = random.Random(a.seed)
    sample = list(new) if a.new_sample is None else rng.sample(new, min(a.new_sample, len(new)))
    sample += rng.sample(upd, min(a.update_sample, len(upd)))
    # stratum weights so precision can be reweighted to the full week
    strata = {"new": (len(new), sum(r["new_project_event"] for r in sample)),
              "update": (len(upd), sum(not r["new_project_event"] for r in sample))}
    (root / "strata.json").write_text(json.dumps({"window": [start, end], "strata": strata}, indent=1))
    run_downloads(sample, root, a.workers)


def cmd_live(a):
    root = Path(a.out).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    state_path = root / "live_state.json"
    rpc = _rpc()
    serial = (json.loads(state_path.read_text())["serial"] if state_path.exists()
              else rpc.changelog_last_serial())
    stop_at = time.time() + a.hours * 3600
    rng = random.Random(a.seed)
    while time.time() < stop_at:
        events = list(iter_events(serial))
        if events:
            serial = events[-1][4]
            rels = releases_from_events(events)
            batch = [r for r in rels.values()
                     if r["new_project_event"] or rng.random() < a.update_rate]
            with (root / "releases_all.jsonl").open("a") as fh:
                for r in rels.values():
                    fh.write(json.dumps(r) + "\n")
            run_downloads(batch, root, a.workers)
            state_path.write_text(json.dumps({"serial": serial}))
        time.sleep(a.poll_seconds)


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("backfill")
    b.add_argument("--days", type=float, default=7)
    b.add_argument("--lag-hours", type=float, default=0, help="end the window this many hours ago")
    b.add_argument("--new-sample", type=int, default=None, help="cap new-project releases (default: all)")
    b.add_argument("--update-sample", type=int, default=3000)
    l = sub.add_parser("live")
    l.add_argument("--hours", type=float, default=168)
    l.add_argument("--poll-seconds", type=int, default=300)
    l.add_argument("--update-rate", type=float, default=0.06, help="fraction of updates to keep")
    for s in (b, l):
        s.add_argument("--out", default="~/soteria_pypi_eval")
        s.add_argument("--workers", type=int, default=12)
        s.add_argument("--seed", type=int, default=42)
    a = p.parse_args()
    {"backfill": cmd_backfill, "live": cmd_live}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
