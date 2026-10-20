"""
Pull recent npm publishes and keep only package.json + JS/TS sources, without
installing or executing anything.

Enumeration uses the public CouchDB changes feed (replicate.npmjs.com). It has
no timestamps, so the start sequence for the window is found by binary search
on the `time.modified` of docs at a given seq. Each change carries the doc
revision ("7-abc..."); a package whose first change in the window has a small
revision number (<= NEW_REV_MAX) was created in or just before the window.
That gives two strata known for every package in the window:

  new     first rev in window <= NEW_REV_MAX   (all fetched, up to --new-sample)
  update  everything else                      (random --update-sample)

Unit = one package: its latest version published inside the window. Packages
whose only change was metadata (dist-tags, deprecation, owner change) are kept
in the manifest as status=no_version_in_window so the stratum weights stay
honest (weight = N_stratum / n_sampled_stratum).

Safety:
  - tarballs are read in memory with tarfile; nothing is extracted to disk,
    installed, imported or run
  - only regular members named package.json or ending in .js/.cjs/.mjs/.ts
    (not .d.ts) are kept, re-packed into a new gzip tarball under pkgs/;
    plaintext source never touches disk
  - size caps on the tarball, each member and the total

Usage:
  python3 -I fetch_npm.py --hours 24 --new-sample 2000 --update-sample 1000 \
      --out ~/soteria_npm_eval
"""
from __future__ import annotations

import argparse
import io
import json
import random
import re
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

REPLICATE = "https://replicate.npmjs.com"
REGISTRY = "https://registry.npmjs.org"
UA = "soteria-precision-eval/0.1 (research; contact via github.com/manu-j3400/Soteria)"

NEW_REV_MAX = 3
MAX_PACKUMENT_BYTES = 40 * 1024 * 1024
MAX_TARBALL_BYTES = 25 * 1024 * 1024
MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 40 * 1024 * 1024
KEEP_EXT = (".js", ".cjs", ".mjs", ".ts")
AV_SETTLE_SECONDS = 2


def _get(url: str, timeout: int = 60, limit: int | None = None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Encoding": "identity"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read(limit + 1) if limit else r.read()
                if limit and len(data) > limit:
                    raise ValueError("too_big")
                return data
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and attempt < 3:
                time.sleep(2 ** attempt * 2)
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt < 3:
                time.sleep(2 ** attempt)
                continue
            raise
    raise RuntimeError("unreachable")


def _getj(url: str, **kw):
    return json.loads(_get(url, **kw))


def pkg_url(name: str) -> str:
    # quote() with safe="@" turns the scope slash into %2F, as the registry expects
    return f"{REGISTRY}/{urllib.parse.quote(name, safe='@')}"


def _ts(s: str | None) -> float | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


# ── Window enumeration ───────────────────────────────────────────────────────

def _seq_time(seq: int) -> float | None:
    """Approximate wall time of a seq: min time.modified over a few docs just
    after it (modified only moves forward, so the min is the tightest bound)."""
    res = _getj(f"{REPLICATE}/_changes?limit=6&since={seq}")["results"]
    ts = []
    for r in res:
        try:
            d = _getj(pkg_url(r["id"]), limit=MAX_PACKUMENT_BYTES)
            t = _ts(d.get("time", {}).get("modified"))
            if t:
                ts.append(t)
        except Exception:
            continue
    return min(ts) if ts else None


def seq_at(ts: float, top: int) -> int:
    lo, hi = max(0, top - 2_000_000), top
    while hi - lo > 3000:
        mid = (lo + hi) // 2
        t = _seq_time(mid)
        if t is None or t >= ts:
            hi = mid
        else:
            lo = mid
    return lo


def iter_changes(since: int, until: int):
    seq = since
    while seq < until:
        d = _getj(f"{REPLICATE}/_changes?limit=10000&since={seq}", timeout=120)
        res = d.get("results", [])
        if not res:
            return
        for r in res:
            if r["seq"] > until:
                return
            yield r
        seq = d.get("last_seq", res[-1]["seq"])
        time.sleep(0.3)


def window_packages(since: int, until: int) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in iter_changes(since, until):
        name = r["id"]
        if name.startswith("_design/"):
            continue
        rev = (r.get("changes") or [{}])[0].get("rev", "0-")
        try:
            n = int(rev.split("-")[0])
        except ValueError:
            n = 0
        e = out.setdefault(name, {"name": name, "first_rev": n, "n_changes": 0, "deleted": False})
        e["n_changes"] += 1
        e["deleted"] = e["deleted"] or bool(r.get("deleted"))
    return out


# ── Fetch one package ────────────────────────────────────────────────────────

def _safe_rel(name: str) -> str | None:
    p = PurePosixPath(name.replace("\\", "/"))
    if p.is_absolute() or any(part in ("..", "") for part in p.parts):
        return None
    return str(p)


def _keep(rel: str) -> bool:
    base = rel.rsplit("/", 1)[-1]
    if base == "package.json":
        return True
    return rel.endswith(KEEP_EXT) and not rel.endswith(".d.ts")


def filter_tarball(blob: bytes) -> tuple[bytes, int, int]:
    """Re-pack only package.json + JS/TS members into a new .tgz, in memory."""
    out = io.BytesIO()
    n = total = 0
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as src, \
            tarfile.open(fileobj=out, mode="w:gz") as dst:
        for m in src:
            if not m.isreg():
                continue
            rel = _safe_rel(m.name)
            if rel is None or not _keep(rel) or m.size > MAX_MEMBER_BYTES or total > MAX_TOTAL_BYTES:
                continue
            f = src.extractfile(m)
            if f is None:
                continue
            data = f.read(MAX_MEMBER_BYTES + 1)[:MAX_MEMBER_BYTES]
            info = tarfile.TarInfo(rel)
            info.size = len(data)
            info.mtime = 0
            dst.addfile(info, io.BytesIO(data))
            n += 1
            total += len(data)
    return out.getvalue(), n, total


def fetch_package(rec: dict, root: Path, win: tuple[float, float]) -> dict:
    out = dict(rec)
    name = rec["name"]
    try:
        doc = _getj(pkg_url(name), limit=MAX_PACKUMENT_BYTES, timeout=120)
    except urllib.error.HTTPError as e:
        out["status"] = "unavailable" if e.code == 404 else f"http_{e.code}"
        return out
    except ValueError as e:
        out["status"] = "packument_too_big" if "too_big" in str(e) else "bad_json"
        return out
    except Exception as e:
        out["status"] = f"error:{type(e).__name__}"
        return out
    times = doc.get("time", {}) or {}
    if "unpublished" in times:
        out["status"] = "unavailable"
        out["unpublished"] = times.get("unpublished", {}).get("time") if isinstance(
            times.get("unpublished"), dict) else True
        return out
    created = _ts(times.get("created"))
    out["created"] = times.get("created")
    out["created_in_window"] = bool(created and created >= win[0])
    out["n_versions"] = len(doc.get("versions", {}))
    latest = (doc.get("dist-tags") or {}).get("latest", "")
    if latest.endswith("-security") or "security holding" in (doc.get("description") or "").lower():
        out["status"] = "security_holding"
        return out
    in_win = [(t, v) for v, s in times.items() if v not in ("created", "modified")
              and (t := _ts(s)) and win[0] <= t <= win[1] and v in doc.get("versions", {})]
    if not in_win:
        out["status"] = "no_version_in_window"
        return out
    t, ver = max(in_win)
    vdoc = doc["versions"][ver]
    out.update(version=ver, published=times.get(ver), n_versions_in_window=len(in_win),
               description=(vdoc.get("description") or "")[:200],
               scripts={k: v for k, v in (vdoc.get("scripts") or {}).items()
                        if k in ("preinstall", "install", "postinstall", "prepare")},
               repository=str((vdoc.get("repository") or {}).get("url", "")
                              if isinstance(vdoc.get("repository"), dict) else vdoc.get("repository") or "")[:200],
               maintainers=[m.get("name") for m in (vdoc.get("maintainers") or []) if isinstance(m, dict)][:5],
               n_deps=len(vdoc.get("dependencies") or {}))
    dist = vdoc.get("dist") or {}
    url = dist.get("tarball")
    if not url:
        out["status"] = "no_tarball"
        return out
    if (dist.get("unpackedSize") or 0) > 20 * MAX_TARBALL_BYTES:
        out["status"] = "too_big"
        return out
    try:
        blob = _get(url, timeout=180, limit=MAX_TARBALL_BYTES)
    except ValueError:
        out["status"] = "too_big"
        return out
    except Exception as e:
        out["status"] = f"download_error:{type(e).__name__}"
        return out
    out["tarball_bytes"] = len(blob)
    try:
        packed, n, total = filter_tarball(blob)
    except Exception as e:
        out["status"] = f"extract_error:{type(e).__name__}"
        return out
    safe = re.sub(r"[^A-Za-z0-9._@-]", "__", name)
    vsafe = re.sub(r"[^A-Za-z0-9._+-]", "_", ver)
    dest = root / "pkgs" / f"{safe}@{vsafe}.tgz"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(packed)
    time.sleep(AV_SETTLE_SECONDS)
    out.update(status="ok" if n else "no_js", n_files=n, src_bytes=total,
               path=str(dest.relative_to(root)), av_removed=not dest.exists())
    return out


# ── Driver ───────────────────────────────────────────────────────────────────

class Manifest:
    def __init__(self, path: Path):
        self.path, self.lock, self.done = path, threading.Lock(), set()
        if path.exists():
            for line in path.read_text().splitlines():
                try:
                    self.done.add(json.loads(line)["name"])
                except (json.JSONDecodeError, KeyError):
                    continue

    def write(self, rec: dict):
        with self.lock:
            with self.path.open("a") as fh:
                fh.write(json.dumps(rec) + "\n")
            self.done.add(rec["name"])


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--hours", type=float, default=24)
    p.add_argument("--lag-hours", type=float, default=0)
    p.add_argument("--new-sample", type=int, default=2000)
    p.add_argument("--update-sample", type=int, default=1000)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out", default="~/soteria_npm_eval")
    a = p.parse_args()
    root = Path(a.out).expanduser()
    root.mkdir(parents=True, exist_ok=True)

    win_path = root / "window.json"
    if win_path.exists():  # resume
        w = json.loads(win_path.read_text())
        print(f"resuming window {w['start_iso']} .. {w['end_iso']}")
    else:
        top = _getj(f"{REPLICATE}/")["update_seq"]
        end = time.time() - a.lag_hours * 3600
        start = end - a.hours * 3600
        end_seq = top if a.lag_hours == 0 else seq_at(end, top)
        print(f"locating seq for {datetime.fromtimestamp(start, timezone.utc).isoformat()} ...", flush=True)
        start_seq = seq_at(start, end_seq)
        print(f"enumerating changes {start_seq} .. {end_seq}", flush=True)
        pk = window_packages(start_seq, end_seq)
        (root / "window_packages.jsonl").write_text("".join(json.dumps(r) + "\n" for r in pk.values()))
        w = {"start": start, "end": end, "start_seq": start_seq, "end_seq": end_seq,
             "start_iso": datetime.fromtimestamp(start, timezone.utc).isoformat(),
             "end_iso": datetime.fromtimestamp(end, timezone.utc).isoformat()}
        win_path.write_text(json.dumps(w, indent=1))
    pk = [json.loads(l) for l in (root / "window_packages.jsonl").read_text().splitlines()]
    new = [r for r in pk if r["first_rev"] <= NEW_REV_MAX]
    upd = [r for r in pk if r["first_rev"] > NEW_REV_MAX]
    print(f"{len(pk)} packages changed in window: {len(new)} new-ish (rev<={NEW_REV_MAX}), {len(upd)} updates")
    rng = random.Random(a.seed)
    s_new = rng.sample(new, min(a.new_sample, len(new)))
    s_upd = rng.sample(upd, min(a.update_sample, len(upd)))
    for r in s_new:
        r["stratum"] = "new"
        r["new_project_event"] = True
    for r in s_upd:
        r["stratum"] = "update"
        r["new_project_event"] = False
    strata = {"new": [len(new), len(s_new)], "update": [len(upd), len(s_upd)]}
    (root / "strata.json").write_text(json.dumps({"window": [w["start"], w["end"]], "strata": strata,
                                                  "unit": "package (latest version in window)"}, indent=1))
    man = Manifest(root / "manifest.jsonl")
    todo = [r for r in s_new + s_upd if r["name"] not in man.done]
    print(f"{len(todo)} packages to fetch", flush=True)
    t0 = time.time()

    def job(r):
        res = fetch_package(r, root, (w["start"], w["end"]))
        man.write(res)
        return res["status"]

    counts: dict[str, int] = {}
    with ThreadPoolExecutor(a.workers) as ex:
        for i, st in enumerate(ex.map(job, todo), 1):
            counts[st] = counts.get(st, 0) + 1
            if i % 200 == 0:
                print(f"  {i}/{len(todo)}  {time.time() - t0:.0f}s  {counts}", flush=True)
    print("done", counts)


if __name__ == "__main__":
    main()
