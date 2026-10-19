"""
Cross-check scored releases against known PyPI malware.

Ground-truth sources:
  1. OSV PyPI dump. Includes MAL-* records imported from
     ossf/malicious-packages and GHSA "malicious package" advisories.
  2. Datadog malicious-software-packages-dataset PyPI manifest.
  3. PyPI removal: release or whole project now 404s. Weaker signal, since
     authors also delete their own projects, so it's reported separately
     and these releases go to hand labeling.

Rerun this a few days after the fetch: takedown reports lag publishes.

Usage:
  python3 -I crosscheck.py --data ~/soteria_pypi_eval --tag baseline
"""
from __future__ import annotations

import argparse
import io
import json
import re
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

OSV_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
DATADOG_MANIFEST = ("https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/"
                    "main/samples/pypi/manifest.json")
UA = "soteria-precision-eval/0.1"


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def load_known_malicious(cache: Path) -> dict[str, dict]:
    """name -> {"ids": [...], "versions": set | None (None = all versions)}"""
    if not cache.exists():
        req = urllib.request.Request(OSV_ZIP, headers={"User-Agent": UA})
        cache.write_bytes(urllib.request.urlopen(req, timeout=300).read())
    mal: dict[str, dict] = {}
    with zipfile.ZipFile(cache) as zf:
        for n in zf.namelist():
            rec = json.loads(zf.read(n))
            rid = rec.get("id", "")
            text = f'{rec.get("summary", "")} {rec.get("details", "")[:300]}'.lower()
            is_mal = rid.startswith("MAL-") or "malicious" in text or "malware" in text
            if not is_mal:
                continue
            for aff in rec.get("affected", []):
                pkg = aff.get("package", {})
                if pkg.get("ecosystem") != "PyPI":
                    continue
                entry = mal.setdefault(_norm(pkg["name"]), {"ids": [], "versions": set()})
                entry["ids"].append(rid)
                vers = aff.get("versions")
                if vers and entry["versions"] is not None:
                    entry["versions"].update(vers)
                else:
                    entry["versions"] = None  # range or unspecified: treat all as malicious
    return mal


def merge_datadog(mal: dict[str, dict], cache: Path) -> int:
    """Datadog manifest: name -> null (all versions malicious) or [versions]."""
    if not cache.exists():
        req = urllib.request.Request(DATADOG_MANIFEST, headers={"User-Agent": UA})
        cache.write_bytes(urllib.request.urlopen(req, timeout=120).read())
    added = 0
    for name, vers in json.loads(cache.read_text()).items():
        entry = mal.setdefault(_norm(name), {"ids": [], "versions": set()})
        entry["ids"].append("datadog")
        added += 1
        if vers and entry["versions"] is not None:
            entry["versions"].update(vers)
        else:
            entry["versions"] = None
    return added


def pypi_status(name: str, version: str) -> str:
    for url, tag in ((f"https://pypi.org/pypi/{name}/{version}/json", "present"),
                     (f"https://pypi.org/pypi/{name}/json", "version_removed")):
        try:
            urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=30)
            return tag
        except urllib.error.HTTPError as e:
            if e.code != 404:
                return f"http_{e.code}"
        except Exception:
            return "error"
    return "project_removed"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data", default="~/soteria_pypi_eval")
    p.add_argument("--tag", default="baseline")
    p.add_argument("--refresh-osv", action="store_true")
    p.add_argument("--recheck-all", action="store_true",
                   help="check PyPI status for every release, not just flagged ones")
    a = p.parse_args()

    root = Path(a.data).expanduser()
    sdir = root / "scores" / a.tag
    df = pd.read_csv(sdir / "packages.csv")
    cache = root / "osv_pypi_all.zip"
    dd_cache = root / "datadog_pypi_manifest.json"
    if a.refresh_osv:
        cache.unlink(missing_ok=True)
        dd_cache.unlink(missing_ok=True)
    mal = load_known_malicious(cache)
    print(f"OSV: {len(mal)} PyPI package names with malicious-package advisories")
    print(f"Datadog manifest: {merge_datadog(mal, dd_cache)} names; {len(mal)} known-malicious names total")

    def osv_hit(row) -> str:
        e = mal.get(_norm(row["name"]))
        if not e:
            return ""
        if e["versions"] is None or str(row["version"]) in e["versions"]:
            return ",".join(sorted(set(e["ids"])))[:120]
        return ""

    df["known_malicious"] = df.apply(osv_hit, axis=1)

    # every release the downloader couldn't fetch is a takedown candidate too
    man = [json.loads(l) for l in (root / "manifest.jsonl").read_text().splitlines()]
    unavailable = [r for r in man if r.get("status") == "unavailable"]
    unavail_osv = sum(bool(mal.get(_norm(r["name"]))) for r in unavailable)

    check = df if a.recheck_all else df[df["n_flagged"] > 0]
    with ThreadPoolExecutor(16) as ex:
        status = list(ex.map(lambda r: pypi_status(r[0], str(r[1])),
                             zip(check["name"], check["version"])))
    df["pypi_status"] = ""
    df.loc[check.index, "pypi_status"] = status

    df.to_csv(sdir / "packages_crosschecked.csv", index=False)
    flagged = df[df["n_flagged"] > 0]
    print(f"scored releases:          {len(df)}")
    print(f"  known malicious:    {(df['known_malicious'] != '').sum()}")
    print(f"flagged:                  {len(flagged)}")
    print(f"  known malicious:    {(flagged['known_malicious'] != '').sum()}")
    print(f"  removed from PyPI:      {flagged['pypi_status'].str.contains('removed').sum()}")
    print(f"unavailable at fetch:     {len(unavailable)} ({unavail_osv} known malicious)")
    (sdir / "unavailable_known.json").write_text(json.dumps(
        [r for r in unavailable if mal.get(_norm(r["name"]))], indent=1))


if __name__ == "__main__":
    main()
