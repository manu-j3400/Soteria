"""
Run the JS dataflow rules (backend/src/dataflow_rules_js.py) over packages
fetched by fetch_npm.py, then cross-check against known npm malware.

Sources are read from the re-packed gzip tarballs in memory; nothing is
extracted, installed or executed.

Writes <data>/scores/dataflow/:
  packages.csv    one row per package: count per rule, df_install (finding in
                  an install hook or a file it runs), known_malicious,
                  registry_status
  findings.jsonl  each finding with a pack_code snippet

Usage:
  python3 -I npm_scan.py --data ~/soteria_npm_eval --workers 4
"""
from __future__ import annotations

import argparse
import io
import json
import re
import sys
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import SRC, pack_code, read_jsonl  # noqa: E402,F401

RULES = ["remote_code_exec", "remote_cmd_exec", "decoded_exec", "exfil_env_bulk", "exfil_cred_file",
         "exfil_hostinfo", "exfil_hostid", "download_exec", "shell_download", "install_script_download", "url_dependency"]
WEAK = {"decoded_exec", "exfil_hostinfo"}
OSV_NPM = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"
_TEST = re.compile(r"(^|/)(tests?|__tests__|spec|examples?|fixtures?)/|\.(test|spec)\.[cm]?[jt]s$")
MAX_FILE = 1_000_000


def _minified(text: str) -> bool:
    lines = text.count("\n") + 1
    return len(text) / lines > 400


def scan(rec: dict, root: str) -> tuple[dict, list[dict]]:
    from dataflow_rules_js import analyze_file, install_hooks, url_dependencies
    out = {"name": rec["name"], "version": rec["version"], "stratum": rec.get("stratum"),
           "new_project_event": rec.get("new_project_event")}
    found: list[dict] = []
    files: dict[str, str] = {}
    with tarfile.open(Path(root) / rec["path"], "r:gz") as tf:
        for m in tf:
            if m.isreg() and m.size <= MAX_FILE:
                f = tf.extractfile(m)
                if f is not None:
                    files[re.sub(r"^package/", "", m.name)] = f.read().decode("utf-8", "replace")
    hook_files, hook_found = install_hooks(files.get("package.json", "{}"))
    hook_found += url_dependencies(files.get("package.json", "{}"))
    hook_files = {re.sub(r"^\./", "", h) for h in hook_files}
    for f in hook_found:
        found.append({"file": "package.json", "func": f.func, "line": 0, "rule": f.rule, "install_time": True,
                      "raw": pack_code(json.dumps(json.loads(files["package.json"]).get("scripts", {}))[:2000])})
    n_min = n_js = 0
    for rel, text in files.items():
        if rel == "package.json" or _TEST.search(rel):
            continue
        n_js += 1
        if rel.endswith(".min.js") or _minified(text):
            n_min += 1
            continue
        try:
            hits = analyze_file(text)
        except RecursionError:
            continue
        lines = text.splitlines()
        seen = set()
        for h in hits:
            if (h.rule, h.line) in seen:
                continue
            seen.add((h.rule, h.line))
            found.append({"file": rel, "func": h.func, "line": h.line, "rule": h.rule,
                          "install_time": rel in hook_files,
                          "raw": pack_code("\n".join(lines[max(0, h.line - 12): h.line + 4])[:6000])})
    for f in found:
        f.update(name=rec["name"], version=rec["version"])
    for r in RULES:
        out[r] = sum(f["rule"] == r for f in found)
    out.update(n_js=n_js, n_minified=n_min, df_install=int(any(f["install_time"] for f in found)),
               install_hooks=",".join(sorted(hook_files)))
    return out, found


def known_malicious(cache: Path) -> dict[str, set | None]:
    if not cache.exists():
        cache.write_bytes(urllib.request.urlopen(OSV_NPM, timeout=300).read())
    mal: dict[str, set | None] = {}
    with zipfile.ZipFile(cache) as zf:
        for n in zf.namelist():
            rec = json.loads(zf.read(n))
            text = f'{rec.get("summary", "")} {rec.get("details", "")[:300]}'.lower()
            if not (rec.get("id", "").startswith("MAL-") or "malicious" in text):
                continue
            for aff in rec.get("affected", []):
                pkg = aff.get("package", {})
                if pkg.get("ecosystem") != "npm":
                    continue
                cur = mal.get(pkg["name"], set())
                mal[pkg["name"]] = None if (cur is None or not aff.get("versions")) else cur | set(aff["versions"])
    return mal


def registry_status(name: str, version: str) -> str:
    url = "https://registry.npmjs.org/" + name.replace("/", "%2F")
    try:
        doc = json.loads(urllib.request.urlopen(url, timeout=30).read())
    except urllib.error.HTTPError as e:
        return "removed" if e.code == 404 else f"http_{e.code}"
    except Exception:
        return "error"
    if "0.0.1-security" in (doc.get("versions") or {}):
        return "security_holding"
    if version not in (doc.get("versions") or {}):
        return "version_removed"
    return "present"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data", default="~/soteria_npm_eval")
    p.add_argument("--workers", type=int, default=4)
    a = p.parse_args()
    root = Path(a.data).expanduser()
    recs = [r for r in read_jsonl(root / "manifest.jsonl")]
    ok = [r for r in recs if r.get("status") == "ok"]
    out_dir = root / "scores" / "dataflow"
    out_dir.mkdir(parents=True, exist_ok=True)
    rows, t0 = [], time.time()
    with open(out_dir / "findings.jsonl", "w") as fh, ProcessPoolExecutor(a.workers) as ex:
        futs = {ex.submit(scan, r, str(root)): r for r in ok}
        for i, fut in enumerate(as_completed(futs), 1):
            try:
                row, found = fut.result()
            except Exception as e:
                r = futs[fut]
                row, found = {"name": r["name"], "version": r["version"], "error": repr(e)[:200]}, []
            rows.append(row)
            for f in found:
                fh.write(json.dumps(f) + "\n")
            if i % 500 == 0:
                print(f"  {i}/{len(ok)}  {time.time() - t0:.0f}s", flush=True)
    df = pd.DataFrame(rows)
    for r in RULES:
        df[r] = df[r].fillna(0)
    df["df_any"] = (df[RULES].sum(axis=1) > 0).astype(int)
    df["df_strong"] = (df[[r for r in RULES if r not in WEAK]].sum(axis=1) > 0).astype(int)

    mal = known_malicious(root / "osv_npm_all.zip")
    df["known_malicious"] = [n in mal and (mal[n] is None or v in mal[n]) for n, v in zip(df["name"], df["version"])]
    # holding placeholders from the fetch are known takedowns too
    held = {r["name"] for r in recs if r.get("status") == "security_holding"}
    check = df[(df["df_any"] > 0) | df["known_malicious"]]
    with ThreadPoolExecutor(8) as tp:
        st = list(tp.map(lambda nv: registry_status(*nv), zip(check["name"], check["version"])))
    df["registry_status"] = ""
    df.loc[check.index, "registry_status"] = st
    df.to_csv(out_dir / "packages.csv", index=False)

    n = len(df)
    print(f"\n{n} packages scanned in {time.time() - t0:.0f}s "
          f"({len(held)} more were already security-holding placeholders at fetch)")
    print(f"known malicious among scanned: {int(df['known_malicious'].sum())}")
    for r in RULES + ["df_any", "df_strong", "df_install"]:
        f = df[df[r] > 0]
        print(f"  {r:24s} {len(f):5d} ({len(f) / n:.2%})  known-mal {int(f['known_malicious'].sum())}  "
              f"removed-now {int(f['registry_status'].isin(['removed', 'security_holding', 'version_removed']).sum())}")


if __name__ == "__main__":
    main()
