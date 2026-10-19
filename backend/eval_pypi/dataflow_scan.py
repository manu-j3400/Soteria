"""
Run the package-level dataflow rules (backend/src/dataflow_rules.py) over a
fetched dataset. Parses only; nothing is imported or executed.

Writes <data>/scores/dataflow/:
  packages.csv    one row per release, one count column per rule, plus
                  df_install (any finding in install-time code)
  findings.jsonl  each finding with its enclosing source (zlib+base64)

Usage:
  python3 -I dataflow_scan.py --data ~/soteria_pypi_eval
  python3 -I dataflow_scan.py --data ~/soteria_malware_samples
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import is_install_time, iter_sources, pack_code, read_jsonl  # noqa: E402
from dataflow_rules import analyze_package  # noqa: E402

RULES = ["remote_code_exec", "remote_cmd_exec", "decoded_exec",
         "exfil_env_bulk", "exfil_cred_file", "exfil_hostinfo", "download_exec", "shell_download",
         "reverse_shell", "exfil_hostid", "oversize_install_file"]


def scan(rec: dict, root: str) -> tuple[dict, list[dict]]:
    mods, srcs, oversize = [], {}, []
    for rel, src in iter_sources(Path(root), rec):
        if src is None:
            # a >1MB setup.py / build hook is padding to dodge scanners, not real code
            if is_install_time(rel):
                oversize.append(rel)
            continue
        try:
            mods.append((rel, ast.parse(src)))
            srcs[rel] = src
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
    try:
        found = analyze_package(mods)
    except RecursionError:
        found = []
    seen, rows = set(), []
    for rel, f in found:
        if (rel, f.rule, f.line) in seen:
            continue
        seen.add((rel, f.rule, f.line))
        lines = srcs[rel].splitlines()
        snippet = "\n".join(lines[max(0, f.line - 15): f.line + 5])
        rows.append({"name": rec["name"], "version": rec["version"], "file": rel, "func": f.func,
                     "line": f.line, "rule": f.rule, "install_time": is_install_time(rel),
                     "raw": pack_code(snippet)})
    for rel in oversize:
        rows.append({"name": rec["name"], "version": rec["version"], "file": rel, "func": "<file>",
                     "line": 0, "rule": "oversize_install_file", "install_time": True, "raw": ""})
    out = {"name": rec["name"], "version": rec["version"], "n_files": len(mods)}
    for r in RULES:
        out[r] = sum(x["rule"] == r for x in rows)
    out["df_install"] = int(any(x["install_time"] for x in rows))
    return out, rows


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data", default="~/soteria_pypi_eval")
    p.add_argument("--workers", type=int, default=8)
    a = p.parse_args()
    root = Path(a.data).expanduser()
    recs = read_jsonl(root / "manifest.jsonl")
    recs = [r for r in recs if r.get("status") == "ok"]
    for r in recs:
        if "zip" in r:
            r.update(name=r["pkg"], version=r["path"].split("/")[1])
    uniq = {(r["name"], r["version"]): r for r in recs}
    out_dir = root / "scores" / "dataflow"
    out_dir.mkdir(parents=True, exist_ok=True)
    rows, t0 = [], time.time()
    with open(out_dir / "findings.jsonl", "w") as fh, ProcessPoolExecutor(a.workers) as ex:
        futs = {ex.submit(scan, r, str(root)): r for r in uniq.values()}
        for i, fut in enumerate(as_completed(futs), 1):
            try:
                row, found = fut.result()
            except Exception as e:
                r = futs[fut]
                row, found = {"name": r["name"], "version": r["version"], "error": repr(e)[:200]}, []
            rows.append(row)
            for f in found:
                fh.write(json.dumps(f) + "\n")
            if i % 1000 == 0:
                print(f"  {i}/{len(uniq)}  {time.time() - t0:.0f}s", flush=True)
    df = pd.DataFrame(rows).fillna(0)
    df.to_csv(out_dir / "packages.csv", index=False)
    print(f"{len(df)} releases in {time.time() - t0:.0f}s")
    for r in RULES + ["df_install"]:
        print(f"  {r:18s} {(df[r] > 0).sum():6d}  ({(df[r] > 0).mean():.2%})")


if __name__ == "__main__":
    main()
