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

--rules v4 uses dataflow_rules_v4.py (parameter-aware taint) and writes to
<data>/scores/dataflow_v4/ instead; its findings also carry `via` (the caller
whose arguments made it fire) and `loose`. Default is v3, unchanged.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import is_install_time, iter_sources, pack_code, read_jsonl  # noqa: E402
from dataflow_rules import analyze_package  # noqa: E402
import dataflow_rules_v4  # noqa: E402

ANALYZERS = {"v3": analyze_package, "v4": dataflow_rules_v4.analyze_package}
OUT_DIRS = {"v3": "dataflow", "v4": "dataflow_v4"}

_TEST_PATH = re.compile(r"(^|/)(tests?|testing)/|(^|/)test_[^/]*\.py$|_test\.py$|conftest\.py$")

RULES = ["remote_code_exec", "remote_cmd_exec", "decoded_exec",
         "exfil_env_bulk", "exfil_cred_file", "exfil_hostinfo", "download_exec", "shell_download",
         "reverse_shell", "exfil_hostid", "oversize_install_file"]


def scan(rec: dict, root: str, rules: str = "v3") -> tuple[dict, list[dict]]:
    mods, srcs, oversize = [], {}, []
    for rel, src in iter_sources(Path(root), rec):
        # tests never run on install or import
        if _TEST_PATH.search(rel):
            continue
        if src is None:
            # a >1MB setup.py / build hook is padding to dodge scanners, not real code;
            # a >1MB __init__.py is usually generated bindings (jsii, protobuf)
            if is_install_time(rel) and not rel.endswith("__init__.py"):
                oversize.append(rel)
            continue
        try:
            mods.append((rel, ast.parse(src)))
            srcs[rel] = src
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
    try:
        found = ANALYZERS[rules](mods)
    except RecursionError:
        found = []
    seen, rows = set(), []
    for rel, f in found:
        if (rel, f.rule, f.line) in seen:
            continue
        seen.add((rel, f.rule, f.line))
        lines = srcs[rel].splitlines()
        snippet = "\n".join(lines[max(0, f.line - 15): f.line + 5])
        row = {"name": rec["name"], "version": rec["version"], "file": rel, "func": f.func,
               "line": f.line, "rule": f.rule, "install_time": is_install_time(rel),
               "raw": pack_code(snippet)}
        if rules != "v3":
            # a helper called from setup.py runs at install time wherever it lives
            row.update(via=f.via, loose=f.loose, origin=f.origin,
                       install_time=is_install_time(rel) or bool(f.origin and is_install_time(f.origin)))
        rows.append(row)
    for rel in oversize:
        rows.append({"name": rec["name"], "version": rec["version"], "file": rel, "func": "<file>",
                     "line": 0, "rule": "oversize_install_file", "install_time": True, "raw": ""})
    out = {"name": rec["name"], "version": rec["version"], "n_files": len(mods)}
    for r in RULES:
        out[r] = sum(x["rule"] == r for x in rows)
    out["df_install"] = int(any(x["install_time"] for x in rows))
    if rules != "v3":
        out["n_via"] = sum(bool(x.get("via")) for x in rows)
        out["n_loose"] = sum(bool(x.get("loose")) for x in rows)
    return out, rows


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data", default="~/soteria_pypi_eval")
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--rules", choices=sorted(ANALYZERS), default="v3")
    a = p.parse_args()
    root = Path(a.data).expanduser()
    recs = read_jsonl(root / "manifest.jsonl")
    recs = [r for r in recs if r.get("status") == "ok"]
    for r in recs:
        if "zip" in r:
            r.update(name=r["pkg"], version=r["path"].split("/")[1])
    uniq = {(r["name"], r["version"]): r for r in recs}
    out_dir = root / "scores" / OUT_DIRS[a.rules]
    out_dir.mkdir(parents=True, exist_ok=True)
    rows, t0 = [], time.time()
    with open(out_dir / "findings.jsonl", "w") as fh, ProcessPoolExecutor(a.workers) as ex:
        futs = {ex.submit(scan, r, str(root), a.rules): r for r in uniq.values()}
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
