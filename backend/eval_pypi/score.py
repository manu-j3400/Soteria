"""
Run the Soteria AST model over every .py file fetched by fetch_pypi.py.

Parses only (ast.parse); nothing from the packages is imported or executed.

Outputs in <data>/scores/<tag>/:
  packages.csv   one row per release: max prob, flagged unit counts,
                 install-time flag, file/unit counts, parse failures
  units.jsonl    every unit scoring >= --keep (default 0.3) or carrying a
                 risky constant category, with its source (zlib+base64, see
                 features.pack_code), for labeling

Usage:
  python3 -I score.py --data ~/soteria_pypi_eval --tag baseline
  python3 -I score.py --data ~/soteria_pypi_eval --tag constcat \
      --model ../ML_master/acidModel_constcat.pkl
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import warnings
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))

DEFAULT_MODEL = Path(__file__).resolve().parent.parent / "ML_master" / "acidModel.pkl"
MAX_UNITS_PER_PKG = 20_000

_model = None
_feats = None
_use_cc = False


def _init(model_path: str):
    global _model, _feats, _use_cc
    from joblib import load
    warnings.filterwarnings("ignore")
    _model = load(model_path)
    # one process per core already; keep sklearn single-threaded inside
    for est in [_model, *getattr(_model, "estimators_", [])]:
        for obj in [est, *getattr(est, "named_steps", {}).values()]:
            if hasattr(obj, "n_jobs"):
                obj.n_jobs = 1
    _feats = list(_model.feature_names_in_)
    _use_cc = any(f.startswith("cc_") for f in _feats)


def cc_risk(cc: dict) -> list[str]:
    """Constant categories that a binary fetcher or licensing wrapper
    normally doesn't have. Used to gate the baseline model's flags."""
    hits = [k for k in ("cc_url_raw_ip", "cc_url_exfil_host", "cc_decode_exec") if cc[k]]
    # reading secrets, credential files or the whole environment is normal for
    # SDKs, CLIs and tests; it's risky when the same code also talks to the network
    for k in ("cc_env_secret", "cc_path_credential", "cc_env_bulk"):
        if cc[k] and cc["cc_network_call"]:
            hits.append(k)
    if cc["cc_download_then_run"] and cc["cc_path_outside_pkg"]:
        hits.append("download_run_outside_pkg")
    return hits


def score_package(rec: dict, root: str, keep: float, thr: float) -> tuple[dict, list[dict]]:
    from features import is_install_time, iter_sources, pack_code, split_units, unit_features
    from constant_categories import constant_categories

    rows, meta = [], []
    n_files = n_parse_fail = n_oversize = 0
    for rel, src in iter_sources(Path(root), rec):
        n_files += 1
        if src is None:
            n_oversize += 1
            continue
        try:
            units = list(split_units(src))
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            n_parse_fail += 1
            continue
        install = is_install_time(rel)
        for name, mod, line in units:
            if len(rows) >= MAX_UNITS_PER_PKG:
                break
            try:
                counts, raw, _ = unit_features(mod)
                cc = constant_categories(mod)
            except Exception:
                continue
            if _use_cc:
                counts.update(cc)
            rows.append(counts)
            meta.append({"file": rel, "unit": name, "line": line, "install_time": install,
                         "risk": cc_risk(cc), "cc": {k: v for k, v in cc.items() if v}, "raw": raw})

    out = {k: rec.get(k) for k in ("name", "version", "new_project", "summary", "dist_file", "ts")}
    # Files written at fetch time but gone now were almost certainly removed
    # by antivirus, which is itself a strong malware signal.
    expected = rec.get("n_py_unique", rec.get("n_py")) or 0
    n_missing = max(0, expected - n_files)
    out.update(n_files=n_files, n_units=len(rows), n_parse_fail=n_parse_fail, n_oversize=n_oversize,
               n_missing=n_missing, av_quarantined=bool(n_missing) and not rec.get("zip"),
               # older manifests counted duplicate tar members, so a count gap is weaker evidence
               av_basis="unique_count" if "n_py_unique" in rec else "raw_count")
    units_out = []
    if rows:
        X = pd.DataFrame(rows).reindex(columns=_feats, fill_value=0).fillna(0)
        probs = _model.predict_proba(X)[:, 1]
        best = int(probs.argmax())
        inst = [p for p, m in zip(probs, meta) if m["install_time"]]
        out.update(
            max_prob=round(float(probs.max()), 4),
            max_unit=f'{meta[best]["file"]}:{meta[best]["line"]} {meta[best]["unit"]}',
            n_flagged=int((probs >= thr).sum()),
            max_prob_install=round(float(max(inst)), 4) if inst else 0.0,
            n_flagged_install=int(sum(p >= thr for p in inst)),
            n_flagged_gated=int(sum(p >= thr and bool(m["risk"]) for p, m in zip(probs, meta))),
            risk_cats=",".join(sorted({r for m in meta for r in m["risk"]})),
        )
        for p, m in zip(probs, meta):
            if p >= keep or m["risk"]:
                units_out.append({"name": rec["name"], "version": rec["version"],
                                  "prob": round(float(p), 4), **m, "raw": pack_code(m["raw"][:6000])})
    else:
        out.update(max_prob=0.0, max_unit=None, n_flagged=0, max_prob_install=0.0,
                   n_flagged_install=0, n_flagged_gated=0, risk_cats="")
    return out, units_out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data", default="~/soteria_pypi_eval")
    p.add_argument("--tag", default="baseline")
    p.add_argument("--model", default=str(DEFAULT_MODEL))
    p.add_argument("--threshold", type=float, default=0.5)
    p.add_argument("--keep", type=float, default=0.3)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--limit", type=int, default=None)
    a = p.parse_args()

    root = Path(a.data).expanduser()
    recs = [json.loads(l) for l in (root / "manifest.jsonl").read_text().splitlines()]
    recs = [r for r in recs if r.get("status") == "ok"]
    for r in recs:  # ingest_datadog.py manifest: pkg/<version>/<date>-pkg-v<version>.zip
        if "zip" in r:
            r.update(name=r["pkg"], version=r["path"].split("/")[1])
    seen, uniq = set(), []
    for r in recs:
        if (r["name"], r["version"]) not in seen:
            seen.add((r["name"], r["version"]))
            uniq.append(r)
    recs = uniq[: a.limit] if a.limit else uniq

    out_dir = root / "scores" / a.tag
    out_dir.mkdir(parents=True, exist_ok=True)
    pkg_rows = []
    t0 = time.time()
    with open(out_dir / "units.jsonl", "w") as uf, \
            ProcessPoolExecutor(a.workers, initializer=_init, initargs=(a.model,)) as ex:
        futs = {ex.submit(score_package, r, str(root), a.keep, a.threshold): r for r in recs}
        for i, fut in enumerate(as_completed(futs), 1):
            r = futs[fut]
            try:
                row, units = fut.result(timeout=600)
            except Exception as e:
                row, units = {"name": r["name"], "version": r["version"], "error": repr(e)[:200]}, []
            pkg_rows.append(row)
            for u in units:
                uf.write(json.dumps(u) + "\n")
            if i % 250 == 0:
                print(f"  {i}/{len(recs)}  {time.time() - t0:.0f}s", flush=True)

    df = pd.DataFrame(pkg_rows)
    df.to_csv(out_dir / "packages.csv", index=False)
    flagged = (df["n_flagged"] > 0).sum()
    flagged_inst = (df["n_flagged_install"] > 0).sum()
    print(f"\n{len(df)} releases scored in {time.time() - t0:.0f}s")
    print(f"flagged (any unit >= {a.threshold}): {flagged} ({flagged / len(df):.1%})")
    print(f"flagged via install-time code:      {flagged_inst} ({flagged_inst / len(df):.1%})")
    gated = (df["n_flagged_gated"] > 0).sum()
    print(f"flagged + risky constant category:  {gated} ({gated / len(df):.1%})")
    if "av_quarantined" in df:
        print(f"files removed by antivirus since fetch: {int(df['av_quarantined'].fillna(False).sum())} releases")
    (out_dir / "run.json").write_text(json.dumps(vars(a), indent=1))


if __name__ == "__main__":
    main()
