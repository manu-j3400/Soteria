"""
Train two comparison models on the same data so the effect of constant
categories can be separated from the effect of adding real-world data.

  realdata    original training set + real PyPI benign units (disjoint
              window) + real PyPI malware units (Datadog dataset).
              AST features only, same 101 columns as acidModel.pkl.
  constcat    same rows, plus the cc_* constant-category features.

Malware labels are package-level, so per package we only keep units most
likely to carry the payload: setup.py / __init__.py / module-level code,
plus everything in small packages (<= 5 .py files).

Split is grouped by package so no package lands in both train and test.

Usage:
  python3 -I train_variants.py --benign ~/soteria_pypi_train_benign \
      --malware ~/soteria_malware_samples
"""
from __future__ import annotations

import argparse
import ast
import json
import random
import sys
import warnings
from pathlib import Path

import pandas as pd
from joblib import dump
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import SRC, is_install_time, iter_sources, split_units, unit_features  # noqa: E402
from constant_categories import FEATURES as CC_FEATURES, constant_categories  # noqa: E402
from trainerModel_AST import build_ensemble  # noqa: E402

ML_DIR = SRC.parent / "ML_master"
BASE_CSV = SRC.parent / "CSV_master" / "finalData.csv"


def units_from_record(root: Path, rec: dict, label: int, group: str, max_units: int,
                      rng: random.Random, payload_only: bool) -> list[dict]:
    sources = [(rel, src) for rel, src in iter_sources(root, rec) if src is not None]
    small = len(sources) <= 5
    rows = []
    for rel, src in sources:
        try:
            units = list(split_units(src))
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
        for name, mod, _ in units:
            if payload_only and not (small or is_install_time(rel) or name == "<module>"):
                continue
            try:
                counts, _, _ = unit_features(mod)
            except Exception:
                continue
            counts.update(constant_categories(mod))
            rows.append({**counts, "LABEL": label, "GROUP": group})
    rng.shuffle(rows)
    return rows[:max_units]


def base_rows() -> list[dict]:
    from features import get_Node_Counts
    df = pd.read_csv(BASE_CSV)
    rows = []
    for i, r in df.iterrows():
        counts = get_Node_Counts(r["normalizedCode"])
        if isinstance(counts, Exception):
            continue
        try:
            counts.update(constant_categories(ast.parse(r["rawCode"])))
        except Exception:
            counts.update(dict.fromkeys(CC_FEATURES, 0.0))
        rows.append({**counts, "LABEL": int(r["label"]), "GROUP": f"base:{r['source']}"})
    return rows


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--benign", default="~/soteria_pypi_train_benign")
    p.add_argument("--malware", default="~/soteria_malware_samples")
    p.add_argument("--benign-units-per-pkg", type=int, default=15)
    p.add_argument("--malware-units-per-pkg", type=int, default=10)
    a = p.parse_args()
    rng = random.Random(42)
    warnings.filterwarnings("ignore")

    rows = base_rows()
    print(f"base rows: {len(rows)}")

    broot = Path(a.benign).expanduser()
    known_bad = set()
    kb = broot / "known_malicious_names.json"
    if kb.exists():
        known_bad = set(json.loads(kb.read_text()))
    n_b = 0
    for line in (broot / "manifest.jsonl").read_text().splitlines():
        r = json.loads(line)
        if r.get("status") != "ok" or r["name"].lower() in known_bad:
            continue
        got = units_from_record(broot, r, 0, f"pypi:{r['name']}", a.benign_units_per_pkg, rng, False)
        rows += got
        n_b += len(got)
    print(f"real benign units: {n_b}")

    mroot = Path(a.malware).expanduser()
    n_m = 0
    for line in (mroot / "manifest.jsonl").read_text().splitlines():
        r = json.loads(line)
        if r.get("status") != "ok":
            continue
        got = units_from_record(mroot, r, 1, f"dd:{r['pkg']}", a.malware_units_per_pkg, rng, True)
        rows += got
        n_m += len(got)
    print(f"real malware units: {n_m}")

    df = pd.DataFrame(rows).fillna(0)
    y, groups = df.pop("LABEL"), df.pop("GROUP")
    base_feats = list(pd.read_csv(SRC.parent / "CSV_master" / "numericFeatures.csv", nrows=1)
                      .drop(columns=["LABEL", "SOURCE"]).columns)
    for c in base_feats:
        if c not in df:
            df[c] = 0
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=42).split(df, y, groups))

    summary = {"rows": len(df), "malicious": int(y.sum()), "benign_real": n_b, "malware_real": n_m}
    for tag, cols in (("realdata", base_feats), ("constcat", base_feats + CC_FEATURES)):
        X = df[cols]
        model = build_ensemble()
        model.fit(X.iloc[tr], y.iloc[tr])
        pred = model.predict(X.iloc[te])
        print(f"\n== {tag} ({len(cols)} features) ==")
        print(confusion_matrix(y.iloc[te], pred))
        rep = classification_report(y.iloc[te], pred, output_dict=True)
        print(classification_report(y.iloc[te], pred, digits=3))
        summary[tag] = {"test_f1_mal": rep["1"]["f1-score"], "test_recall_mal": rep["1"]["recall"],
                        "test_precision_mal": rep["1"]["precision"],
                        "test_fpr": float(((pred == 1) & (y.iloc[te] == 0)).sum() / (y.iloc[te] == 0).sum())}
        dump(model, ML_DIR / f"acidModel_{tag}.pkl")
    (ML_DIR / "variants_summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
