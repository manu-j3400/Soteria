"""
Estimate precision, flag rate and recall for each flag rule.

  any       any unit scores >= threshold
  install   an install-time unit (setup.py, build hooks, top-level
            __init__.py) scores >= threshold
  gated     a unit scores >= threshold AND carries a risky constant category
  gated_pkg any unit scores >= threshold AND any unit in the release carries
            a risky constant category
  risk_only no model at all: any risky constant category in the release

Dataflow rules, when <data>/scores/dataflow/packages.csv exists
(dataflow_scan.py); skipped otherwise:
  df_any       any dataflow rule fires
  df_strong    any rule except decoded_exec and exfil_hostinfo (the noisy ones)
  df_install   a dataflow finding in install-time code
  model_and_df any unit scores >= threshold AND df_any

Precision for a rule = (known-malicious flagged + p_hat * other flagged) / flagged,
where p_hat is the malicious share among hand-labeled releases sampled from
"other flagged" for that rule. The interval is a Wilson 95% CI on p_hat.
Update rows are reweighted to the full window by strata.json (written by
fetch_pypi.py backfill, or live_strata.py for a live dir). New-project
releases were all fetched.

Recall is measured on (a) known-malicious releases inside the week and
(b) the Datadog malware set (training-disjoint for the baseline model only).

Usage:
  python3 -I precision.py --data ~/soteria_pypi_eval --tag baseline \
      --malware ~/soteria_malware_samples
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dataflow_scan import RULES as DF_RULES  # noqa: E402
from features import read_jsonl  # noqa: E402

RULES = {"any": "n_flagged", "install": "n_flagged_install", "gated": "n_flagged_gated",
         "gated_pkg": "gated_pkg", "risk_only": "risk_only",
         "df_any": "df_any", "df_strong": "df_strong", "df_install": "df_install",
         "model_and_df": "model_and_df"}
DF_WEAK = {"decoded_exec", "exfil_hostinfo"}


def add_derived(df: pd.DataFrame, root: Path | None = None) -> pd.DataFrame:
    """Package-level rules: the risky constant can sit in a different function
    than the one the model flagged (e.g. setup.py flagged, webhook URL in utils.py).
    With root, also merge root/scores/dataflow/packages.csv and add the df_* rules."""
    risk = df["risk_cats"].fillna("") != ""
    df["gated_pkg"] = ((df["n_flagged"] > 0) & risk).astype(int)
    df["risk_only"] = risk.astype(int)
    path = root / "scores" / "dataflow" / "packages.csv" if root else None
    if path is None or not path.exists():
        return df
    d = pd.read_csv(path, dtype={"version": str}).drop_duplicates(["name", "version"])
    # older scans may lack newer rule columns
    rules = [r for r in DF_RULES if r in d]
    d = d[["name", "version", *rules, "df_install"]]
    df = df.drop(columns=[c for c in d.columns[2:] if c in df])
    df = df.merge(d, on=["name", "version"], how="left", indicator="_df")
    missing = int((df.pop("_df") == "left_only").sum())
    if missing:
        print(f"warning: {missing} releases have no dataflow row ({path}); counted as not flagged")
    df[d.columns[2:]] = df[d.columns[2:]].fillna(0)
    df["df_any"] = (df[rules].sum(axis=1) > 0).astype(int)
    df["df_strong"] = (df[[r for r in rules if r not in DF_WEAK]].sum(axis=1) > 0).astype(int)
    df["model_and_df"] = ((df["n_flagged"] > 0) & (df["df_any"] > 0)).astype(int)
    df.attrs["df_rules"] = rules
    return df


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data", default="~/soteria_pypi_eval")
    p.add_argument("--tag", default="baseline")
    p.add_argument("--malware", default="~/soteria_malware_samples")
    p.add_argument("--labels-from", default=None,
                   help="reuse hand labels from another tag (same releases, different model)")
    a = p.parse_args()

    root = Path(a.data).expanduser()
    sdir = root / "scores" / a.tag
    df = pd.read_csv(sdir / "packages_crosschecked.csv", dtype={"version": str})
    df["known_malicious"] = df["known_malicious"].fillna("")
    df = add_derived(df, root)
    strata = json.loads((root / "strata.json").read_text())["strata"]
    w_upd = strata["update"][0] / max(strata["update"][1], 1)
    # new_project in the manifest is release-level; the sampling stratum is the changelog event
    man = {(r["name"], r["version"]): r for r in read_jsonl(root / "manifest.jsonl")}
    df["w"] = [1.0 if man.get((n, v), {}).get("new_project_event") else w_upd
               for n, v in zip(df["name"], df["version"])]

    lab_dir = root / "scores" / (a.labels_from or a.tag)
    labels = pd.DataFrame(columns=["name", "version", "label", "pattern"])
    if (lab_dir / "labels.csv").exists():
        labels = pd.read_csv(lab_dir / "labels.csv", dtype={"version": str})
        labels = labels[labels["label"].isin(["malicious", "benign"])]
    if "sampled_for" not in labels:
        # sheets from before per-rule sampling covered only the model/constant rules
        labels["sampled_for"] = "any,install,gated,gated_pkg,risk_only"
    # per rule, only use releases sampled for that rule: each rule's sample is a
    # random draw from its own flagged set, the union is not
    lab = {(n, v): (l, pat, set(str(sf).split(","))) for n, v, l, pat, sf in
           zip(labels["name"], labels["version"], labels["label"], labels["pattern"], labels["sampled_for"])}

    n_all, w_all = len(df), df["w"].sum()
    known = df["known_malicious"] != ""
    out = {"releases_scored": n_all, "releases_week_weighted": round(w_all),
           "known_malicious_scored": int(known.sum()), "rules": {}}
    lines = [f"# Soteria PyPI precision: {a.tag}", "",
             f"Releases scored: {n_all} (reweighted to full window: {w_all:,.0f})",
             f"Known-malicious releases among them: {int(known.sum())}", "",
             "| rule | flag rate (week) | flagged | known mal. | labeled (mal/ben) | precision | 95% CI | recall in-week | recall Datadog |",
             "|---|---|---|---|---|---|---|---|---|"]

    mal_pk = None
    mroot = Path(a.malware).expanduser()
    if (mroot / "scores" / a.tag / "packages.csv").exists():
        mal_pk = add_derived(pd.read_csv(mroot / "scores" / a.tag / "packages.csv", dtype={"version": str}), mroot)

    fp_patterns: dict[str, dict[str, int]] = {}
    for rule, col in RULES.items():
        if col not in df:
            continue
        f = df[df[col] > 0]
        fk = f[f["known_malicious"] != ""]
        fo = f[f["known_malicious"] == ""]
        labeled = [lab[k][:2] for k in zip(fo["name"], fo["version"]) if k in lab and rule in lab[k][2]]
        m = sum(l == "malicious" for l, _ in labeled)
        n = len(labeled)
        p_hat = m / n if n else float("nan")
        lo, hi = wilson(m, n)
        fw, fkw, fow = f["w"].sum(), fk["w"].sum(), fo["w"].sum()
        prec = (fkw + p_hat * fow) / fw if fw and n else float("nan")
        prec_lo = (fkw + lo * fow) / fw if fw else float("nan")
        prec_hi = (fkw + hi * fow) / fw if fw else float("nan")
        rec_week = len(fk) / known.sum() if known.sum() else float("nan")
        rec_dd = (mal_pk[col] > 0).mean() if mal_pk is not None and col in mal_pk else float("nan")
        pats: dict[str, int] = {}
        for l, pat in labeled:
            if l == "benign":
                pats[pat] = pats.get(pat, 0) + 1
        fp_patterns[rule] = dict(sorted(pats.items(), key=lambda x: -x[1]))
        out["rules"][rule] = {"flag_rate_week": fw / w_all, "flagged": len(f), "known_malicious_flagged": len(fk),
                              "labeled": n, "labeled_malicious": m, "precision": prec,
                              "precision_ci95": [prec_lo, prec_hi], "recall_in_week": rec_week,
                              "recall_datadog": rec_dd, "fp_patterns": fp_patterns[rule]}
        lines.append(f"| {rule} | {fw / w_all:.1%} | {len(f)} | {len(fk)} | {m}/{n - m} | "
                     f"{prec:.3%} | {prec_lo:.3%} to {prec_hi:.2%} | {rec_week:.0%} | {rec_dd:.0%} |")

    lines += ["", "## False-positive patterns (hand-labeled benign)", ""]
    for rule, pats in fp_patterns.items():
        tot = sum(pats.values()) or 1
        lines.append(f"**{rule}**: " + ", ".join(f"{k} {v} ({v / tot:.0%})" for k, v in pats.items()))
    (sdir / "results.md").write_text("\n".join(lines) + "\n")
    (sdir / "results.json").write_text(json.dumps(out, indent=1, default=float))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
