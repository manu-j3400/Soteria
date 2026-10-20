"""
Write strata.json for a `fetch_pypi.py live` dir so precision.py can reweight
update rows to everything published while the collector ran.

Totals come from releases_all.jsonl, sampled counts from manifest.jsonl.
Updates are reweighted by actual counts, not the nominal --update-rate: a
release re-seen in a later poll (e.g. a second file upload) gets another
draw, so the real rate runs a little above nominal.

Releases are deduped by (name, version). The stratum is the manifest's
new_project_event when the release was downloaded (precision.py weights by
that), otherwise new if any poll saw the project created. Only events up to
live_state.json's serial count: that poll's downloads have finished, so later
lines may still be in flight.

Usage:
  python3 -I live_strata.py --data ~/soteria_pypi_live
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def read_jsonl(path: Path) -> list[dict]:
    out = []
    for line in path.read_text().splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:  # collector mid-append
            continue
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data", default="~/soteria_pypi_live")
    a = p.parse_args()
    root = Path(a.data).expanduser()

    state = root / "live_state.json"
    cutoff = json.loads(state.read_text())["serial"] if state.exists() else float("inf")
    seen: dict[tuple[str, str], dict] = {}
    for r in read_jsonl(root / "releases_all.jsonl"):
        if r["serial"] > cutoff:
            continue
        k = (r["name"], r["version"])
        e = seen.setdefault(k, {"new": False, "ts": r["ts"]})
        e["new"] |= bool(r["new_project_event"])
        e["ts"] = min(e["ts"], r["ts"])

    man = {(r["name"], r["version"]): bool(r.get("new_project_event"))
           for r in read_jsonl(root / "manifest.jsonl") if r.get("serial", 0) <= cutoff}
    for k, new in man.items():
        seen.setdefault(k, {"ts": None})["new"] = new

    n_new = sum(e["new"] for e in seen.values())
    s_new = sum(man.values())
    strata = {"new": (n_new, s_new), "update": (len(seen) - n_new, len(man) - s_new)}
    ts = [e["ts"] for e in seen.values() if e["ts"]]
    (root / "strata.json").write_text(json.dumps(
        {"source": "live", "window": [min(ts, default=0), max(ts, default=0)],
         "cutoff_serial": cutoff if cutoff != float("inf") else None, "strata": strata}, indent=1))
    for s, (tot, smp) in strata.items():
        print(f"{s:7s} {tot:6d} published, {smp:5d} fetched ({smp / max(tot, 1):.1%}, weight {tot / max(smp, 1):.2f})")


if __name__ == "__main__":
    main()
