"""
Pull real PyPI malware samples from DataDog/malicious-software-packages-dataset
(samples/pypi/malicious_intent) as training data for the malicious class.

Samples are password-protected zips (password "infected"). We keep them
encrypted on disk and only decrypt .py members in memory when parsing
(see features.iter_sources), so no plaintext malware ever lands on disk and
antivirus has nothing to quarantine. Nothing is installed, imported or executed.

Samples discovered on/after --before are skipped so training never overlaps
the eval window.

Usage:
  python3 -I ingest_datadog.py --out ~/soteria_malware_samples --before 2026-10-01
"""
from __future__ import annotations

import argparse
import io
import json
import re
import subprocess
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = "DataDog/malicious-software-packages-dataset"
RAW = f"https://raw.githubusercontent.com/{REPO}/main/"
MAX_ZIP = 2 * 1024 * 1024
MAX_MEMBER = 1024 * 1024


def list_samples() -> list[dict]:
    sha = subprocess.check_output(
        ["gh", "api", f"repos/{REPO}/contents/samples/pypi", "--jq",
         '.[]|select(.name=="malicious_intent").sha'], text=True).strip()
    tree = json.loads(subprocess.check_output(
        ["gh", "api", f"repos/{REPO}/git/trees/{sha}?recursive=1"], text=True))
    return [e for e in tree["tree"] if e["path"].endswith(".zip")]


def fetch_one(entry: dict, out: Path) -> dict:
    path = entry["path"]
    m = re.search(r"(\d{4}-\d\d-\d\d)", path)
    rec = {"path": path, "date": m.group(1) if m else None, "pkg": path.split("/")[0]}
    if entry["size"] > MAX_ZIP:
        return {**rec, "status": "too_big"}
    try:
        url = RAW + "samples/pypi/malicious_intent/" + urllib.request.quote(path)
        blob = urllib.request.urlopen(url, timeout=60).read()
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            n = sum(1 for i in zf.infolist() if i.filename.endswith(".py")
                    and not i.is_dir() and i.file_size <= MAX_MEMBER)
        dest = out / "zips" / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(blob)  # still encrypted
        return {**rec, "status": "ok" if n else "no_py", "n_py": n, "zip": str(dest.relative_to(out))}
    except Exception as e:
        return {**rec, "status": f"error:{type(e).__name__}"}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="~/soteria_malware_samples")
    p.add_argument("--before", default="2026-10-01")
    a = p.parse_args()
    out = Path(a.out).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    entries = [e for e in list_samples()
               if (re.search(r"(\d{4}-\d\d-\d\d)", e["path"]) or [None, "9999"])[1] < a.before]
    print(f"{len(entries)} samples discovered before {a.before}")
    with ThreadPoolExecutor(16) as ex:
        recs = list(ex.map(lambda e: fetch_one(e, out), entries))
    (out / "manifest.jsonl").write_text("".join(json.dumps(r) + "\n" for r in recs))
    ok = sum(r["status"] == "ok" for r in recs)
    print(f"{ok} encrypted samples saved under {out / 'zips'}")


if __name__ == "__main__":
    main()
