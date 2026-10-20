# Soteria on one week of PyPI (Oct 10 to 17, 2026)

Scope: Soteria is a multi-language detector (tree-sitter parsing plus the
vulnerability_db pattern set for Go, Rust and others). This evaluation covers
only the Python path: the AST model, constant categories and the Python
dataflow rules. Nothing here measures the other language paths.

First run, Oct 17. Hand labels are a first pass and still need human review.
Rerun `crosscheck.py` + `precision.py` around Oct 21 to 22: takedown reports
lag publishes, so more true positives will show up.

## Data

| | releases |
|---|---|
| Releases in the week (changelog) | 74,441 (13,174 from new projects, 61,267 updates) |
| Fetched: all new-project releases + random 3,000 updates | 16,174 |
| Scored (.py files present) | 15,203 (11.2M functions, median 196 per release) |
| Gone before download | 373, of which 46 are known malware |
| Known malware among scored | 2 (`pyyi` 2.4.1, 2.4.2; MAL-2026-17866, removed from PyPI Oct 17) |

Ground truth: OSV `MAL-*` / malicious-package advisories (includes
ossf/malicious-packages), Datadog malicious-packages manifest, PyPI removal.
Update rows are reweighted x20.4 to the full week.

## Models

| model | training data | features | held-out mal. F1 | held-out FPR (per function) |
|---|---|---|---|---|
| baseline (`acidModel.pkl`) | 5,780 original samples | 101 AST | 0.81 (reported) | 2.1% (reported) |
| realdata | + 26.5k real PyPI benign units (Sep 24 to 26) + 8.9k Datadog malware units | 101 AST | 0.863 | 5.1% |
| constcat | same rows | 101 AST + 20 constant categories | 0.872 | 4.6% |

Held-out split is grouped by package. Datadog recall for the retrained models
is not reported because ~85% of those packages were in their training set.

## Results on the week

| model / rule | functions flagged | releases flagged (week) | precision | 95% CI upper | Datadog recall |
|---|---|---|---|---|---|
| baseline, any unit >= 0.5 | 34.9% | 99.2% | 0.003% | 2.5% | 68% |
| baseline, install-time unit | | 84.6% | 0.003% | 2.5% | 49% |
| realdata, any | 2.8% | 91.8% | 0.003% | 2.9% | n/a |
| realdata, install-time | | 47.5% | 0 of 6,376 | 5.4% | n/a |
| constcat, any | 2.5% | 90.3% | 0.003% | 3.0% | n/a |
| constcat, install-time | | 45.5% | 0 of 5,905 | 6.1% | n/a |
| risky constant category alone (no model) | | 8.5% | 0 of 1,037 | 2.5% | 35% |
| baseline + risky constant, same unit | | 2.6% | 0 of 262 | 2.5% | 11% |

0 malicious found in 682 hand-reviewed flagged releases. The only known
malware still downloadable (`pyyi`) ranks around the median under every model
(top 30 to 60%), so no threshold catches it without flagging a third of PyPI.

## Why

1. **Training shortcut.** `Import` nodes appear in 76% of malicious training
   samples and 7% of benign. Benign = CodeSearchNet functions, malicious =
   mostly CyberNative DPO (LLM-written *vulnerable* code, not malware). The
   baseline learned "has imports / looks like a module" = malicious.
2. **Wrong unit.** Even at 2.5% per function, a 196-function release has
   1 - 0.975^196 ≈ 99% chance of at least one flag. Scoring has to be
   per package, not max-over-functions.
3. **Constants help, a little.** Same rows, constant categories add +0.009 F1
   and -0.5pt FPR. They don't fix the unit problem.
4. **pyyi miss.** Decode (`gzip.decompress(b64decode(...))`, cli.py:678) and
   `exec(compile(...))` (cli.py:681) are separate statements; server URL comes
   from `PY2_SERVER` env var with fallback to an unknown domain. Needs
   dataflow (source -> decode -> exec), not a single-expression check.

## False-positive patterns (first-pass labels)

Baseline, any-unit sample (n=150): import-only modules 31%, ordinary functions
28%, test files 27%, other module-level code 9%.

Baseline + risky constant, same unit (n=150): Telegram/Discord/Slack bot code
42%, SDKs reading `*_API_KEY` and calling their own API 29%, tunnel/paste host
mentions in docs/tests 11%, public-IP lookups (ipify etc.) 8%.

Risky constants alone (n=150): API-key SDKs 40%, bot code 23%, hardcoded
backend IPs 9%, test fixtures 9%, IP lookups 7%.

Feross's patterns, seen but rare in samples:
- binary fetchers: `pulsecheckcli` (shoutrrr from GitHub releases),
  `chatify-app` (downloads Ollama)
- install-time network: `camb` setup.py runs `git clone`
- security tooling: `adxpl-forge` (AD red-team kit) and `ttprism` (attack
  test corpus) were quarantined by Norton after download
- licensing obfuscation: none in samples. Bundled/vendored: 3 releases.

## Package-level dataflow rules (Oct 19)

`backend/src/dataflow_rules.py`: def-use taint over the AST, per package.
Sources: network responses, whole-environment dumps, host identity,
credential files, decoders. Sinks: exec/eval, subprocess/os.system, network
sends, plus constant shell downloaders and reverse shells. No model.

| version | rule | week flagged | precision | Datadog recall (raw / unique payloads) |
|---|---|---|---|---|
| v2 (bug-fixed, untuned) | strong | 3.5% | 0.08% (pyyi caught) | 39.6% / 23% |
| v2 | install-time only | 0.1% (9) | 0 of 9 | 39.9% / 21% |
| v3 (tuned on this week) | strong | 1.7% | 0.17% (pyyi caught) | 35.3% / 17% |
| v3 | install-time only | 0.05% (7) | 0 of 7 | 37.8% / 18% |

0 malicious among 240 hand-read dataflow-flagged releases. v3 was tuned on
these labels, so its week numbers are optimistic; the live-collector week
(Oct 19 to 23) is the held-out test. v2 outputs are in `scores/dataflow_v2/`.

Dataflow false positives (v2 sample, n=240): dev tools running subprocesses
57, LAN-IP lookups 54, test code 33, device registration/telemetry 30,
installers and self-updaters (curl | sh, download wheel then pip install) 29,
import-hook mocks 22. `webrunc` execs code from a caller-supplied URL: a
dangerous API by design, not malware.

### Live held-out run (collected Oct 19 to 20, v3 rules frozen before collection)

1,593 releases (all 1,038 new projects, 638 of 11,336 updates), downloaded
within minutes of publish. Reweighted to the full window (11,453 releases).

| rule | flagged (raw) | malicious | precision (reweighted) | 95% CI |
|---|---|---|---|---|
| model, any unit | 1,574 (99.4%) | 2 | 0.02% | to 2.5% |
| dataflow strong | 20 (2.1%) | 2 | 5.7% (raw 2/20 = 10%) | 1.4% to 25% |
| dataflow any | 26 (3.0%) | 2 | 4.3% (raw 7.7%) | 1.0% to 20% |
| dataflow install-time | 2 (0.2%) | 1 | | |

v4 (parameter taint, built and frozen on Datadog + the eval week, never on
this data): any-rule flags 32, malicious 3. It catches `vinted-mocked-apis`
(the beacon-through-a-parameter miss) and adds 5 benign flags (cluster
registration, device session, a ClamAV GUI's issue report, an offensive
security tool's OSINT lookup, an endpoint health check). `memories-core` and
`hx-depconf-canary` still missed.

True positives: `asurion` 99.0.0 (dependency-confusion PoC, MAL-2026-18045,
flagged install-time) and `pyyi` 2.5.0, a re-upload of the pyyi payload
(`run_payload`: base64+gzip from a space-z.ai server, then exec) after
PyPI removed 2.4.x. Not in OSV/Datadog at scan time; still live on PyPI
Oct 19. Reported to PyPI via "Report project as malware" on Oct 20 (account
mj3400), with an Inspector link to the exec line (cli.py:659). Missed: `vinted-mocked-apis` and `memories-core` (dependency-confusion
beacons passing the hostname through a function parameter, which the rules
don't track). New false-positive shapes seen but not tuned on: NSS `certutil`,
`start cmd.exe /k`, `os.dup` of stdout read as a reverse shell.

What no .py rule can see (subagent read of missed Datadog clusters, not
counted exactly): metadata-only typosquats, droppers that only declare a
stealer in install_requires, payloads in .so/.bat/.dll/.sh/.js files.
Estimated 100 to 150 of 758 unique payload clusters.

### v4: parameter-aware taint (Oct 19, not yet adopted)

`backend/src/dataflow_rules_v4.py` (`dataflow_scan.py --rules v4`, output in
`scores/dataflow_v4/`). v3 is unchanged and stays the rule set for the live run.
When a call passes labeled values into a package function (same resolution
as return values: unique, non-generic name, `f()` or `self.f()`; plus bare calls
to a generic name defined at the top of the same module, marked `loose`), the
callee is re-analyzed with those parameters labeled (memoized per label set,
depth 2). Findings sit on the callee's line, with the caller in `via`, and count as
install-time when the outermost caller is. Only exfil-source labels (env dump,
cred file, hostinfo/hostid) cross into parameters. Pushing NET/NETFILE/DECODED down too
(`scores/dataflow_v4_alllabels/`) found nothing extra on Datadog but took week
strong flags from 143 to 350. Those were all dev tools and self-updaters passing response
fields to their own subprocess helpers.

| rule | v3 | v4 | v4, all labels |
|---|---|---|---|
| Datadog strong, raw / unique payloads | 35.3% / 16.8% (127) | 39.8% / 19.0% (144) | same as v4 |
| Datadog install-time, raw / unique | 37.8% / 18.2% (138) | 40.8% / 18.9% (143) | 40.8% / 19.0% |
| week strong (raw, of 15,203) | 143 (0.94%) | 153 (1.01%) | 350 (2.30%) |
| week any | 217 | 254 | 452 |
| week install-time | 7 | 9 | 12 |

Most of the Datadog gain is one Discord-token-stealer family (cred file read,
then posted by an upload helper: 74 releases, 9 clusters), plus `send(data)`-style
env/hostname beacons. Of the 47 week releases newly flagged by v4 (37 any + 10
strong), all were read and none is malicious: generic HTTP wrappers handed
labeled config (lonoboard, pdt-cli, omnimarket, scriptcollection, semantic-memory-mcp),
device login/registration (hexiel, ergoda, hopsworks, aisquare-cli, stimulir,
protolabs-agent), telemetry/report posts (autoclip-mcp, adbc-replicate,
jcodemunch-mcp), localhost health probes (aicortex*, conexus), IP geolocation
(archivebox), token refresh (aden-hive), API lookups (depictio-cli), LLM call
(wfpy), self-update download (lium.io). Both new install-time flags are files that
happen to be named `setup.py` (a CLI's `setup` command, a build helper). Decide
on adoption after the live run, by rescanning it with `--rules v4`.

## npm, one day (Oct 19, JS dataflow rules)

`backend/src/dataflow_rules_js.py` (tree-sitter port of the same rules, plus
npm install hooks) and `npm_scan.py`. `fetch_npm.py` sampled 2,000 of 5,462
new packages and 1,000 of 43,595 updated ones from the replicate.npmjs.com
changes feed; 2,610 downloaded (5 more were already npm security-holding
placeholders). Unweighted counts below.

| rule | flagged | malicious | precision |
|---|---|---|---|
| JS code dataflow rules | 28 (1.1%) | 0 | 0% |
| `url_dependency` (metadata) | 6 (0.23%) | 6 | 6 of 6 |

- All 3 OSV-known malicious packages in the sample were missed by the code
  rules: dependency-only droppers with a 35-byte index.js whose payload is a
  dependency on an http(s) tarball (`ltidisafe` from
  `ltidi.storage.googleapis.com/depenconf/`, version 99.9.1). The
  `url_dependency` rule was written after seeing them, so its 6/6 is
  optimistic. It found 3 more packages from the same campaign that were not
  in OSV yet: `@jm-telefonica/multibrand-components`,
  `@fmr-ap153177/apex-kit-icons`, `@factoryz/apollo`.
- The 28 code flags are bundler output: Ajv validators compiled with
  `new Function` (12), legit script loaders (p5, a 3D engine), and whole
  programs in one chunk where `process.env` and `fetch` end up in the same
  scope. Feross's point 3 exactly: bundlers rewrite structure. Minified files
  were already skipped; bundled-but-readable `dist/` code is the open problem.

## Caveats

- Backfill, not live: malware removed before download (46 known) is missing,
  so true positives are undercounted. `fetch_pypi.py live` fixes this.
- Constant-category gate rules were tuned on 28 smoke-test packages from
  inside the eval window.
- Labels are one reviewer's first pass, heuristic patterns plus manual review
  of risky and install-time units. Blind second pass (Oct 20): an independent
  AI reviewer relabeled 25 random dataflow-flagged releases (week + live)
  without seeing the first labels. Agreement 20/20 on the items with code
  (19 direct, wandb-hivemind resolved: token exchange with W&B's own
  hivemind.wandb.tools); 5 items had no snippet (v2 flags that v3 no longer
  emits) and were excluded. No human second reviewer yet.
- Datadog samples are mostly GuardDog detections (selection bias).

## Reproduce

```bash
cd backend/eval_pypi
python3 -I fetch_pypi.py backfill --days 7 --update-sample 3000 --out ~/soteria_pypi_eval
python3 -I ingest_datadog.py --out ~/soteria_malware_samples --before 2026-10-01
python3 -I fetch_pypi.py backfill --days 2 --lag-hours 504 --new-sample 1000 \
    --update-sample 1000 --seed 7 --out ~/soteria_pypi_train_benign
python3 -I train_variants.py
python3 -I score.py --data ~/soteria_pypi_eval --tag baseline
python3 -I score.py --data ~/soteria_pypi_eval --tag constcat --model ../ML_master/acidModel_constcat.pkl
python3 -I crosscheck.py --data ~/soteria_pypi_eval --tag baseline
python3 -I label_sheet.py --data ~/soteria_pypi_eval --tag baseline --n 150
python3 -I precision.py --data ~/soteria_pypi_eval --tag baseline
```

`report.sh <data_dir> [tags...]` runs the scoring half in one go: score.py
(default tag `baseline`; other tags use `ML_master/acidModel_<tag>.pkl`),
dataflow_scan.py, crosscheck.py `--refresh-osv`, live_strata.py when needed,
label_sheet.py, precision.py. `SKIP_SCORE=1` reuses existing scores.
label_sheet.py keeps labels already filled in.

When `scores/dataflow/packages.csv` exists, precision.py and label_sheet.py
add dataflow rules: `df_any` (any rule fires), `df_strong` (any except
`decoded_exec` / `exfil_hostinfo`), `df_install` (finding in install-time
code), `model_and_df` (any unit >= 0.5 and `df_any`). Datadog recall uses the
malware dir's dataflow scan, so run `dataflow_scan.py --data
~/soteria_malware_samples` first.

Live collection (keeps malware that's taken down within days):

```bash
python3 -I fetch_pypi.py live --hours 168 --update-rate 0.06 --out ~/soteria_pypi_live
./report.sh ~/soteria_pypi_live
```

A live dir has no strata.json from the fetcher; live_strata.py builds it from
releases_all.jsonl (deduped) and the manifest on every report.sh run. Update
weights use the actual fetched share, which runs slightly above
`--update-rate` because releases re-seen in a later poll get another draw.

Nothing from PyPI or the malware set is installed, imported or executed. Only
`.py` text is kept; Datadog samples stay in their encrypted zips and stored code
snippets are zlib+base64 encoded so antivirus doesn't delete result files.
