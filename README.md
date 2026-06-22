# Soteria

[![CI](https://github.com/manu-j3400/Soteria/actions/workflows/ci.yml/badge.svg)](https://github.com/manu-j3400/Soteria/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-154%20passing-brightgreen)](https://github.com/manu-j3400/Soteria/tree/main/tests)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.13%2B-blue)](https://www.python.org)

**Soteria** is a machine-learning security platform that detects malicious code, backdoors, and injected vulnerabilities by analyzing the *structural and behavioral DNA* of source code. Instead of relying on easily bypassable keyword searches, Soteria layers four independent detection engines — pattern matching, statistical entropy, a Random Forest ensemble over Abstract Syntax Trees, and a Graph Convolutional Network over control-flow graphs — into a single verdict.

The detection core is branded **Kyber**. Around it sits a suite of research-grade security engines (honeypot orchestration, APT hunting, SOC response, container-escape and memory-exploit detection) under `engines/`.

🔗 **Live demo:** [trysoteria.live](https://trysoteria.live) · **API:** [a-c-i-d-1.onrender.com](https://a-c-i-d-1.onrender.com)

---

## How It Works

Every code submission flows through a layered detection pipeline. Each layer can independently raise the verdict; the highest-severity signal wins.

| # | Layer | What it catches | Torch? |
|---|-------|-----------------|--------|
| 1 | **Pattern scan** | 1,498 vulnerability patterns across 13 languages (SQLi, RCE, hardcoded secrets, dependency confusion, typosquatting) | No |
| 2 | **Entropy profiler** | Packed/obfuscated/encrypted payloads via Shannon entropy of string & byte literals | No |
| 3 | **SNN temporal profiler** | Anomalous execution rhythm (decryption loops, unpacking, network probing) using a spiking neural network | Yes |
| 4 | **RF ensemble** | 101-feature Random Forest vote (89 AST node counts + 12 engineered features) | No |
| 5 | **GCN inference** | Structural intent via Graph Convolutional Network over the control-flow graph | Yes |
| 6 | **Semgrep** *(optional)* | AST-level community rules as a fourth deep-scan layer | No |

**Structural DNA.** Code is parsed to an AST, variable names and constants are anonymized by a custom `ast.NodeTransformer` (so renaming obfuscation fails), then vectorized into a numeric feature matrix:

| Function | `Assign` | `Call` | `BinOp` | `Attribute` | **Label** |
|---|---|---|---|---|---|
| `calculate_total` | 2.0 | 1.0 | 3.0 | 0.0 | **0 (Clean)** |
| `backdoor_shell` | 1.0 | 4.0 | 0.0 | 2.0 | **1 (Malicious)** |

The GCN blends into the final score when its validation F1 ≥ 0.60, with an adaptive weight (0.2–0.6) scaled by model confidence.

---

## Architecture

```
┌──────────────┐      HTTPS       ┌────────────────────┐
│   Frontend   │  ───────────────▶│     Middleware     │
│ React + Vite │  /analyze, /auth │  Flask (app.py)    │
│  (Vercel)    │◀───────────────  │  JWT · SQLite      │
└──────────────┘   verdict JSON   └─────────┬──────────┘
       │                                     │ sys.path
   Supabase                                  ▼
   (auth)                          ┌────────────────────┐
                                   │   backend/src/     │
                                   │  AST · GCN · SNN   │
                                   │  entropy · patterns│
                                   └────────────────────┘
```

- **Frontend** — React 18, Vite 6, TypeScript, Tailwind CSS 4, Framer Motion. Hosted on Vercel. Auth via Supabase.
- **Middleware** (`middleware/app.py`) — production Flask API: JWT auth, SQLite scan history, rate limiting, 24h result caching, webhook notifications, online retraining, model-drift detection. ~1,800 lines.
- **Backend** (`backend/src/`) — the ML/analysis modules the middleware imports at runtime.
- **Engines** (`engines/`) — standalone research security engines (see below).

---

## Security Engines (`engines/`)

The detection core is **Kyber**. Additional engines target distinct threat surfaces:

| Engine | Purpose |
|--------|---------|
| **Kyber** | Multi-modal deep program analysis: TDA manifolds, Siamese GCN IR verification, SNN temporal profiling |
| **DeceptiNet** | Adaptive honeypot orchestrator — hypergame-theoretic DRL (PPO + belief-state particle filter) |
| **SymbAPT** | Neurosymbolic APT hunter — differentiable MITRE ATT&CK rules + Kafka streaming |
| **RLShield** | Multi-agent MAPPO SOC response orchestrator with Wazuh integration |
| **AgentShield** | DOM Merkle-hash TOCTOU detector for browser-use agents (Rust) |
| **ContainerGuard** | Container-escape detection (GNN over syscall graphs: `unshare`, `pivot_root`, `chroot`) |
| **MemShield** | Memory-exploit detection (ROP-chain detection, heap-spray analysis, taint tracking) |
| **Ruflo** | MCP server exposing Soteria's scanning API as tools for Claude/Ruflo agents |

---

## Tech Stack

- **Languages:** Python 3.13+, TypeScript, Rust
- **ML / analysis:** scikit-learn, PyTorch, PyTorch Geometric (GCN), `ast`, tree-sitter (13 languages), pandas, joblib
- **Backend:** Flask, PyJWT, bcrypt, FPDF2 (reporting), flasgger (OpenAPI), gunicorn
- **Frontend:** React 18, Vite 6, Tailwind CSS 4, Framer Motion, Radix UI, Supabase
- **Infra:** Docker, GitHub Actions, Render (API), Vercel (frontend)

---

## Quick Start

### Prerequisites
- Python 3.13+
- Node.js 18+ (frontend)
- Rust toolchain (only for AgentShield)

### Backend / Middleware

```bash
# from repo root
pip install -r backend/requirements.txt

# run the production middleware API
cd middleware
python app.py          # serves on http://localhost:5000
```

### Frontend

```bash
cd frontend
npm install
# create frontend/.env.local with VITE_SUPABASE_URL + VITE_SUPABASE_ANON_KEY
npm run dev                          # http://localhost:5173
```

Required frontend env vars:

| Variable | Purpose |
|----------|---------|
| `VITE_SUPABASE_URL` | Supabase project URL (auth) |
| `VITE_SUPABASE_ANON_KEY` | Supabase anon key |
| `VITE_POSTHOG_KEY` | *(optional)* PostHog analytics — omit to disable |

### Docker

```bash
docker compose up --build
```

---

## API Reference

The middleware exposes a REST API. Interactive docs are at `/apidocs` (Swagger UI) when `flasgger` is installed.

**Core scanning**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/analyze` | Scan a single code snippet → verdict + vulnerabilities |
| `POST` | `/batch-scan` | Scan multiple files |
| `POST` | `/deep-scan` | Full multi-layer deep scan |
| `POST` | `/github-scan` | Scan a GitHub repository |
| `POST` | `/generate-report` | PDF executive summary |

**Auth & history**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/signup` · `/login` · `/logout` | JWT authentication |
| `GET`  | `/scan-history` | Authenticated scan history |
| `GET`  | `/api/scan-history/export` | CSV export |
| `POST` | `/github/pkce/state` · `/github/token` | GitHub OAuth (PKCE) |

**Model ops (admin)**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/admin/retrain` | Trigger online retrain |
| `GET`  | `/api/admin/retrain/status` · `/history` | Retrain state + persistent log |
| `GET`  | `/api/model/drift` | KL-divergence drift detection |
| `GET`  | `/model-stats` · `/api/engines/status` | Engine + model health |

Example:

```bash
curl -X POST https://a-c-i-d-1.onrender.com/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "import os\nos.system(input())"}'
```

---

## Project Structure

```
.
├── middleware/app.py        # Production Flask API (JWT, SQLite, retraining, drift)
├── backend/
│   ├── src/                 # AST/GCN/SNN/entropy/pattern modules
│   ├── CSV_master/          # Training data
│   └── ML_master/           # Serialized models (acidModel.pkl, acidModel_gcn.pt)
├── frontend/                # React + Vite dashboard
├── engines/                 # Kyber + research security engines
├── tests/  backend/tests/   # 154 tests
└── .github/workflows/       # CI: ci.yml, middleware-ci.yml, kyber-pr-check.yml
```

---

## Testing

```bash
# full suite (154 tests)
python3 -m pytest tests/ backend/tests/

# frontend type-check + build
cd frontend && npx tsc --noEmit && npm run build
```

**CI** runs the middleware test suite, mypy type-checking, and (on PRs) the Kyber taint-analysis check via GitHub Actions.

---

## License

MIT — see [LICENSE](LICENSE).
