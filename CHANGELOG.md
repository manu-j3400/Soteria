# Changelog

All notable changes to Soteria are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-22

First stable release. Soteria is a production multi-engine code security platform.

### Detection
- Six-layer detection pipeline: pattern scan, entropy profiler, SNN temporal
  profiler, Random Forest ensemble, GCN inference, and optional Semgrep.
- 1,498 vulnerability patterns across 13 languages via tree-sitter.
- 101-feature Random Forest ensemble (89 AST node counts + 12 engineered features).
- Graph Convolutional Network over control-flow graphs with adaptive blending
  (activates at validation F1 ≥ 0.60).
- Structural normalization that defeats variable-renaming obfuscation.

### Platform
- Production Flask middleware: JWT auth, SQLite scan history, per-user rate
  limiting, 24h result caching, webhook notifications.
- Online retraining pipeline with persistent retrain log.
- KL-divergence model-drift detection with auto-retrain scheduler.
- GitHub OAuth (PKCE), CSV/PDF export, OpenAPI/Swagger docs.

### Security Engines
- **Kyber** — multi-modal deep program analysis (TDA, Siamese GCN, SNN).
- **DeceptiNet** — hypergame-theoretic DRL honeypot orchestrator.
- **SymbAPT** — neurosymbolic APT hunter with MITRE ATT&CK rules.
- **RLShield** — multi-agent MAPPO SOC response orchestrator.
- **AgentShield** — DOM Merkle-hash TOCTOU detector (Rust).
- **ContainerGuard** — container-escape detection via syscall-graph GNN.
- **MemShield** — ROP-chain and heap-spray memory-exploit detection.
- **Ruflo** — MCP server exposing the scanning API to AI agents.

### Infrastructure
- React 18 + Vite 6 frontend on Vercel, Flask API on Render, Docker support.
- CI: middleware tests, mypy type-checking, Kyber PR taint analysis.
- 154 passing tests.

[1.0.0]: https://github.com/manu-j3400/Soteria/releases/tag/v1.0.0
