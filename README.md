# ZERO SUITE v1.0

**Epistemic Defensive Web Surface Auditor, Anti-Trap Shield, and Deliberative ZSES + EmbeddingGemma 2 Workbench**

[![Version](https://img.shields.io/badge/VERSION-1.0-CCFF00?style=flat-square&labelColor=0D0D0D)](https://github.com/VersaNexusIX/Zero-Suite)
[![License: MIT](https://img.shields.io/badge/LICENSE-MIT-F2F2EE?style=flat-square&labelColor=0D0D0D)](./LICENSE)
[![Design System](https://img.shields.io/badge/STYLE-VERSANEXUSIX-CCFF00?style=flat-square&labelColor=0D0D0D)](./DESIGN.md)
[![Python](https://img.shields.io/badge/PYTHON-3.11%2B-8A8A85?style=flat-square&labelColor=0D0D0D)](https://www.python.org/)
[![Repository](https://img.shields.io/badge/GITHUB-VersaNexusIX%2FZero--Suite-111111?style=flat-square&labelColor=0D0D0D)](https://github.com/VersaNexusIX/Zero-Suite)

---

## Executive Rationale

Conventional web security scanners routinely conflate heuristic suspicion with empirical proof, flooding engineering teams with unverified alerts while remaining oblivious to crawler traps, redirect hijacking, and their own observational limits. **Zero Suite v1.0** is architected around a stricter epistemic mandate: **a defensive auditing system must prove when it is right, explicitly declare when it does not know, and articulate precisely why an unconfirmed vulnerability cannot yet be substantiated.**

Operated strictly within authorized defensive scopes, Zero Suite pairs a deterministic, rule-governed **Zero Suite Expert System (ZSES)** with a read-only semantic path planner powered by **EmbeddingGemma 2 (EG2)**. Control flow, initial resource discovery, network execution, and safety enforcement remain exclusively under ZSES governance. EmbeddingGemma 2 possesses **zero execution privileges** against target infrastructure; its remit is confined to vector-space route prioritization, semantic trap avoidance, online contrastive metric adaptation, and multi-round analytical deliberation until epistemic convergence is reached.

---

## Architectural Invariants

1. **Expert-Owned Control Plane (`ZSES -> ZeroSuiteAuditor`)**: Initial scope calibration, `robots.txt` compliance, `sitemap.xml` ingestion, TLS inspection, and persistent memory hydration originate exclusively from ZSES.
2. **Zero-Execution AI Boundary**: `EmbeddingGemma2Advisor` receives curated, read-only frontier snapshots and returns ranked analytical recommendations. It holds no HTTP session to the target, no shell capability, and no autonomous mutation rights.
3. **Epistemic Verdict Ledger (`PROVEN` · `UNCONFIRMED` · `UNKNOWN`)**:
   - **`PROVEN`**: Deterministically substantiated by reproducible HTTP/TLS/DOM telemetry (e.g., dual-origin CORS reflection, absent security headers, `200 OK` source map exposure). Eligible for non-destructive Verification PoC generation.
   - **`UNCONFIRMED`**: Heuristic or partial signals (e.g., static DOM sinks, POST forms lacking visible CSRF inputs, framework-level CVE/KEV banner matches). Zero Suite refuses to issue synthetic PoCs for these leads and instead states *why confirmation failed* and *what evidence is required*.
   - **`UNKNOWN BOUNDARIES`**: Explicit declarations of blind spots outside passive visibility—such as authenticated IDOR/BOLA matrices, server-side injection sinks, and `robots.txt`-excluded paths.
4. **Strict Redirect & Egress/SSRF Guard**: Disables implicit redirect chaining (`allow_redirects=False`), enforcing manual hop-by-hop verification against cross-host escapes, `HTTPS -> HTTP` downgrades, redirect loops, and non-global IP resolution (`RFC 1918`, loopback, link-local, and cloud metadata ranges).
5. **Adaptive Honeypot Shield & Persistent Vault (`/sdcard/.zerorcmemo`)**: Filters hidden CSS/ARIA links, cyclic or deeply nested trap URLs, duplicate-content traps (SimHash), and sustained high-latency tarpits. Learned `TRAP` and `SAFE` templates, historical drift snapshots, and trained 256-dimensional EG2 adapter weights persist across restarts in SQLite at `/sdcard/.zerorcmemo` (falling back gracefully to `~/.zerorcmemo` on non-Android hosts).
6. **Non-Destructive Verification PoCs**: For every `PROVEN` posture finding, ZSES + EG2 synthesize safe `curl` and `openssl` verification commands paired with expected vulnerable signals, expected patched signals, and Blue Team hardening snippets—exportable to Markdown (`zero_suite_verification_poc.md`) and VersaNexusIX-styled HTML reports.

---

## Modular Repository Structure

```text
Zero-Suite/
├── Zero-Suite.py           # Backward-compatible CLI entrypoint
├── setup.sh                # Automated bootstrap for Termux (Android), Linux, and macOS
├── setup.ps1               # Automated bootstrap for Windows PowerShell
├── pyproject.toml          # Modern PEP 621 package manifest (`zero-suite` CLI script)
├── requirements.txt        # Core runtime dependencies
├── requirements-eg2.txt    # Optional Hugging Face / Sentence Transformers stack for EG2
├── DESIGN.md               # Canonical VersaNexusIX Design System specification
├── LICENSE                 # MIT License
├── README.md               # Project documentation
└── zero_suite/
    ├── __init__.py         # Package exports and version metadata
    ├── core.py             # Shared base: tokens, dataclasses, RateLimiter, SimHash, SSRF & trap guards
    ├── memory.py           # ZeroMemoryStore (SQLite vault) & PublicIntelFetcher (CISA KEV / OSV.dev)
    ├── eg2.py              # EmbeddingGemma2Advisor: Ollama/HF/256d MRL fallback, online training & deliberation
    ├── expert.py           # ZeroExpertSystem: epistemic ledger, risk chains, drift & Safe Verification PoC builder
    ├── auditor.py          # ZeroSuiteAuditor: deep crawler, JS bundle audit, repeater, comparer & JWT inspector
    ├── ui.py               # VersaNexusIX TUI renderer, HTML report generator & Markdown PoC dossier exporter
    └── cli.py              # Argument parser and interactive workbench (Modules 00–07)
```

---

## Technology Stack

| Layer | Component | Specification & Role |
| :--- | :--- | :--- |
| **Runtime** | Python `3.11+` | Type-annotated modern Python (`slots=True`, `sqlite3`, `ssl`, `ipaddress`, `concurrent.futures`). |
| **HTTP & Parsing** | `requests`, `urllib3`, `BeautifulSoup4` | Bounded streaming fetches, manual hop-by-hop redirect enforcement, HTML/XML/JS passive inspection. |
| **Semantic AI** | **EmbeddingGemma 2** (`google/embeddinggemma-2` / `embeddinggemma-2:270m`) | 256-dimensional Matryoshka Representation Learning (MRL) embeddings via local **Ollama** (`/api/embed`), **Sentence Transformers** (text-only encoder), or deterministic 256d local fallback. |
| **Online Adaptation** | 256d Contrastive Metric Adapter | Pure-Python multi-epoch margin-loss trainer persisting adapted weights and trap/safe centroids in SQLite. |
| **Threat Intelligence** | **CISA KEV** & **OSV.dev** | Allowlisted, read-only public advisory enrichment with 24-hour local disk caching (`--no-net-intel` for strict offline mode). |
| **Persistent Memory** | `SQLite3` (`/sdcard/.zerorcmemo`) | Atomic cross-session storage for `trap_memory`, `scan_history` drift tracking, and `eg2_adapter_state`. |
| **Visual System** | **VersaNexusIX Design System** (`Rich` + Editorial HTML/CSS) | Industrial monochrome (`#0D0D0D`, `#111111`, `#242424`, `#F2F2EE`, `#8A8A85`) with surgical `#CCFF00` lime acid, `0px` corners, `Silkscreen` + `Plus Jakarta Sans` + `IBM Plex Mono`, `.pixel-frame`, `.pixel-reticle`, and `.pixel-flame`. |

---

## Automated Installation & Model Setup

### 1. Clone the Repository

```bash
git clone https://github.com/VersaNexusIX/Zero-Suite.git
cd Zero-Suite
```

### 2. Run the Automated Bootstrap

**Linux, macOS, and Termux (Android):**

```bash
chmod +x setup.sh
./setup.sh
```

**Windows (PowerShell):**

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup.ps1
```

The installer automatically verifies or installs **Python 3.11+**, provisions a virtual environment (or configures Termux shared storage for `/sdcard/.zerorcmemo`), installs all core packages, and guides you through selecting your **EmbeddingGemma 2** runtime:

- **Option 1 — Ollama (`embeddinggemma-2:270m`)**: Installs Ollama (where supported) and pulls the quantized 270M text+code GGUF build for low-latency CPU inference.
- **Option 2 — Hugging Face (`google/embeddinggemma-2`)**: Installs `requirements-eg2.txt` and initializes the text-only encoder (`vision_config=None, audio_config=None`).
- **Option 3 — Zero-Dependency 256d Fallback**: Requires no external model weights; ideal for resource-constrained mobile/Termux environments while preserving the full epistemic and online-training pipeline.

---

## Usage

### Interactive Workbench

```bash
python3 Zero-Suite.py
```

The interactive console exposes seven operational modules: **01 Deep Epistemic Audit**, **02 Safe HTTP Repeater**, **03 Response Comparer**, **04 Decoder & JWT Audit**, **05 Expert & Epistemic View**, **06 Memory Vault**, and **07 Safe PoC Dossier**.

### Headless CLI Audit

```bash
python3 Zero-Suite.py https://authorized-target.example \
  --profile deep \
  --embed-backend auto \
  --deliberation-rounds 4 \
  --train-epochs 12 \
  --html-report zero_report.html \
  --poc-dossier zero_poc.md \
  --accept-policy
```

### Key CLI Flags

| Flag | Default | Purpose |
| :--- | :--- | :--- |
| `--profile {deep,light}` | `deep` | Controls sitemap ingestion, JS bundle/source-map inspection, and per-template header auditing. |
| `--embed-backend {auto,ollama,st,fallback}` | `auto` | Selects the EmbeddingGemma 2 inference backend. |
| `--memory-dir PATH` | `/sdcard/.zerorcmemo` | Overrides the persistent SQLite memory vault directory. |
| `--memory-status` | `false` | Displays memorized `TRAP`/`SAFE` signatures and cumulative EG2 training epochs. |
| `--deliberation-rounds N` | `4` | Sets ZSES ↔ EG2 deliberation depth before consensus lock. |
| `--train-epochs N` | `12` | Sets contrastive metric adaptation epochs executed per audit. |
| `--no-net-intel` | `false` | Disables public CISA KEV / OSV.dev network lookups for air-gapped operation. |
| `--allow-private` | `false` | Explicitly permits auditing authorized `localhost` / RFC 1918 staging targets. |
| `--poc-dossier PATH` | `None` | Exports the Markdown Verification PoC & Epistemic Dossier. |

---

## Model Attribution & Third-Party Notices

- **EmbeddingGemma 2 (`google/embeddinggemma-2`)**: Developed by **Google DeepMind** and released under the **Apache License 2.0** ([Hugging Face Model Card](https://huggingface.co/google/embeddinggemma-2)). Built on the Gemma 4 architecture with a modular 270M-parameter text/code core and Matryoshka Representation Learning (MRL) truncation (`128`, `256`, `512`, `768` dimensions). Zero Suite does not redistribute model weights; users retrieve weights directly from official Hugging Face or Ollama registries subject to Google DeepMind's Apache 2.0 terms.
- **Public Vulnerability Feeds**: Optional read-only advisory correlation queries the **CISA Known Exploited Vulnerabilities (KEV)** catalog and the **OSV.dev** open-source vulnerability database.

---

## Authorized Use & License

Zero Suite is strictly a **defensive security posture and epistemic verification workbench**. Operate it solely on web assets you own or for which you hold explicit written authorization.

Released under the **MIT License**. See [LICENSE](./LICENSE) for full terms.
