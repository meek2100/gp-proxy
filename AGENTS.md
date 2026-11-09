<!-- File: AGENTS.md -->

# AI Agent Guidelines & Project Architecture

This file is the root constitution for any AI agent interacting with the `gp-proxy` repository.
Per-directory `AGENTS.md` files in `backend/`, `tests/`, `web/`, `apps/gp-client-proxy/`, and `apps/gp-client-proxy/src/` provide directory-scoped rules.

## 1. Mission & Architecture Overview

- **Project Purpose:** Encapsulate a GlobalProtect-compatible VPN client inside Docker, exposing it via proxy protocols (SOCKS5, HTTP, HTTPS, Shadowsocks) and/or a Transparent NAT Gateway using a Three-Tier Split-Agent architecture (Container, Desktop Host Agent in Rust, and Browser).
- **Active Playbook(s):** Playbook B (Brownfield Governance Onboarding) + Playbook C (Production Readiness Audit).
- **Canonical Truth Docs:**
    - Project Brief: `.agents/foundation/brief.md`
    - Master Plan & Task Ledger: `.agents/docs/plan.md`
    - Architecture & Shared Helper Registry: `.agents/docs/architecture.md`
    - Forensic Audit & Research: `.agents/docs/forensic-audit.md`, `.agents/docs/research.md`

## 2. Mandatory Sub-Agent Operating Rules

1. **Strict Scope Discipline:** Read ONLY this root `AGENTS.md`, the local `AGENTS.md` in your target directory, and exact files listed in your Work Order.
2. **Hard Traversal Blacklist:** NEVER run broad search, grep, or file-tree scans inside `.venv/`, `node_modules/`, `.git/`, `.agents/bin/`, or `.agents/cache/`.
3. **Task-Namespaced Sandbox Staging (`.agents/`):**
    - Never modify production source files directly unless executing an authorized `PROMOTION` task.
    - Write staged files exclusively to `.agents/scratchpad/<YOUR_TASK_ID>/`.
    - Read-only `recon-scout` returns findings to the lead, which persists them to `.agents/docs/drops/<YOUR_TASK_ID>.md`.
    - Write logs and evidence to `.agents/logs/<YOUR_TASK_ID>.md`, and QA outputs to `.agents/reports/<YOUR_TASK_ID>.md`.
    - Never modify `.agents/foundation/`. Sequential `consolidator` holds single-writer lock on `.agents/docs/`. `qa-validator` alone owns `.agents/scratchpad/INTEGRATION/`. `release-promoter` handles production promotion after Human approval.
4. **DRY & Shared Helpers:** Always check the Shared Helper Registry in `.agents/docs/architecture.md` and `backend/AGENTS.md` before authoring utilities.
5. **Zero Vaporware Policy:** Reject unfinished code and `TODO` comments. Deliver complete, verified implementations.
6. **ReAct & CoVe Mandatory:** Follow `Thought -> Action -> Observation`. Verify all paths, imports, and CLI commands with tools before reporting completion.

## 3. The `.agents/` Sandbox Protocol

### Sandbox Layout (8 Canonical Subdirectories)

- `.agents/foundation/` & `.agents/foundation/research/`: Read-only Human PM brief, seeds, and reference assets.
- `.agents/docs/` & `.agents/docs/drops/`: Canonical plans, architecture notes, and sub-agent research drops.
- `.agents/scratchpad/` & `.agents/scratchpad/INTEGRATION/`: Task-isolated staging trees and unified QA integration tree.
- `.agents/logs/`: Task-specific execution logs and command transcripts.
- `.agents/reports/`: QA validation reports, test runs, and checksum manifests.
- `.agents/assets/`: Design assets, screenshots, and visual reference materials.
- `.agents/bin/`: Standalone local portable tool binaries (never install global system packages).
- `.agents/cache/`: Local ephemeral caches (excluded from version control).

### Staging & Promotion Rules

- Do not modify `backend/`, `web/`, `apps/`, `entrypoint.sh`, or other root files until staged and verified in `.agents/scratchpad/`.
- Root `AGENTS.md` is the root constitution; updates must be staged and approved before promotion.

## 4. Architecture & Security Invariants

### Three-Tier Split-Agent Architecture

- **Tier 1 — Container Agent (The Brain):** Inside Docker (`backend/`, `entrypoint.sh`). State management & networking.
- **Tier 2 — Host Agent (The Manager):** Desktop native app in Rust (`apps/gp-client-proxy`). UI, auto-discovery, and bridge logic.
- **Tier 3 — Browser (The Auth Provider):** Executes SSO/SAML in native browser, redirecting to `globalprotect://...`.

### Network Modes (`VPN_MODE` & `PROXY_MODE`)

- `VPN_MODE`: `proxy,gateway` (proxies + iptables NAT, default), `proxy` (proxies only, NAT disabled), `gateway` (NAT only).
- `PROXY_MODE`: Comma-separated list: `socks5` (1080), `socks4` (1084), `socks4a` (1085), `http` (8080), `https` (8443), `ss` (8388).
- `SPLIT_TUNNEL=true`: Strips `0.0.0.0/0`, configures `dnsmasq`, policy routing table 100, and `ipset vpn_domains` with mark `0x10`.
- **Bridge Mode Shadow Routes:** High-metric routes (`10.0.0.0/8 dev tun0 metric 1024`) satisfy `rp_filter=1` in Docker Bridge mode.

### Security Directives

1. **Linting:** Python uses `uv`, `ruff` (120 chars), strict Basedpyright (Python 3.15). Rust uses `clippy` (warnings as errors), `rustfmt`, no CLI emojis. Shell uses `shellcheck` (no `xargs` trimming). Prettier for web/markdown/json.
2. **Source Code Isolation:** Python scripts reside in `/opt/gp-proxy/`, webroot in `/var/www/html/`. Explicit 403 on `*.py`, `*.sh`, `*.env`.
3. **Authentication:** Ed25519 TOFU pairing (`POST /api/pair`, atomic lock); 5-second replay window (`abs(time.time() - ts) < 5`). Ephemeral UI token injected into `index.html`. `API_TOKEN` environment override.
4. **Timing-Safe Auth:** Any token comparison must strictly use `hmac.compare_digest()`.
5. **IPC Callback & Sanitization:** SAML callbacks (`globalprotect://`) forward via `/submit` over TCP 32802 to `gpclient` stdin. Input tokens stripped of `\r` and `\n`.
6. **SSO Cache & UDP Beacon:** URL cached for `/status.json`. UDP port 32800 responds to `GP_DISCOVER` (credentials omitted).

## 5. Hierarchical `AGENTS.md` Routing Map

Before reading or staging changes in any directory, read its local `AGENTS.md`:

- `/AGENTS.md` — Global constitution, sandbox locks, and routing map (this file).
- `/backend/AGENTS.md` — Python backend rules, threading guards, and Shared Helper Registry (`backend/utils.py`).
- `/tests/AGENTS.md` — Test runner commands (`pytest`), mocking rules, security test assertions, and report outputs.
- `/web/AGENTS.md` — Dynamic DOM diffing, network resilience, proxy tab rendering, and ephemeral token handling.
- `/apps/gp-client-proxy/AGENTS.md` — Rust Host Agent conventions, ureq pooling, TOFU pairing, and operating modes.
- `/apps/gp-client-proxy/src/AGENTS.md` — Rust `main.rs` dispatch modes, doc comments, keystore permissions (`0o600`).

## 6. Sub-Agent Return Report Contract (< 200 Words)

Conclude every task report with:

- **Task ID & Status:** `TASK-XXX` | `STAGED` | `PROMOTED` | `BLOCKED` | `FAILED`
- **Base State Read:** Git SHA or file checksums inspected.
- **Exclusive Outputs Written:** Exact paths created/updated with SHA-256 hashes.
- **Verification:** Exact test/lint commands executed and pass/fail summary.
- **Unresolved Decisions:** Gaps, conflicting locks, or edge cases requiring Lead Orchestrator or Human PM input.
