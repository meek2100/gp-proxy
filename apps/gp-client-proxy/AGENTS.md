---
applyTo: "**"
---

<!-- File: apps/gp-client-proxy/AGENTS.md -->

# apps/gp-client-proxy/ — Rust Host Agent Conventions

Rules in this file apply to all Rust source files in `apps/gp-client-proxy/` and its subdirectories.
See the project root `AGENTS.md` for project-level architecture, the TOFU security model, and the sandbox protocol.

## Rust Language Rules

- Uses `clippy` (warnings as errors) and `rustfmt`. No unused code or fields allowed.
- CLI outputs must be professional — no emojis; use text brackets like `[SUCCESS]`, `[ERROR]`.
- Uses `ureq` (3.x) for HTTP requests (`send_empty`, `read_json`).
- Uses `serde` for JSON parsing.
- Uses `webbrowser` to launch the Auth page.

## HTTP Agent & Connection Pooling

- Utilize a single, globally instantiated `ureq::Agent` for standard connections and a separate fast `ureq::Agent` for status polling.
- Do **not** instantiate new HTTP agents inside loops — this discards TCP connection pooling and exhausts system ports.
- **Timeout profiles:** Routine requests (connect, disconnect, submit) use a standard 10-second agent. Status polling uses a localized 2-second fast agent (`get_fast_agent`).

## Ed25519 TOFU Pairing

- On first run, generate an Ed25519 keypair and issue `POST /api/pair` to securely lock the container identity.
- For all subsequent requests, sign a Unix timestamp and the URL path (e.g. `1710000000:/status.json`) and pass `X-Signature` and `X-Timestamp` HTTP headers to authorize.
- Base URLs persisted in the Host Agent configuration must have trailing slashes aggressively trimmed `.trim_end_matches('/')` during serialization and deserialization. Failing to sanitize produces `//` paths that break Ed25519 signature validation.

## Keystore Privileges

- Any Rust logic writing long-lived secret materials (like `private_key` fields) to disk MUST explicitly lock down filesystem privileges (e.g. `0o600` on UNIX). Do not rely on default OS masks.

## Auto-Discovery

- Broadcast `GP_DISCOVER` on UDP 32800 to find the container IP automatically rather than requiring manual configuration.

## Status Polling JSON

- The `error` field in `/status.json` must return `None` (resulting in JSON `null`) if no error is present. Parse this field as `Option<String>` and surface the actual API response via `.as_deref().unwrap_or(...)` to prevent silent failure masking.

## Operating Modes

The binary operates in two modes:

1. **Dashboard Mode (Interactive):** Launches when the user runs the executable. Displays real-time status (polled from `status.json`), allows Connect/Disconnect actions, and automatically opens the system default browser to the Auth URL when required.
2. **Handler Mode (Background):** Triggered by the OS when a `globalprotect://` link is clicked. Captures the callback URL, forwards it to the Container Agent via `POST /submit` using Ed25519 signed headers, and exits immediately (fire-and-forget).
