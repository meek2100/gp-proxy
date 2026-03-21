---
applyTo: "**"
---

# apps/gp-client-proxy/src/ — main.rs Implementation Conventions

Rules in this file apply to all source files in `src/` and its subdirectories.
See `apps/gp-client-proxy/AGENTS.md` for Rust language rules, and the project root `AGENTS.md` for the security model and sandbox protocol.

## Module Dispatch Pattern

`main()` dispatches to three strictly ordered modes via `args[1]`:

1. **Protocol Handler** — `args[1].starts_with("globalprotect://")` → `handle_link()` → exit immediately.
2. **Uninstaller** — `args[1] == "--uninstall"` → `uninstall_process()` → exit.
3. **Dashboard** — default interactive loop via `run_dashboard()`.

Do not add new dispatch modes without updating all three match arms and the binary's `--help` output.

## HTTP Agent Instantiation

- `get_agent()` → 10-second global timeout. Use for all write actions: `connect`, `disconnect`, `submit`.
- `get_fast_agent()` → 2-second global timeout. Use for status polling only.
- Both agents must be instantiated **once** and passed by reference — never create a new agent inside a loop or per-request function.

## Authentication via `with_auth()`

All outbound HTTP requests must pass through `with_auth(req, &config, path)`. This function selects the correct auth mode automatically:

- Non-empty `config.token` → `Authorization: Bearer <token>` (legacy `API_TOKEN` override).
- Non-empty `config.private_key` → Ed25519 sign `"<ts>:<path>"` → `X-Timestamp` + `X-Signature` headers.
- Neither set → unauthenticated (TOFU not yet paired).

Never set auth headers manually outside `with_auth()`.

## Configuration File Format

`proxy_url.txt` is a plain-text file with exactly three lines:

```
<base_url>          # line 1 — required, trailing slashes stripped on read/write
<token>             # line 2 — empty string when using TOFU
<base64_private_key># line 3 — optional, 32-byte Ed25519 key; omit line if not using TOFU
```

`load_config()` must `.trim_end_matches('/')` on the URL. `save_config()` must write with `mode(0o600)` on Unix.

## Doc Comments

All public and module-level functions must have a `///` doc comment that includes:

- A one-line summary.
- `# Arguments` — for functions with non-obvious parameters.
- `# Returns` — for non-trivial return types.
- `# Errors` — for functions returning `Result`.
- `# Examples` — at least one `no_run` example for non-trivial functions.

Private helper functions (e.g., `clear_screen`, `wait_for_enter`) are exempt from full doc comment requirements.

## Platform-Gated Code

Use `#[cfg(target_os = "...")]` for all platform-specific features (Windows Registry handler, macOS `.icns` icon, Linux `.png` icon). Never use runtime `std::env::consts::OS` checks for compile-time-constant behavior — use cfg attributes instead.

## URL Safety

- Strip trailing slashes with `.trim_end_matches('/')` on every URL before persisting or signing.
- Percent-encode tokens with the `encode_token()` helper before appending to query strings — never concatenate raw tokens into URLs.
