<!-- File: AGENTS.md -->

# Agent Context: GP Proxy & Client

## Project Overview

This project encapsulates a GP-compatible VPN client inside a Docker container, exposing it via a SOCKS5 proxy (`gost`) on port 1080 and a Transparent Gateway. It utilizes a "Split-Agent" architecture where a secure **Container Agent** handles the networking/VPN and a **Host Agent** (Desktop App) handles the SSO authentication flow and management.

## Development Standards (Crucial)

**Strict linting and formatting are enforced via CI and Pre-commit hooks.** Any code changes must adhere to these standards to pass the `lint` workflow.

- **Python:** Uses `ruff` for formatting (line length 120) and linting. **Strict typing (Mypy/Pyright) is required.** The project uses Python 3.14. Note: Do not use subscripted generics for `socket.socket` as `typeshed` strictness will reject type arguments like `[Any, Any]`. Discarded process standard outputs (`stdout=subprocess.DEVNULL`) must be typed strictly as `CompletedProcess[bytes]` to satisfy Python 3.14 static type guarantees.
- **Rust:** Uses `clippy` (warnings as errors) and `rustfmt`. No unused code or fields allowed. CLI outputs must be professional (no emojis; use text brackets like `[SUCCESS]`, `[ERROR]`).
- **Shell:** Uses `shellcheck` (gcc format).
- **Formatting:** Uses `prettier` for Markdown, YAML, HTML, and JSON.
- **YAML:** Uses `yamllint` (relaxed mode, max 120 chars).
- **Docker:** Uses `hadolint` (ignores DL3008). Multi-arch support should be handled via dynamic arguments like `TARGETARCH` when downloading specific binaries.

## Architecture

The system uses a **"Three-Tier" architecture** to bridge the gap between a headless container and a desktop GUI login flow.

### 1. The Container Agent (The Brain)

**Location:** Inside Docker (`server.py`, `entrypoint.sh`)
**Role:** State Management & Networking

- **Source Code Isolation:** Python backend scripts (`server.py`, `control_listener.py`, `stdin_proxy.py`) MUST reside in `/opt/gp-proxy/` and NOT in the `/var/www/html/` web root. This prevents accidental source code exposure via the `http.server.SimpleHTTPRequestHandler`.
- **Timing-Safe Authentication:** Any token comparison logic (such as checking `API_TOKEN` in HTTP headers) must strictly utilize `hmac.compare_digest()` to prevent timing attacks.
- **Web Server (`server.py`):**
    - Runs on Port 8001.
    - **State Management:** Uses a thread-safe `StateManager` to handle concurrent access from the log analyzer and HTTP requests.
    - Parses logs (`gp-client.log`) to determine state (Idle, Connecting, Auth, Input, Connected, Error).
    - Exposes API endpoints: `/status.json` (polled), `/connect`, `/disconnect`, and `/submit` (auth tokens).
    - **Configurable Zero-Touch Security:** The server evaluates the `API_TOKEN` environment variable. If an `API_TOKEN` is provided, all control routes and status payloads strictly require `Authorization: Bearer <token>` headers and enforce a **fail-closed** zero-trust model. If omitted, `entrypoint.sh` enforces a secure-by-default posture by auto-generating a random 16-byte token and printing it to the container logs.
    - **UDP Beacon:** Listens on UDP port 32800 to auto-respond to discovery broadcasts from the Host Agent. The UDP Beacon broadcasts the container IP and Port to the Host Agent. For security against LAN sniffing, the `SESSION_TOKEN` is strictly omitted. Since `API_TOKEN` is enforced, the operator must pre-provision the Host Agent with the token.

### 2. The Host Agent (The Manager)

**Location:** User's Desktop (`apps/gp-client-proxy`)
**Role:** User Interface & Bridge
**Language:** Rust

This is a cross-platform binary (`gp-client-proxy`) that operates in two modes:

1.  **Dashboard Mode (Interactive):**
    - Launches when the user runs the executable.
    - **Auto-Discovery:** Broadcasts `GP_DISCOVER` on UDP 32800 to find the container IP automatically. Prompts the user to manually enter the `API_TOKEN` required by the container environment.
    - **Management:** Displays real-time status (polled from `status.json`) and allows Connect/Disconnect actions.
    - **Browser Launch:** Automatically opens the system default browser to the Auth URL when required, injecting the token via `?token=...`.
    - **Connection Info:** Displays the calculated Gateway IP and SOCKS port when connected.
2.  **Handler Mode (Background):**
    - Triggered by the OS when a `globalprotect://` link is clicked.
    - Captures the callback URL.
    - Forwards the URL to the Container Agent via `POST /submit`.
    - Exits immediately (fire-and-forget).

### 3. The Browser (The Auth Provider)

**Role:** SSO/SAML Execution

- The user authenticates (Okta, Microsoft, etc.) in their native browser.
- The portal redirects to `globalprotect://...`, handing control back to the Host Agent.

## Network Modes (`VPN_MODE`)

- **`standard`:** Starts `gost` (port 1080) AND configures `iptables` for NAT/IP Forwarding. Best for general use.
- **`socks`:** Starts `gost` ONLY. Disables IP Forwarding and NAT. Locked down.
- **`gateway`:** Configures NAT/IP Forwarding ONLY. No SOCKS proxy. Requires `macvlan` network driver.

## Key Files

### Container (Server)

- **`entrypoint.sh`:** Orchestrator. Handles `VPN_MODE`, `GOST_AUTH`, `ALLOWED_SUBNETS`, DNS Watchdog, cleanup traps, builds cross-platform Python IPC listener endpoints, and invokes `gpclient`.
- **`server.py`:** Python Control Server. Handles optional `API_TOKEN` bearer auth logic, length-limited payload parsing, uses Python 3.8+ Walrus operators to securely map API elements, reads binary `CLIENT_LOG`, and hosts the UDP Beacon. Control endpoints rely on OS-agnostic local TCP sockets (`IPC_CONTROL_PORT` and `IPC_STDIN_PORT`). Process lifecycle management (`_kill_and_poll`) dynamically detects the host OS (`sys.platform == "win32"`) to utilize `taskkill`, enabling full native Windows development and testing outside the container.
- **`web/index.html` / `web/index.js` / `web/index.css`:** Frontend assets. Separated for maintainability and Docker layer caching. Relies strictly on modern HTTP caching headers injected by `server.py` alongside dynamic MD5 cache-busting hashes applied at container startup. Supports parsing initial URL `?token=` parameters into local storage to transparently handle authorized environments.

### Host (Client)

- **`apps/gp-client-proxy/src/main.rs`:** The Rust source code.
    - Uses `ureq` (3.x) for HTTP requests (`send_empty`, `read_json`).
    - Uses `serde` for JSON parsing.
    - Uses `webbrowser` to launch the auth page.
    - Implements the "Manager" TUI (Text User Interface).
- **`apps/gp-client-proxy/Cargo.toml`:** Dependency definitions.

## Critical Implementation Details & Behaviors

- **Status Polling JSON:** The `error` field in `/status.json` must return `None` (resulting in JSON `null`) if no error is present. The Rust client parses this field as `Option<String>`, and surfacing the actual API response via `.as_deref().unwrap_or(...)` prevents silent failure masking.
- **Frontend DOM Diffing:** `index.js` leverages HTML `dataset` attributes (`data.prompt`, `data.type`, `data.options`) on the dynamic input container. Elements are compared against stringified array structures `JSON.stringify()` to ensure they are only fully rebuilt when types or options fundamentally change; otherwise, only text labels are updated.
- **Frontend Network Resilience:** All UI actions that invoke API endpoints (`triggerConnect`, `handleFormSubmit`, etc.) must be wrapped in `try/catch/finally` blocks to ensure the frontend polling loop (`resetPoll`) resurrects if a network exception occurs. This prevents the UI from becoming permanently locked in a 'loading' state.
- **Rust Connection Pooling:** The Host Agent must utilize a single, globally instantiated `ureq::Agent` for standard connections and a separate fast `ureq::Agent` for status polling. Do not instantiate new HTTP agents inside loops, as this discards TCP connection pooling and exhausts system ports.
- **Frontend State Deadlock Prevention:** Generating new SSO links briefly toggles an `isRestarting` safety flag to suspend polling jitter. In addition, 401 exceptions forcefully command `resetPoll(5000)` to ensure background loop resurrection upon credential fixing.
- **Agent HTTP Timeouts (Rust):** The Host Agent utilizes two specialized timeout profiles. Routine requests (connect, disconnect, submit) use a standard 10-second agent. Status polling utilizes a localized 2-second fast agent (`get_fast_agent`).
- **Process Orchestration:** When destroying VPN tunnels, `server.py`'s `_kill_and_poll` uses `pgrep` in a blocking loop to definitively verify that `gpclient` and `gpservice` have exited before reinitializing logic. If processes refuse to terminate gracefully within the polling window, it automatically escalates to a `SIGKILL` (-9) payload to prevent zombie state races.
- **API Security (`SESSION_TOKEN`):** If the backend demands a token, the frontend natively parses `?token=<secret>` strings on application load and injects the generated Bearer Token into all subsequent `fetch` calls.
- **Dynamic SOCKS5 UI Rendering:** The backend dynamically evaluates the presence of `GOST_AUTH` and surfaces a `socks_auth_enabled` boolean in `/status.json`. The frontend must rely exclusively on this flag to update the SOCKS5 Authentication UI text (e.g., "See Env Config" vs "None"), avoiding hardcoded assumptions about the proxy's security state.

## System Optimizations & Guardrails (DO NOT REMOVE)

- **Frontend DOM Diffing Scope:** Query selectors managing the UI state must strictly target exact classes (e.g. `.conn-tab-btn`) rather than raw elements (e.g. `<button>`) to prevent dynamic UI injections from hijacking unrelated states.
- **Strict I/O Caching (`server.py`):** The `StateManager` restricts disk reads for `CLIENT_LOG` by verifying the file's `.stat().st_mtime` and `.st_size`. Doing direct reads on 1-second polling intervals triggers critical CPU/GIL degradation. The file read operation must execute strictly _outside_ the `StateManager` thread lock to prevent serializing concurrent web UI requests. Additionally, the `get_best_ip()` routine caches the outbound local UDP IP string behind a 60-second TTL to avoid exhausting host system sockets during high-frequency API polling.
- **IPC Execution (`entrypoint.sh`):** Control endpoints rely on OS-agnostic local TCP sockets (`127.0.0.1:32801`, `127.0.0.1:32802`) instead of POSIX FIFOs to guarantee out-of-container testing compatibility on Windows. The listener endpoints (`control_listener.py` and `stdin_proxy.py`) must utilize a non-blocking `select.select` wait approach inside a `while True` loop to act as persistent daemons capable of receiving graceful interrupt signals.
- **IPC Payload Sanitization:** All HTTP `/submit` parameters mapped into IPC streams MUST be rigorously sanitized for internal newline injections (`\r`, `\n`) prior to socket dispatch. Unfiltered payloads permit arbitrary shell interaction escapes.
- **Shell Injection Boundaries:** `eval` is utilized in `entrypoint.sh` strictly to parse quoted string flags passed dynamically via the `GP_ARGS` environment variable. This constitutes a trust boundary; the operator is responsible for sanitizing `GP_ARGS` at the orchestrator level.
- **Cache Invalidation:** `server.py` injects MD5 cache-busting query strings directly into `index.html` at runtime. CSS and JS headers must be left as `immutable` to preserve bandwidth, as the injected hash implicitly guarantees cache breaking on new container releases.

## Handling Callbacks (`globalprotect://`)

The SAML flow often ends with a redirect to `globalprotect://...`.

1.  **Browser Redirect:** The IDP redirects the browser to the custom protocol.
2.  **OS Trigger:** The OS spawns `gp-client-proxy globalprotect://...`.
3.  **Forwarding:** The Rust binary reads its config (`proxy_url.txt`), connects to the Docker container IP, injects the Bearer authorization header, and POSTs the payload to `/submit`.
4.  **Processing:** `server.py` receives the payload and dispatches it over the local TCP socket `127.0.0.1:32802`.
5.  **Execution:** The `stdin_proxy.py` daemon receives the socket buffer and writes it directly to the running `gpclient` standard input to complete the handshake.

## Future Improvements

- **Automated Callback:** Requires an embedded browser extension or custom handler to POST the callback to `localhost:8001/submit` automatically, removing the need for protocol handlers.
