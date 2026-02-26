<!-- File: AGENTS.md -->

# Agent Context: GP Proxy & Client

## Project Overview

This project encapsulates a GP-compatible VPN client inside a Docker container, exposing it via various proxy protocols (`gost`) and/or a Transparent Gateway. It utilizes a "Split-Agent" architecture where a secure **Container Agent** handles the networking/VPN and a **Host Agent** (Desktop App) handles the SSO authentication flow and management.

## Development Standards (Crucial)

**Strict linting and formatting are enforced via CI and Pre-commit hooks.** Any code changes must adhere to these standards to pass the `lint` workflow.

- **Python:** Uses `ruff` for formatting (line length 120) and linting. **Strict typing (Mypy/Pyright) is required.** The project uses Python 3.14.
    - Do not use subscripted generics for `socket.socket` as `typeshed` strictness will reject type arguments like `[Any, Any]`.
    - Overriding class attributes must utilize `typing.ClassVar` to satisfy strict Pyright/Mypy checks.
    - Discarded process standard outputs (`stdout=subprocess.DEVNULL`) must be typed strictly as `CompletedProcess[bytes]`. To satisfy this under strict Mypy checks without discarding typing, use `capture_output=True` when polling processes.
    - **Exception Syntax Constraint:** Multi-target exceptions must strictly utilize the Python 3 tuple syntax `except (ValueError, KeyError, TypeError):`. The comma-separated Python 2 syntax will invoke an immediate container-crashing `SyntaxError`. **If the `ruff format` pre-commit hook aggressively strips these required parentheses, you must apply a `# fmt: skip` suppression comment directly at the end of the line being stripped to lock the syntax and pass `mypy` checks.**
    - **Network Resilience:** Socket loops utilizing `.settimeout()` must explicitly catch `(OSError, TimeoutError)` tuples to prevent ungraceful daemon crashes during dead client timeouts.
    - All module-level files must include descriptive docstrings.
- **Rust:** Uses `clippy` (warnings as errors) and `rustfmt`. No unused code or fields allowed. CLI outputs must be professional (no emojis; use text brackets like `[SUCCESS]`, `[ERROR]`).
- **Shell:** Uses `shellcheck` (gcc format). **Do not use `xargs` to trim strings, as it silently collapses internal whitespace.** Rely exclusively on native bash parameter expansion or `sed` for sanitization.
- **Formatting:** Uses `prettier` for Markdown, YAML, HTML, and JSON.
- **YAML:** Uses `yamllint` (relaxed mode, max 120 chars).
- **Docker:** Uses `hadolint` (ignores DL3008). Multi-arch support should be handled via dynamic arguments like `TARGETARCH` when downloading specific binaries.

## Architecture

The system uses a **"Three-Tier" architecture** to bridge the gap between a headless container and a desktop GUI login flow.

### 1. The Container Agent (The Brain)

**Location:** Inside Docker (`backend/`, `entrypoint.sh`)
**Role:** State Management & Networking

- **Source Code Isolation:** Python backend scripts (`server.py`, `control_listener.py`, `stdin_proxy.py`, `utils.py`) reside in the `backend/` directory during development and are deployed to `/opt/gp-proxy/`. They MUST NOT reside in the `/var/www/html/` web root. To prevent accidental source code exposure, the backend `server.py` initializes by strictly verifying the presence of target web directories (`/var/www/html` or local `web/`). It will exit immediately with a fatal error rather than fallback to the repository root. Dockerfile permissions explicitly lock `chmod +x` to entrypoint files (`server.py`, `control_listener.py`, `stdin_proxy.py`) to prevent library modules from executing.
- **Timing-Safe Authentication:** Any token comparison logic (such as checking `API_TOKEN` in HTTP headers) must strictly utilize `hmac.compare_digest()` to prevent timing attacks.
- **Web Server (`server.py`):**
    - Runs on Port 8001. Fallback default log level is strictly `INFO`.
    - **State Management:** Uses a thread-safe `StateManager` to handle concurrent access from the log analyzer and HTTP requests.
    - Parses logs (`gp-client.log`) to determine state (Idle, Connecting, Auth, Input, Connected, Error).
    - Exposes API endpoints: `/status.json` (polled), `/connect`, `/disconnect`, `/api/pair`, and `/submit`.
    - **Configurable Zero-Touch Security:** The server employs a decoupled authentication model:
        1. **Web GUI (Ephemeral Token):** To eliminate manual passwords for the local dashboard, the Python server generates an `EPHEMERAL_TOKEN` on startup and permanently injects it into a meta tag inside `index.html`. The frontend JavaScript automatically extracts this token and attaches it to its API `Authorization: Bearer <token>` requests.
        2. **Host Agent (Ed25519 TOFU Pairing):** External clients achieve "Perfect Security" without user input by utilizing Trust On First Use (TOFU). The client automatically issues an unauthenticated `POST /api/pair` containing a Base64 Ed25519 Public Key. The server stores this key in memory and rejects future pairing attempts. All subsequent commands from the client must include an `X-Signature` header (signing `"{timestamp}:{path}"`) and an `X-Timestamp` header. The server verifies this signature to permit access.
        3. **Manual Lockdown (`API_TOKEN`):** An operator can explicitly export `API_TOKEN` via Docker environments. When set, this completely disables the TOFU pairing mechanism and acts as a legacy override, requiring external clients to pass the static token via the Bearer header.
    - **UDP Beacon:** Listens on UDP port 32800 to auto-respond to discovery broadcasts from the Host Agent. The UDP Beacon broadcasts the container IP and Port to the Host Agent. For security against LAN sniffing, credentials are intentionally omitted from the broadcast payload.

### 2. The Host Agent (The Manager)

**Location:** User's Desktop (`apps/gp-client-proxy`)
**Role:** User Interface & Bridge
**Language:** Rust

This is a cross-platform binary (`gp-client-proxy`) that operates in two modes:

1.  **Dashboard Mode (Interactive):**
    - Launches when the user runs the executable.
    - **Auto-Discovery & Pairing:** Broadcasts `GP_DISCOVER` on UDP 32800 to find the container IP automatically. On first run, it generates an Ed25519 keypair and issues `POST /api/pair` to securely lock the container identity. For subsequent queries, it signs a Unix timestamp and the URL path (e.g. `1710000000:/status.json`) and passes `X-Signature` and `X-Timestamp` HTTP headers to authorize itself.
    - **Management:** Displays real-time status (polled from `status.json`) and allows Connect/Disconnect actions.
    - **Browser Launch:** Automatically opens the system default browser to the Auth URL when required.
    - **Connection Info:** Displays the calculated Gateway IP and proxy ports when connected.
2.  **Handler Mode (Background):**
    - Triggered by the OS when a `globalprotect://` link is clicked.
    - Captures the callback URL.
    - Forwards the URL to the Container Agent via `POST /submit` (using its Ed25519 signed headers).
    - Exits immediately (fire-and-forget).

### 3. The Browser (The Auth Provider)

**Role:** SSO/SAML Execution

- The user authenticates (Okta, Microsoft, etc.) in their native browser.
- The portal redirects to `globalprotect://...`, handing control back to the Host Agent.

## Network Modes (`VPN_MODE` & `PROXY_MODE`)

The application supports simultaneous proxy and gateway topologies. Configure the overarching network stance via the `VPN_MODE` variable:

- **`standard`:** Starts proxy handler(s) AND configures `iptables` for NAT/IP Forwarding (Gateway). Best for general use.
- **`proxy`:** Starts proxy handler(s) ONLY. Explicitly disables IP Forwarding and NAT. Locked down.
- **`gateway`:** Configures NAT/IP Forwarding ONLY. No proxy listeners. Requires `macvlan` network driver.

When the mode is set to `standard` or `proxy`, you can configure exactly which proxy endpoints are active simultaneously via the `PROXY_MODE` environment variable. Provide a comma-separated list of values (e.g. `socks5,http,https,socks4`).

- **`socks5`:** Standard UDP/TCP SOCKS5 proxy on Port 1080.
- **`socks4`:** Standard TCP SOCKS4 proxy on Port 1084.
- **`http`:** Standard HTTP proxy on Port 8080.
- **`https`:** TLS-encrypted proxy on Port 8443. Auto-generates a local certificate.

## Advanced Networking: Smart Split-Tunneling

The container features a "Smart Detection Engine" that automatically implements split-tunneling and split-DNS by analyzing the connection payloads from the GlobalProtect server.

To isolate corporate VPN traffic from standard local internet traffic, you only need to provide a single environment variable:

- **`SPLIT_TUNNEL=true`**: When enabled, the container automatically strips the default `0.0.0.0/0` internet route pushed by the VPN. It then dynamically reads the DNS servers, Split-Include Subnets, and Split-DNS Domains from the OpenConnect environment. It configures an internal `dnsmasq` instance to route corporate domains to the VPN DNS, and uses dynamic `ipset` routing to transparently forward traffic for those resolved addresses through the tunnel. All other traffic (like personal domains or standard internet) remains safely on your local network.

_(Note: Advanced power users can still optionally declare `VPN_DOMAINS`, `LOCAL_DNS`, or `VPN_SUBNETS` to forcefully inject custom overrides into the smart detection tables)._

## Key Files

### Container (Server)

- **`entrypoint.sh`:** Orchestrator. Handles `VPN_MODE`, `PROXY_MODE`, `GOST_AUTH`, `ALLOWED_SUBNETS`, `SPLIT_TUNNEL` watchdog logic, cleanup traps, builds cross-platform Python IPC listener endpoints, and invokes `gpclient`. Strict globbing rejections are enforced on environment parameters. It injects a smart `vpnc-script` wrapper to process GlobalProtect payloads dynamically.
- **`backend/server.py`:** Python Control Server. Handles Trust-On-First-Use (TOFU) Ed25519 pairing, dynamic HTML cache busting, and ephemeral UI token injection. Control endpoints rely on OS-agnostic local TCP sockets (`IPC_CONTROL_PORT` and `IPC_STDIN_PORT`). Process lifecycle management dynamically delegates (`sys.platform == "win32"`) to explicit OS handlers, enabling native Windows development while securely isolating Unix orchestration constraints.
- **`backend/utils.py`:** Shared Python utility library. Centralizes cross-process configuration constants (`IPC_CONTROL_PORT`, `IPC_STDIN_PORT`), normalizes the execution environment paths (`CLIENT_LOG`, `SERVICE_LOG`), standardizes the `logging` format outputs across all background daemons, and contains the cross-platform TCP socket transmission logic (`send_ipc_message`).
- **`web/index.html` / `web/index.js` / `web/index.css`:** Frontend assets. Separated for maintainability and Docker layer caching. The server dynamically rewrites the `<meta name="session-token">` tag in `index.html` on startup so the JS layer automatically picks up authorized access. The UI uses strict DOM diffing against a JSON array to natively support concurrent multi-proxy rendering.

### Host (Client)

- **`apps/gp-client-proxy/src/main.rs`:** The Rust source code.
    - Uses `ureq` (3.x) for HTTP requests (`send_empty`, `read_json`).
    - Uses `serde` for JSON parsing.
    - Uses `webbrowser` to launch the Auth page.
    - Implements the "Manager" TUI (Text User Interface) and Ed25519 TOFU pairing logic.
- **`apps/gp-client-proxy/Cargo.toml`:** Dependency definitions.

## Critical Implementation Details & Behaviors

- **Status Polling JSON:** The `error` field in `/status.json` must return `None` (resulting in JSON `null`) if no error is present. The Rust client parses this field as `Option<String>`, and surfacing the actual API response via `.as_deref().unwrap_or(...)` prevents silent failure masking.
- **Frontend Error State Recovery:** Handlers rendering `data.error` payloads to the screen must actively wipe the DOM content (e.g., `el.innerText = data.error || ""`) when an error resolves to `null`. Omitting the fallback leaves stale error text permanently ghosted on the GUI.
- **Frontend DOM Diffing:** `index.js` leverages HTML `dataset` attributes (`data.prompt`, `data.type`, `data.options`) on the dynamic input container. Elements are compared against stringified array structures `JSON.stringify()` to ensure they are only rebuilt when types or options fundamentally change; otherwise, only text labels are updated.
- **Frontend Network Resilience:** All UI actions that invoke API endpoints (`triggerConnect`, `handleFormSubmit`, etc.) must be wrapped in `try/catch/finally` blocks to ensure the frontend polling loop (`resetPoll`) resurrects if a network exception occurs. This prevents the UI from becoming permanently locked in a 'loading' state.
- **Rust Connection Pooling:** The Host Agent must utilize a single, globally instantiated `ureq::Agent` for standard connections and a separate fast `ureq::Agent` for status polling. Do not instantiate new HTTP agents inside loops, as this discards TCP connection pooling and exhausts system ports.
- **Frontend State Deadlock Prevention:** Generating new SSO links briefly toggles an `isRestarting` safety flag to suspend polling jitter. In addition, 401 exceptions forcefully command `window.location.reload()` to ensure background loop resurrection and ephemeral token extraction upon credential fixing.
- **Agent HTTP Timeouts (Rust):** The Host Agent utilizes two specialized timeout profiles. Routine requests (connect, disconnect, submit) use a standard 10-second agent. Status polling utilizes a localized 2-second fast agent (`get_fast_agent`).
- **Process Orchestration:** When destroying VPN tunnels, `server.py`'s `_kill_and_poll_unix()` dynamically determines container privileges by directly injecting `sudo -n` to invoke `pkill -x` and `pgrep -x` safely. It relies on a blocking loop alongside `subprocess.run(..., capture_output=True)` to natively return byte streams that satisfy strict Mypy types, verifying that processes have exited before reinitializing logic. If processes refuse to terminate gracefully within the polling window, it automatically escalates to a `SIGKILL` (-9) payload to prevent zombie state races. It specifically unblocks bash pipelines by killing the unprivileged `stdin_proxy.py` daemon directly, bypassing `sudo`.
- **Dynamic Proxy UI Rendering:** The backend dynamically evaluates the configured proxies and network boundaries, surfaceing them as JSON arrays (`proxy_modes`). The frontend strictly relies on array matching (`ALL_TABS.includes()`) and DOM class toggling (`hidden-mode`) to safely control layout scaling and proxy info display.

## System Optimizations & Guardrails (DO NOT REMOVE)

- **Frontend DOM Diffing Scope:** Query selectors managing the UI state must strictly target exact classes (e.g. `.conn-tab-btn`) rather than raw elements (e.g. `<button>`) to prevent dynamic UI injections from hijacking unrelated states. Elements managed dynamically (like `btn`) must employ optional chaining (`?.classList`) to prevent crashes during conditional rendering.
- **Strict I/O Caching (`server.py`):** The `StateManager` restricts disk reads for `CLIENT_LOG` by verifying the file's `.stat().st_mtime` and `.st_size`. Doing direct reads on 1-second polling intervals triggers critical CPU/GIL degradation. The file read operation must execute strictly _outside_ the `StateManager` thread lock to prevent serializing concurrent web UI requests. Additionally, the `get_best_ip()` routine caches the outbound local UDP IP string behind a 60-second TTL to avoid exhausting host system sockets during high-frequency API polling.
- **IPC Execution (`entrypoint.sh`):** Control endpoints rely on OS-agnostic local TCP sockets (`127.0.0.1:32801`, `127.0.0.1:32802`) instead of POSIX FIFOs to guarantee out-of-container testing compatibility on Windows. The listener endpoints (`control_listener.py` and `stdin_proxy.py`) must utilize a non-blocking `select.select` wait approach inside a `while True` loop to act as persistent daemons capable of receiving graceful interrupt signals. IPC byte streams must be buffered and split strictly on newlines (`\n`) prior to UTF-8 decoding to prevent multi-byte characters from being mangled across TCP chunk boundaries.
- **IPC Payload Sanitization:** All HTTP `/submit` parameters mapped into IPC streams MUST be rigorously sanitized for internal newline injections (`\r`, `\n`) prior to socket dispatch. Unfiltered payloads permit arbitrary shell interaction escapes. Handlers must strictly filter standard HTTP errors (`ValueError`, `KeyError`, `TypeError`) before catching generic `Exception` objects to avoid masking underlying API implementation issues in `500` HTTP blocks.
- **Shell Injection Boundaries:** `eval` is utilized in `entrypoint.sh` strictly to parse quoted string flags passed dynamically via the `GP_ARGS` environment variable. This constitutes a trust boundary; the operator is responsible for sanitizing `GP_ARGS` at the orchestrator level. Safe interpolation is protected via evaluated environment variables (`$BASH_NL`).
- **System Privileges:** Sudoers permissions inside the Dockerfile strictly utilize `Cmnd_Alias` to lock down `/usr/bin/pkill` and `/usr/bin/pgrep` to precise `gpclient` and `gpservice` arguments, preventing arbitrary process termination or systemic container disruption.
- **Atomic API State:** The nil-check (`_paired_pubkey is None`) **and** the assignment to `_paired_pubkey` must occur inside a single `with _pairing_lock:` acquisition. Splitting the guard across lock boundaries reopens the TOCTOU race this lock is intended to prevent. Reject any pairing request if `_paired_pubkey` is already set within the same critical section.
- **TOFU Lifecycle & Restarts:** The Container Agent stores `_paired_pubkey` strictly in memory. If the container restarts, the key is lost, and the Host Agent will receive `401 Unauthorized` errors. This is a known limitation. To recover, the user must re-run the Host Agent setup wizard to wipe the local keypair and re-issue `POST /api/pair`.
- **Idempotent Token Injection:** Operations that dynamically modify `index.html` on boot (like rewriting the `session-token` meta tag content) MUST use `re.sub` regex patterns rather than standard string `.replace()`. The payload must be idempotent, matching against previous tokens, to guarantee the file is successfully updated after container restarts.
- **Deterministic Fallbacks:** When generating cache-busting `build_hash` identifiers, avoid stochastic elements like `time.time()`. If primary asset byte evaluation fails, fallback identifiers must remain deterministic to preserve immutable cache semantics across application restarts.
- **URL Normalization & Cryptography:** Base URLs persisted in the Host Agent configuration must have trailing slashes aggressively trimmed `.trim_end_matches('/')` during serialization and deserialization. Failing to sanitize this produces `//` paths that break Ed25519 signature validation.
- **Keystore Privileges:** Any Rust logic writing long-lived secret materials (like `private_key` fields) to disk MUST explicitly lock down filesystem privileges (e.g. `0o600` on UNIX). Do not rely on default OS masks.

## Handling Callbacks (`globalprotect://`)

The SAML flow often ends with a redirect to `globalprotect://...`.

1.  **Browser Redirect:** The IDP redirects the browser to the custom protocol.
2.  **OS Trigger:** The OS spawns `gp-client-proxy globalprotect://...`.
3.  **Forwarding:** The Rust binary connects to the Docker container IP, generates its Ed25519 authorization signature blocks, and POSTs the callback string payload to `/submit`.
4.  **Processing:** `server.py` verifies the Ed25519 signature, unpacks the payload, and dispatches it over the local TCP socket `127.0.0.1:32802`.
5.  **Execution:** The `stdin_proxy.py` daemon receives the socket buffer and writes it directly to the running `gpclient` standard input to complete the handshake.

## Future Improvements

- **Automated Callback:** Requires an embedded browser extension or custom handler to POST the callback to `localhost:8001/submit` automatically, removing the need for protocol handlers.
