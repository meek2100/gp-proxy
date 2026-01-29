<!-- File: AGENTS.md -->

# Agent Context: GP Proxy & Client

## Project Overview

This project encapsulates a GP-compatible VPN client inside a Docker container, exposing it via a SOCKS5 proxy (`microsocks`) on port 1080 and a Transparent Gateway. It utilizes a "Split-Agent" architecture where a secure **Container Agent** handles the networking/VPN and a **Host Agent** (Desktop App) handles the SSO authentication flow and management.

## Development Standards (Crucial)

**Strict linting and formatting are enforced via CI and Pre-commit hooks.** Any code changes must adhere to these standards to pass the `lint` workflow.

- **Python:** Uses `ruff` for formatting (line length 120) and linting. **Strict typing (Mypy/Pyright) is required.** The project uses Python 3.14.
- **Rust:** Uses `clippy` (warnings as errors) and `rustfmt`. No unused code or fields allowed.
- **Shell:** Uses `shellcheck` (gcc format).
- **Formatting:** Uses `prettier` for Markdown, YAML, HTML, and JSON.
- **YAML:** Uses `yamllint` (relaxed mode, max 120 chars).
- **Docker:** Uses `hadolint` (ignores DL3008).

## Architecture

The system uses a **"Three-Tier" architecture** to bridge the gap between a headless container and a desktop GUI login flow.

### 1. The Container Agent (The Brain)

**Location:** Inside Docker (`server.py`, `entrypoint.sh`)
**Role:** State Management & Networking

- **Web Server (`server.py`):**
    - Runs on Port 8001.
    - Parses logs (`gp-client.log`) to determine state (Idle, Connecting, Auth, Input, Connected, Error).
    - Exposes API endpoints: `/status.json` (polled), `/connect`, `/disconnect`, and `/submit` (auth tokens).
    - **UDP Beacon:** Listens on UDP port 32800 to auto-respond to discovery broadcasts from the Host Agent.
- **Orchestrator (`entrypoint.sh`):**
    - Manages `iptables` for NAT/Forwarding.
    - Monitors the `gpclient` process.
    - Runs a "DNS Watchdog" to update `/etc/resolv.conf` dynamically when the VPN pushes new DNS servers.

### 2. The Host Agent (The Manager)

**Location:** User's Desktop (`apps/gp-client-proxy`)
**Role:** User Interface & Bridge
**Language:** Rust

This is a cross-platform binary (`gp-client-proxy`) that operates in two modes:

1.  **Dashboard Mode (Interactive):**
    - Launches when the user runs the executable.
    - **Auto-Discovery:** Broadcasts `GP_DISCOVER` on UDP 32800 to find the container IP automatically.
    - **Management:** Displays real-time status (polled from `status.json`) and allows Connect/Disconnect actions.
    - **Browser Launch:** Automatically opens the system default browser to the Auth URL when required.
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

- **`standard`:** Starts `microsocks` (port 1080) AND configures `iptables` for NAT/IP Forwarding. Best for general use.
- **`socks`:** Starts `microsocks` ONLY. Disables IP Forwarding and NAT. Locked down.
- **`gateway`:** Configures NAT/IP Forwarding ONLY. No SOCKS proxy. Requires `macvlan` network driver.

## Key Files

### Container (Server)

- **`entrypoint.sh`:** Orchestrator. Handles `VPN_MODE`, DNS Watchdog, cleanup traps, and invokes `gpclient`.
- **`server.py`:** Python Control Server. Handles `LOG_LEVEL` parsing, log analysis regex, ANSI stripping, and UDP Beacon.
- **`index.html`:** Frontend. Supports **Dark Mode** (auto/toggle), dynamic form generation, and "Restart Auth" lock to prevent UI flickering.

### Host (Client)

- **`apps/gp-client-proxy/src/main.rs`:** The Rust source code.
    - Uses `ureq` (3.x) for HTTP requests (`send_empty`, `read_json`).
    - Uses `serde` for JSON parsing.
    - Uses `webbrowser` to launch the auth page.
    - Implements the "Manager" TUI (Text User Interface).
- **`apps/gp-client-proxy/Cargo.toml`:** Dependency definitions.

## Handling Callbacks (`globalprotect://`)

The SAML flow often ends with a redirect to `globalprotect://...`.

1.  **Browser Redirect:** The IDP redirects the browser to the custom protocol.
2.  **OS Trigger:** The OS spawns `gp-client-proxy globalprotect://...`.
3.  **Forwarding:** The Rust binary reads its config (`proxy_url.txt`), connects to the Docker container IP, and POSTs the payload to `/submit`.
4.  **Processing:** `server.py` receives the payload and writes it to the named pipe `/tmp/gp-stdin`.
5.  **Execution:** The running `gpclient` process reads the pipe and completes the handshake.

## Future Improvements

- **Frontend:** Ensure `index.html` has **zero external dependencies** (inline CSS/JS) for strict LAN-only deployments.
- **Security:** Implement an optional Pre-Shared Key (PSK) or Token between the Host Agent and Container Agent to prevent unauthorized control on shared LANs.
- **Automated Callback:** Requires an embedded browser extension or custom handler to POST the callback to `localhost:8001/submit` automatically
- **SOCKS5 Authentication:** Implement an optional SOCKS5 authentication method to prevent unauthorized access to the proxy.
- **Gateway Protection:** Implement an optional Gateway Protection method to prevent unauthorized access to the proxy.
