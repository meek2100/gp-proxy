<!-- File: README.md -->

# GP Proxy & Client

A Dockerized VPN client that provides a **SOCKS5 proxy** and a **Transparent Gateway** for GP-compatible VPNs. It features a modern Web UI, SSO (SAML) authentication support, and a cross-platform desktop companion app (`gp-client-proxy`) to manage connections seamlessly.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Docker](https://img.shields.io/badge/docker-build-blue)
![Rust](https://img.shields.io/badge/built%20with-Rust-orange)

## 🚀 Features

- **Full SSO Support:** Works with MFA/2FA and SAML authentication (Okta, Microsoft Entra ID, etc.).
- **Two Operation Modes:**
    - **SOCKS5 Proxy:** Route specific apps' traffic through the VPN (Port 1080).
    - **Transparent Gateway:** Route entire devices (AppleTV, PlayStation, etc.) through the VPN by setting their Gateway IP.
- **Desktop Companion App:** A Rust-based CLI dashboard (`gp-client-proxy`) for Windows, Linux, and macOS that handles protocol links and manages connection state.
- **Web Dashboard:** A responsive web UI to view status, logs, and connection details.
- **Auto-Reconnect:** Built-in watchdog ensures the connection stays alive.

---

## 🛠️ Quick Start

### 1. Start the Server (Docker)

Create a `docker-compose.yml` (or use the one provided) and configure your VPN Portal URL.

```yaml
services:
    gp-proxy:
        image: ghcr.io/meek2100/global-protect-proxy:latest
        container_name: gp-proxy
        restart: unless-stopped
        cap_add:
            - NET_ADMIN
        devices:
            - /dev/net/tun
        environment:
            - VPN_PORTAL=vpn.yourcompany.com
            - TZ=America/Los_Angeles
        # Gateway Mode requires a macvlan or host network to expose a routable IP
        networks:
            vpn_net:
                ipv4_address: 192.168.1.50

networks:
    vpn_net:
        driver: macvlan
        driver_opts:
            parent: eth0
        ipam:
            config:
                - subnet: 192.168.1.0/24
                  gateway: 192.168.1.1
```

Run the container:

```bash
docker-compose up -d

```

### 2. Set Up the Desktop Client

To handle SSO logins (which require a browser), download the **GP Client Proxy** binary for your OS from the [Releases Page](https://www.google.com/search?q=%23).

1. **Run the Application:**

- **Windows:** Double-click `gp-client-proxy.exe`.
- **Linux/macOS:** Run `./gp-client-proxy` in your terminal.

2. **Auto-Discovery:**

- The tool will automatically scan your network for the Docker container.
- If found, it saves the configuration and registers itself to handle `globalprotect://` links.

3. **Connect:**

- Select **[2] Connect VPN** from the menu.
- Your default browser will open the Company Login page.
- Once authenticated, the browser passes the token back to the tool, completing the connection.

---

## 🖥️ Usage

### Dashboard Manager

Running `gp-client-proxy` opens the management dashboard in your terminal:

```text
========================================
   GP Client Proxy Manager
========================================
SERVER:    Online ([http://192.168.1.50:8001](http://192.168.1.50:8001))
STATUS:    CONNECTED
MODE:      STANDARD

[!] CONNECTION DETAILS
SOCKS5 Proxy:  192.168.1.50:1080 (No Auth)
Gateway IP:    192.168.1.50
DNS Server:    192.168.1.50
----------------------------------------
1. Open Web Dashboard (Browser)
2. Disconnect VPN
3. Re-run Setup / Discovery
4. Uninstall
5. Exit

```

### Environment Variables (Docker)

| Variable         | Description                                        | Default    |
| ---------------- | -------------------------------------------------- | ---------- |
| `VPN_PORTAL`     | **Required.** The URL of your VPN portal.          | `None`     |
| `VPN_MODE`       | `standard` (Socks+Gateway), `socks`, or `gateway`. | `standard` |
| `VPN_GATEWAY`    | Manually specify a GP Gateway IP (advanced).       | `None`     |
| `VPN_HIP_REPORT` | Enable Host Integrity Protocol (HIP) reporting.    | `false`    |
| `VPN_OS`         | Spoof client OS (`Linux`, `Windows`, `Mac`).       | `Linux`    |
| `LOG_LEVEL`      | Logging verbosity (`INFO`, `DEBUG`, `TRACE`).      | `INFO`     |

---

## 🏗️ Building from Source

**Requirements:**

- Docker
- Rust (Cargo)

**Build Desktop Client:**

```bash
cd apps/gp-client-proxy
cargo build --release

```

**Build Docker Image:**

```bash
docker build -t global-protect-proxy .

```

---

_GlobalProtect is a trademark of Palo Alto Networks. This project is an unofficial open-source client and is not affiliated with, endorsed by, or authorized by Palo Alto Networks._

# Agent Architecture

The GP Proxy system consists of two primary "Agents" working in tandem: the **Container Agent** (running inside Docker) and the **Host Agent** (running on your desktop).

## 1. The Container Agent (Server)

**Role:** The Core Engine.
This agent runs inside the Docker container and is responsible for maintaining the actual VPN connection and routing traffic.

- **Components:**
    - `entrypoint.sh`: The supervisor. It manages network interfaces (`iptables`, `tun0`), starts the SOCKS proxy (`microsocks`), and monitors process health.
    - `server.py`: A Python-based HTTP control server (Port 8001). It serves the Web UI and listens for commands.
    - `gpclient`: The underlying OpenConnect wrapper that speaks the proprietary GP protocol.
- **Responsibilities:**
    - Maintains the tunnel interface.
    - Performs Network Address Translation (NAT) for Gateway mode.
    - Receives authentication tokens via the `/submit` endpoint.

## 2. The Host Agent (GP Client Proxy)

**Role:** The Bridge & Controller.
This is the cross-platform Rust binary (`gp-client-proxy`) that runs on the user's physical machine (Windows/Mac/Linux). It bridges the gap between the secure container and the user's desktop environment.

- **Modes of Operation:**
    1.  **Manager Dashboard (Interactive):**
        - When run by the user, it launches a CLI dashboard.
        - It auto-discovers the Container Agent on the local network via UDP broadcast.
        - It displays real-time connection status and IP configuration details.
        - It allows the user to trigger "Connect" (launching the browser) or "Disconnect".
    2.  **Protocol Handler (Background):**
        - Registered with the OS to handle `globalprotect://` links.
        - When a user authenticates in the browser, the portal redirects to this custom protocol.
        - The OS wakes up a background instance of the agent, which captures the token and instantly forwards it to the Container Agent's `/submit` endpoint via HTTP.

## Communication Flow

1.  **User** clicks "Connect" in the Host Agent (Dashboard).
2.  **Host Agent** calls `POST /connect` on the Container.
3.  **Container** generates a SAML Auth URL and returns it.
4.  **Host Agent** opens the System Default Browser to this URL.
5.  **User** logs in via Okta/Microsoft/etc.
6.  **Browser** redirects to `globalprotect://callback/...`
7.  **OS** launches **Host Agent** (Handler Mode).
8.  **Host Agent** forwards the callback URL to the **Container**.
9.  **Container** completes the handshake and establishes the VPN tunnel.
