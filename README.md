<!-- File: README.md -->

# GP Proxy & Client

A Dockerized VPN client that provides **multiple proxy protocols** (SOCKS5, SOCKS4/4a, HTTP/S, Shadowsocks) and a **Transparent Gateway** for GP-compatible VPNs. It features a modern Web UI, SSO (SAML) authentication support, and a cross-platform desktop companion app (`gp-client-proxy`) to manage connections seamlessly.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Docker](https://img.shields.io/badge/docker-build-blue)
![Rust](https://img.shields.io/badge/built%20with-Rust-orange)

## 🚀 Features

- **Full SSO Support:** Works with MFA/2FA and SAML authentication (Okta, Microsoft Entra ID, etc.).
- **Two Operation Modes:**
    - **Multiple Proxy Protocols:** Simultaneously run SOCKS5 (1080), SOCKS4 (1084), SOCKS4a (1085), HTTP (8080), HTTPS (8443), and Shadowsocks (8388) via the `PROXY_MODE` variable.
    - **Transparent Gateway:** Route entire devices (AppleTV, PlayStation, etc.) through the VPN by setting their Gateway IP.
- **Desktop Companion App:** A Rust-based CLI dashboard (`gp-client-proxy`) for Windows, Linux, and macOS that handles protocol links and manages connection state.
- **Web Dashboard:** A responsive web UI to view status, logs, and connection details.
- **Auto-Reconnect:** Built-in watchdog ensures the connection stays alive.

---

## 🛠️ Quick Start

Create a `docker-compose.yml` and configure your VPN Portal.

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
            - SPLIT_TUNNEL=true
            - LOCAL_SUBNETS=192.168.1.0/24 # Bypass VPN for your Home LAN
            - PROXY_MODE=socks5,socks4,socks4a,http,https,ss
            - PROXY_AUTH=user:password
            - SS_AUTH=aes-256-gcm:password
            - API_TOKEN=your-api-token
            - LOG_LEVEL=INFO
            - LOCAL_DOMAINS=local
            - VPN_DOMAINS=vpn.yourcompany.com
            - VPN_SUBNETS=10.0.0.0/8
            - VPN_MODE=standard
        ports:
            - "8001:8001" # Web Dashboard
            - "32800:32800/udp" # UDP Beacon
            - "1080:1080" # SOCKS5
            - "1084:1084" # SOCKS4
            - "1085:1085" # SOCKS4a
            - "8080:8080" # HTTP
            - "8443:8443" # HTTPS
            - "8388:8388" # Shadowsocks TCP
            - "8388:8388/udp" # Shadowsocks UDP
```

Run the container:

```bash
docker-compose up -d
```

### 1. Set Up the Desktop Client

To handle SSO logins (which require a browser), download the **GP Client Proxy** binary for your OS from the [Releases Page](https://github.com/meek2100/gp-proxy/releases).

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
SERVER:    Online (http://192.168.1.50:8001)
STATUS:    CONNECTED
MODE:      STANDARD

[i] CONNECTION DETAILS
SOCKS5 Proxy:  192.168.1.50:1080 (No Auth)
Gateway IP:    192.168.1.50
DNS Server:    192.168.1.50
----------------------------------------
1. Open Web Dashboard (Browser)
2. Disconnect VPN
3. Re-run Setup / Discovery
4. Uninstall
R. Restart Authentication (Generate New Link)
5. Exit
```

### Environment Variables (Docker)

| Variable        | Description                                                                        | Default    |
| :-------------- | :--------------------------------------------------------------------------------- | :--------- |
| `VPN_PORTAL`    | **Required.** The URL of your VPN portal.                                          | `None`     |
| `VPN_MODE`      | `standard` (Proxy+Gateway), `proxy` (proxy only), or `gateway` (transparent only). | `standard` |
| `PROXY_MODE`    | Comma-separated: `socks5,socks4,socks4a,http,https,ss`.                            | `socks5`   |
| `SPLIT_TUNNEL`  | `true` enables Smart Split-Tunneling.                                              | `false`    |
| `PROXY_AUTH`    | Basic proxy auth `user:password`.                                                  | `None`     |
| `SS_AUTH`       | Shadowsocks auth `cipher:password`.                                                | Auto       |
| `API_TOKEN`     | Static token to lock down the API.                                                 | `None`     |
| `LOG_LEVEL`     | Logging verbosity (`INFO`, `DEBUG`).                                               | `INFO`     |
| `LOCAL_SUBNETS` | Comma-separated CIDRs to bypass the VPN (e.g. `192.168.1.0/24`).                   | `None`     |
| `LOCAL_DOMAINS` | Comma-separated domains to resolve via LAN DNS (e.g. `local`).                     | `None`     |
| `LOCAL_DNS`     | Primary LAN DNS server for fallback.                                               | Auto       |
| `VPN_DOMAINS`   | Forceful injection of domains into the VPN tunnel.                                 | Auto       |
| `VPN_SUBNETS`   | Forceful injection of CIDRs into the VPN tunnel.                                   | Auto       |

---

## 🔒 Security Considerations

**Security Model:**
The Desktop Companion App (`gp-client-proxy`) uses a **Trust On First Use (TOFU)** Ed25519 keypair to authenticate with the container — no static passwords or plaintext tokens are ever stored.

- **On first run**, the app generates an Ed25519 keypair and issues a one-time `POST /api/pair` to register the public key with the container.
- **On all subsequent requests**, the app signs `"{timestamp}:{path}"` with its private key and attaches `X-Signature` and `X-Timestamp` headers.
- The private key is stored on disk with **`0600` permissions** inside:
    - **Windows:** `%APPDATA%\gpproxy\client\`
    - **macOS:** `~/Library/Application Support/com.gpproxy.client/`
    - **Linux:** `~/.config/gpproxy/client/`

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

---

## 🧩 Agent Architecture

The GP Proxy system consists of two primary "Agents" working in tandem: the **Container Agent** (running inside Docker) and the **Host Agent** (running on your desktop).

### 1. The Container Agent (Server)

**Role:** The Core Engine.
This agent runs inside the Docker container and is responsible for maintaining the actual VPN connection and routing traffic.

- **Components:**
    - `entrypoint.sh`: The supervisor. Manages network interfaces, proxies, and process health.
    - `server.py`: Python-based HTTP control server (Port 8001).
    - `gpclient`: Underlying OpenConnect wrapper.
- **Responsibilities:**
    - Maintains the tunnel interface and NAT.
    - Implements "Shadow Route" logic for Bridge mode compatibility.

### 2. The Host Agent (GP Client Proxy)

**Role:** The Bridge & Controller.
This is the cross-platform Rust binary (`gp-client-proxy`) that runs on the user's physical machine.

- **Modes of Operation:**
    1. **Manager Dashboard (Interactive):** Displays real-time status and allows user control.
    2. **Protocol Handler (Background):** Registered to handle `globalprotect://` links and forward tokens.

## Communication Flow

1. **User** clicks "Connect" in the Host Agent.
2. **Host Agent** calls `POST /connect` on the Container.
3. **Host Agent** checks for the SAML Auth URL via `GET /status.json`.
4. **Host Agent** opens the default browser to this URL.
5. **User** logs in via SSO.
6. **Browser** redirects to `globalprotect://callback/...`
7. **OS** launches **Host Agent** (Handler Mode).
8. **Host Agent** forwards the callback URL to the **Container**.
9. **Container** completes the handshake and establishes the tunnel.
