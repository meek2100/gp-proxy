# File: backend/server.py
"""
Container Agent - GP Proxy Web Interface and Control Server.

Hosts the primary user-facing web dashboard and API endpoints for managing the VPN lifecycle.
Manages thread-safe log parsing for state detection, enforces Bearer token authentication,
implements Trust On First Use (TOFU) Ed25519 pairing, and orchestrates inter-process communication
(IPC) with the background OpenConnect processes.
"""

import base64
import hashlib
import hmac
import http.server
import json
import logging
import os
import re
import secrets
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, ClassVar, TypedDict

from cryptography.exceptions import InvalidSignature  # pyright: ignore[reportUnknownVariableType]
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,  # pyright: ignore[reportUnknownVariableType]
)
from utils import (
    CLIENT_LOG,
    IPC_CONTROL_PORT,
    IPC_STDIN_PORT,
    RUNTIME_DIR,
    SERVICE_LOG,
    send_ipc_message,
    setup_logger,
)

logger: logging.Logger = setup_logger("server")

# --- Configuration & Security Globals ---
PORT: int = 8001
UDP_BEACON_PORT: int = 32800
MODE_FILE: Path = RUNTIME_DIR / "gp-mode"

# Ephemeral session token for local Web GUI authorization
EPHEMERAL_TOKEN: str = secrets.token_urlsafe(32)

# Paired Trust-On-First-Use (TOFU) Ed25519 Public Key and thread-safe lock
_paired_pubkey: Ed25519PublicKey | None = None
_pairing_lock: threading.Lock = threading.Lock()


# --- Pre-compiled Regex (Optimization) ---
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
GATEWAY_REGEX = re.compile(r"(?:>|\s)*([A-Za-z0-9\-\.]+\s+\([A-Za-z0-9\-\.]+\))")
URL_PATTERN = re.compile(r'(https?://[^\s"<>]+)')


class VPNState(TypedDict):
    """Type definition for the VPN state response sent to the frontend."""

    state: str  # Current connection state (idle, connecting, auth, input, connected, error)
    url: str  # SSO URL for SAML authentication, if required
    prompt: str  # Text prompt for user input (e.g., 'Enter Password')
    input_type: str  # Type of input required (text, password, select)
    options: list[str]  # Dropdown options for 'select' input types
    error: str | None  # Error message if the state is 'error'
    log: str | None  # Recent log lines, only populated if debug_mode is True
    debug_mode: bool  # Whether debug logging is enabled
    vpn_mode: str  # The configured network mode (standard, proxy, gateway)
    proxy_modes: list[str]  # Active proxy types (e.g., ['socks5', 'http'])
    server_ip: str  # The dynamically detected best outbound IP
    proxy_auth_enabled: bool  # Whether Proxy auth is configured


class LogAnalysis(TypedDict):
    """Internal type for the result of log analysis."""

    state: str
    prompt: str
    prompt_type: str
    options: list[str]
    error: str | None
    sso_url: str


# --- State Management (Thread Safety) ---
class StateManager:
    """
    Thread-safe manager for the VPN state.
    Prevents race conditions between the log analyzer thread and HTTP request threads.
    Implements file stat caching to prevent heavy disk I/O on every API poll.
    """

    def __init__(self) -> None:
        """
        Initialize a thread-safe state manager.
        Creates a private lock for synchronizing access, initializes the internal last-state tracker,
        and sets up I/O caching properties including inode tracking to handle rotation replacements.
        """
        self._lock: threading.Lock = threading.Lock()
        self._last_state: str | None = None

        # Caching mechanisms to optimize I/O
        self._log_mtime_ns: int = -1
        self._log_size: int = -1
        self._log_ino: int = -1
        self._cached_analysis: LogAnalysis = {
            "state": "idle",
            "prompt": "",
            "prompt_type": "text",
            "options": [],
            "error": None,
            "sso_url": "",
        }
        self._cached_log: str = ""

    def reset(self) -> None:
        """
        Forcefully flushes the internal cache to eliminate state-flapping race conditions
        where the UI could read an old log representation momentarily during reconnects.
        """
        with self._lock:
            self._log_mtime_ns = -1
            self._log_size = -1
            self._log_ino = -1
            self._last_state = "idle"
            self._cached_log = ""
            self._cached_analysis = {
                "state": "idle",
                "prompt": "",
                "prompt_type": "text",
                "options": [],
                "error": None,
                "sso_url": "",
            }

    def update_and_check_transition(self, new_state: str) -> bool:
        """
        Update the stored state to `new_state` and indicate whether the state changed.

        Parameters:
            new_state (str): The new state value to set.

        Returns:
            bool: `True` if the previous state was different and the stored state was updated, `False` otherwise.
        """
        with self._lock:
            if self._last_state != new_state:
                self._last_state = new_state
                return True
            return False

    def get_cached_log_analysis(self, log_path: Path) -> tuple[LogAnalysis, str]:
        """
        Reads and analyzes the log file safely, only processing it if it has changed since
        the last read operation. Includes TOCTOU file handling.

        Parameters:
            log_path (Path): Path to the log file.

        Returns:
            tuple[LogAnalysis, str]: A tuple containing the log analysis dictionary and the raw log text.
        """
        # Phase 1: Rapid state checks inside the lock
        with self._lock:
            try:
                st = log_path.stat()
                if st.st_mtime_ns == self._log_mtime_ns and st.st_size == self._log_size and st.st_ino == self._log_ino:
                    return self._cached_analysis, self._cached_log

                # Capture signature parameters for validation post-read
                current_mtime_ns = st.st_mtime_ns
                current_size = st.st_size
                current_ino = st.st_ino

            except FileNotFoundError:
                # Log might have rotated or cleared; return safe default
                return {
                    "state": "idle",
                    "prompt": "",
                    "prompt_type": "text",
                    "options": [],
                    "error": None,
                    "sso_url": "",
                }, ""
            except Exception:
                logger.exception("Log stat error")
                return self._cached_analysis, self._cached_log

        # Phase 2: Perform heavy disk I/O and text processing outside the lock to prevent polling bottlenecks
        try:
            with open(log_path, "rb") as f:
                if current_size > 65536:
                    f.seek(current_size - 65536)
                    f.readline()  # Align to the next newline boundary

                data: str = f.read().decode("utf-8", errors="replace")
                lines: list[str] = data.splitlines(keepends=True)
                if lines and not lines[-1].endswith("\n"):
                    lines.pop()

                lines = lines[-300:]
                log_content = "".join(lines)

                clean_lines: list[str] = [strip_ansi(line).strip() for line in lines]
                analysis = analyze_log_lines(clean_lines, log_content)
        except Exception:
            logger.exception("Log parse error")
            with self._lock:
                return self._cached_analysis, self._cached_log

        # Phase 3: Re-acquire lock to update the shared state
        with self._lock:
            try:
                # Validate the file didn't shift beneath us to close the TOCTOU window
                st_verify = log_path.stat()
                if (
                    st_verify.st_mtime_ns == current_mtime_ns
                    and st_verify.st_size == current_size
                    and st_verify.st_ino == current_ino
                ):
                    self._log_mtime_ns = current_mtime_ns
                    self._log_size = current_size
                    self._log_ino = current_ino
                    self._cached_analysis = analysis
                    self._cached_log = log_content
            except FileNotFoundError:
                pass
            return self._cached_analysis, self._cached_log


state_manager = StateManager()

# --- Network IP Caching ---
_best_ip_cache: str = "127.0.0.1"
_best_ip_ts: float = 0.0
_BEST_IP_TTL: float = 60.0
_best_ip_lock: threading.Lock = threading.Lock()


def get_best_ip() -> str:
    """
    Selects the container's primary outbound IP address.
    Attempts to determine the best local IPv4 address by creating a UDP socket
    and targeting a reliable external IP to force routing selection.
    Caches the result to avoid repeated socket creation during frequent polling.

    Returns:
        str: The chosen IPv4 address as a string; "127.0.0.1" on failure.
    """
    global _best_ip_cache, _best_ip_ts
    now = time.monotonic()

    with _best_ip_lock:
        # TTL Cache Check
        if _best_ip_cache != "127.0.0.1" and (now - _best_ip_ts) < _BEST_IP_TTL:
            return _best_ip_cache

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                # Target Google DNS to ensure the OS default gateway route is selected
                s.connect(("8.8.8.8", 80))
                ip = str(s.getsockname()[0])
        except OSError:
            _best_ip_cache = "127.0.0.1"
            _best_ip_ts = now
            return "127.0.0.1"
        else:
            _best_ip_cache = ip
            _best_ip_ts = now
            return ip


# --- UDP BEACON ---
class Beacon(threading.Thread):
    """
    Background thread that listens for UDP broadcast packets.
    Used by the Desktop Client to auto-discover this container's IP address
    and session parameters on the local network.
    """

    def __init__(self) -> None:
        """
        Initialize the Beacon thread by marking it as a daemon and opening an IPv4 UDP socket bound to all interfaces
        on UDP_BEACON_PORT.
        """
        super().__init__()
        self.daemon = True
        self.sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Prevent BindError during rapid restarts
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("", UDP_BEACON_PORT))

    def run(self) -> None:
        """
        Listen for "GP_DISCOVER" UDP packets and respond with a JSON payload containing the agent's IP,
        HTTP port, and hostname.

        When a "GP_DISCOVER" message is received, sends a UTF-8 JSON response with keys "ip", "port",
        and "hostname". Runs indefinitely and logs unexpected errors.
        """
        logger.info(f"UDP Beacon active on port {UDP_BEACON_PORT}")
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                message: str = data.decode("utf-8").strip()

                if message == "GP_DISCOVER":
                    response: str = json.dumps(
                        {
                            "ip": get_best_ip(),
                            "port": PORT,
                            "hostname": socket.gethostname(),
                        }
                    )
                    self.sock.sendto(response.encode("utf-8"), addr)
            except Exception:
                logger.exception("Beacon error")


def strip_ansi(text: str) -> str:
    """
    Remove ANSI escape sequences (colors, cursor movements, and line-control codes) from the given text.

    Parameters:
        text (str): The raw text containing ANSI codes.

    Returns:
        str: The input string with ANSI escape sequences removed.
    """
    return ANSI_ESCAPE.sub("", text)


def _extract_gateways(clean_lines: list[str]) -> list[str]:
    """
    Scans the provided log lines forward chronologically to extract all available gateway connection options.

    Parameters:
        clean_lines (list[str]): A list of log lines stripped of ANSI characters.

    Returns:
        list[str]: A sorted list of unique gateway option strings.
    """
    input_options: list[str] = []
    seen: set[str] = set()
    for scan_line in clean_lines:
        m = GATEWAY_REGEX.search(scan_line)
        if m:
            opt: str = m.group(1).strip()
            if opt not in seen and "Which gateway" not in opt:
                seen.add(opt)
                input_options.append(opt)
    return sorted(input_options)


def _extract_sso_url(full_log_content: str, port: int) -> str:
    """
    Parses the complete log string to extract the most recent valid SAML SSO callback URL.

    Parameters:
        full_log_content (str): The entire readable log context as a string.
        port (int): The local proxy port to filter out to avoid self-referential links.

    Returns:
        str: The most recent SSO URL found, or an empty string if none exist.
    """
    found_urls: list[str] = URL_PATTERN.findall(full_log_content)
    if found_urls:
        local_urls: list[str] = [u for u in found_urls if str(port) not in u and "127.0.0.1" not in u]
        return local_urls[-1] if local_urls else found_urls[-1]
    return ""


def _evaluate_line_state(line: str, clean_lines: list[str], analysis_acc: LogAnalysis) -> bool:
    """
    Evaluates a single chronological log line to determine if it defines the current VPN connection phase.
    Mutates the passed dictionary directly.

    Parameters:
        line (str): The individual line of text to evaluate.
        clean_lines (list[str]): The entire array of lines used for context gathering (e.g. fetching gateways).
        analysis_acc (LogAnalysis): The accumulator dictionary describing the current GUI payload.

    Returns:
        bool: True if a definitive state was matched and applied, False otherwise.
    """
    if "Connected" in line and "to" in line:
        analysis_acc["state"] = "connected"
        return True
    if "Login failed" in line or "GP response error" in line:
        error_msg: str = line
        if "512" in line:
            error_msg = "Gateway Rejected Connection (Error 512). Check Gateway selection."
        analysis_acc["state"] = "error"
        analysis_acc["error"] = error_msg
        return True
    if "Which gateway do you want to connect to" in line:
        analysis_acc["state"] = "input"
        analysis_acc["prompt"] = "Select Gateway"
        analysis_acc["prompt_type"] = "select"
        analysis_acc["options"] = _extract_gateways(clean_lines)
        return True
    if "password:" in line.lower():
        analysis_acc["state"] = "input"
        analysis_acc["prompt"] = "Enter Password"
        analysis_acc["prompt_type"] = "password"
        return True
    if "username:" in line.lower():
        analysis_acc["state"] = "input"
        analysis_acc["prompt"] = "Enter Username"
        analysis_acc["prompt_type"] = "text"
        return True
    if "Connecting" in line:
        analysis_acc["state"] = "connecting"
        return True
    return False


def analyze_log_lines(clean_lines: list[str], full_log_content: str) -> LogAnalysis:
    """
    Determine the current VPN state and any required user interaction by inspecting cleaned log lines and the full
    log text. Performs a single backward-chronological pass to ensure the most recent event dictates the state.
    """
    analysis_acc: LogAnalysis = {
        "state": "idle",
        "prompt": "",
        "prompt_type": "text",
        "options": [],
        "error": None,
        "sso_url": "",
    }

    # Single backward chronological pass ensures the most recent event dictates state
    for line in reversed(clean_lines):
        if _evaluate_line_state(line, clean_lines, analysis_acc):
            break

    # Overarching full-log context checks
    if "Manual Authentication Required" in full_log_content or "auth server started" in full_log_content:
        if analysis_acc["state"] not in ["input", "error", "connected"]:
            analysis_acc["state"] = "auth"

        analysis_acc["sso_url"] = _extract_sso_url(full_log_content, PORT)

    return analysis_acc


def get_vpn_state() -> VPNState:
    """
    Determine the current VPN service status by inspecting the runtime mode file and recent client log output.

    Reads MODE_FILE (if present) to detect an explicit "idle" mode and otherwise utilizes the StateManager cache
    to extract connection state, prompts, options, errors, and SSO URLs.

    Returns:
        VPNState: A dictionary containing the serializable current state.
    """
    is_debug: bool = os.getenv("LOG_LEVEL", "INFO").upper() in ["DEBUG", "TRACE"]
    vpn_mode: str = os.getenv("VPN_MODE", "standard").strip().lower()

    proxy_mode_env: str = os.getenv("PROXY_MODE", "socks5")
    proxy_modes: list[str] = [p.strip().lower() for p in proxy_mode_env.split(",") if p.strip()]

    server_ip: str = get_best_ip()
    proxy_auth_enabled: bool = bool(os.getenv("PROXY_AUTH"))

    if MODE_FILE.exists():
        try:
            content: str = MODE_FILE.read_text().strip()
            if content == "idle":
                return {
                    "state": "idle",
                    "url": "",
                    "prompt": "",
                    "input_type": "text",
                    "options": [],
                    "error": None,
                    "log": "Ready." if is_debug else None,
                    "debug_mode": is_debug,
                    "vpn_mode": vpn_mode,
                    "proxy_modes": proxy_modes,
                    "server_ip": server_ip,
                    "proxy_auth_enabled": proxy_auth_enabled,
                }
        except Exception:
            logger.debug("Failed to read MODE_FILE, proceeding with log analysis")

    analysis, log_content = state_manager.get_cached_log_analysis(CLIENT_LOG)

    if state_manager.update_and_check_transition(analysis["state"]):
        logger.info(f"State Transition: -> {analysis['state']}")

    return {
        "state": analysis["state"],
        "url": analysis["sso_url"],
        "prompt": analysis["prompt"],
        "input_type": analysis["prompt_type"],
        "options": analysis["options"],
        "error": analysis["error"],
        "log": log_content if is_debug else None,
        "debug_mode": is_debug,
        "vpn_mode": vpn_mode,
        "proxy_modes": proxy_modes,
        "server_ip": server_ip,
        "proxy_auth_enabled": proxy_auth_enabled,
    }


def init_runtime_dir() -> None:
    """
    Ensure the process runtime directory exists with secure permissions.

    Creates RUNTIME_DIR if it does not exist. On non-Windows platforms
    the directory mode is set to 0o700; on Windows the directory is created
    without enforcing Unix-style permissions. If creation or permission changes
    fail, the error is caught and logged.
    """
    try:
        if sys.platform != "win32":
            RUNTIME_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
            RUNTIME_DIR.chmod(0o700)
        else:
            RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        logger.exception("Failed to initialize runtime dir")


def _kill_and_poll_windows() -> None:
    """Handles process termination and polling gracefully for Windows environments."""
    res1: subprocess.CompletedProcess[bytes]
    res2: subprocess.CompletedProcess[bytes]

    taskkill: str = shutil.which("taskkill") or str(
        Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32" / "taskkill.exe"
    )

    if os.path.exists(taskkill):
        subprocess.run([taskkill, "/F", "/IM", "gpclient.exe"], stderr=subprocess.DEVNULL)
        subprocess.run([taskkill, "/F", "/IM", "gpservice.exe"], stderr=subprocess.DEVNULL)
        subprocess.run([taskkill, "/F", "/IM", "gost.exe"], stderr=subprocess.DEVNULL)

        # Active polling loop for Windows environment
        for _ in range(50):
            res1 = subprocess.run(["tasklist", "/FI", "IMAGENAME eq gpclient.exe"], capture_output=True)
            res2 = subprocess.run(["tasklist", "/FI", "IMAGENAME eq gpservice.exe"], capture_output=True)
            if b"gpclient.exe" not in res1.stdout and b"gpservice.exe" not in res2.stdout:
                break
            time.sleep(0.1)
        else:
            # Forceful escalation if graceful kill fails
            subprocess.run([taskkill, "/F", "/T", "/IM", "gpclient.exe"], stderr=subprocess.DEVNULL)
            subprocess.run([taskkill, "/F", "/T", "/IM", "gpservice.exe"], stderr=subprocess.DEVNULL)
            time.sleep(0.5)


def _kill_and_poll_unix() -> None:
    """Handles Unix process termination using safe sudo polling checks, strictly avoiding unrelated processes."""
    res1: subprocess.CompletedProcess[bytes]
    res2: subprocess.CompletedProcess[bytes]

    # Directly pass '-n' non-interactive flags to ensure sudo never hangs waiting for a password.
    sudo: str | None = shutil.which("sudo")
    sudo_cmd: list[str] = []
    if sudo:
        sudo_probe: subprocess.CompletedProcess[bytes] = subprocess.run([sudo, "-n", "true"], capture_output=True)
        if sudo_probe.returncode == 0:
            sudo_cmd = [sudo, "-n"]

    pkill: str | None = shutil.which("pkill")
    pgrep: str | None = shutil.which("pgrep")

    if not pkill or not pgrep:
        logger.warning("Missing required tools for process teardown (pkill/pgrep)")
        return

    # 1. Kill gost directly as gpuser to halt routing traffic instantly
    subprocess.run([pkill, "-x", "gost"], stderr=subprocess.DEVNULL)

    # 2. Kill the unprivileged stdin proxy to forcefully unblock the bash entrypoint pipeline's left side.
    subprocess.run([pkill, "-f", "stdin_proxy.py"], stderr=subprocess.DEVNULL)

    # 3. Request graceful shutdown of privileged daemons via sudo wrappers
    subprocess.run([*sudo_cmd, pkill, "-x", "gpclient"], stderr=subprocess.DEVNULL)
    subprocess.run([*sudo_cmd, pkill, "-x", "gpservice"], stderr=subprocess.DEVNULL)

    for _ in range(50):
        res1 = subprocess.run([*sudo_cmd, pgrep, "-x", "gpclient"], capture_output=True)
        res2 = subprocess.run([*sudo_cmd, pgrep, "-x", "gpservice"], capture_output=True)
        if res1.returncode != 0 and res2.returncode != 0:
            break
        time.sleep(0.1)
    else:
        # Escalate to SIGKILL if processes didn't terminate gracefully after 5 seconds
        subprocess.run([*sudo_cmd, pkill, "-9", "-x", "gpclient"], stderr=subprocess.DEVNULL)
        subprocess.run([*sudo_cmd, pkill, "-9", "-x", "gpservice"], stderr=subprocess.DEVNULL)
        time.sleep(0.5)


def _kill_and_poll() -> None:
    """
    Terminates active OpenConnect processes and actively polls until they exit
    to prevent race conditions when generating new VPN sessions.
    Dynamically routes to the correct OS implementation.
    """
    if sys.platform == "win32":
        _kill_and_poll_windows()
    else:
        _kill_and_poll_unix()

    # Aggressively force state evaluation files to an empty/idle state.
    # This proactively prevents UI state flapping (e.g. jumping to 'Connected') on reconnects
    # where the bash orchestrator natively takes a few seconds to start truncating the old log files.
    try:
        MODE_FILE.write_text("idle\n")
        with open(CLIENT_LOG, "w") as f:
            f.truncate(0)
    except OSError:
        pass

    state_manager.reset()


class Handler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP Request Handler for the VPN Web UI.
    Handles API endpoints for status, connections, and log downloads.
    """

    def handle(self) -> None:
        """
        Gracefully catch and suppress BrokenPipeError and ConnectionResetError.
        These occur harmlessly when a web browser requests an asset (like an image)
        but closes the connection before the server finishes sending the bytes.
        """
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):  # fmt: skip
            pass

    def _is_authorized(self) -> bool:
        """
        Check whether the incoming HTTP request is authorized for protected endpoints.

        Accepts one of: the ephemeral GUI bearer token, an API token from the API_TOKEN
        environment variable, or a TOFU Ed25519 signature from a previously paired client.
        For TOFU authentication the request must include X-Signature (base64) and X-Timestamp
        headers; the signature is verified over the message "{timestamp}:{path}" and the timestamp
        must be within 5 seconds of server time to limit replay attacks.

        Returns:
            `True` if the request is authorized, `False` otherwise.
        """
        # 1. Bearer Token Check (Ephemeral GUI or Manual Override API_TOKEN)
        auth_header = self.headers.get("Authorization", "")
        if auth_header:
            if hmac.compare_digest(auth_header, f"Bearer {EPHEMERAL_TOKEN}"):
                return True

            expected_token = os.getenv("API_TOKEN")
            if expected_token and hmac.compare_digest(auth_header, f"Bearer {expected_token}"):
                return True

        # 2. Ed25519 Cryptographic Signature Check (Paired Rust Client)
        with _pairing_lock:
            pubkey_snapshot = _paired_pubkey  # pyright: ignore[reportUnknownVariableType]

        if pubkey_snapshot is not None:
            sig_b64 = self.headers.get("X-Signature")
            timestamp = self.headers.get("X-Timestamp")
            if sig_b64 and timestamp:
                try:
                    ts = int(timestamp)
                    # Enforce a tight 5-second window to mitigate replay attacks
                    if abs(time.time() - ts) < 5:
                        # Required Signature Payload Structure: "{timestamp}:{path}"
                        message = f"{ts}:{self.path}".encode()
                        sig = base64.b64decode(sig_b64)
                        pubkey_snapshot.verify(sig, message)  # pyright: ignore[reportUnknownMemberType]
                        return True
                except (ValueError, InvalidSignature, TypeError):  # fmt: skip
                    pass

        return False

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """
        Log HTTP requests to the module logger, using debug level for requests to "status.json".

        Safely formats the message even if no args are provided and casts the first arg to string
        to avoid crashes with HTTPStatus enum values on newer Python versions.

        Parameters:
            format (str): Format string for the log message.
            *args (Any): Positional values to be interpolated into `format`.
        """
        if args and "status.json" in str(args[0]):
            logger.debug("%s - - %s", self.client_address[0], format % args)
        else:
            logger.info("%s - - %s", self.client_address[0], format % args)

    def end_headers(self) -> None:
        """
        Set response caching headers appropriate for the requested resource before finalizing HTTP headers.

        For the root, index, and status endpoints ("/", "/index.html", "/status.json"), adds headers to disable
        caching. For common static asset extensions (".css", ".js", ".png", ".ico", ".svg", ".jpg"), adds a long-lived,
        immutable Cache-Control header. Safely handles cases where the request path is unavailable.
        """
        # Safely evaluate path in the event this is called prematurely during an HTTP error
        raw_path: str = self.path if hasattr(self, "path") else ""
        base_path: str = urllib.parse.urlparse(raw_path).path

        if base_path in ["/", "/index.html", "/status.json"]:
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
        elif base_path.endswith((".css", ".js", ".png", ".ico", ".svg", ".jpg")):
            self.send_header("Cache-Control", "public, max-age=31536000, immutable")

        super().end_headers()

    def do_GET(self) -> None:  # noqa: C901
        """
        Handle HTTP GET requests for the web UI and API, serving static assets and protected endpoints.

        Processes these routes:
        - /status.json: requires authorization; responds with the current VPN state as JSON.
        - /download_logs: requires authorization and a DEBUG or TRACE log level; streams the combined service
        and client logs as a plain-text attachment named "vpn_full_debug.log".
        - /: maps to /index.html for the web UI.

        Direct access to sensitive file extensions (".py", ".pyc", ".pyo", ".env", ".sh") is blocked; all other
        paths are handled by the base class handler.
        """
        # Security Guard: Explicitly block serving python source files and other sensitive extensions
        request_path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path).lower()
        if request_path.endswith((".py", ".pyc", ".pyo", ".env", ".sh")):
            self.send_error(403, "Forbidden")
            return

        if request_path == "/status.json":
            if not self._is_authorized():
                self.send_error(401, "Unauthorized")
                return
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(get_vpn_state()).encode("utf-8"))
            return

        if request_path == "/download_logs":
            if not self._is_authorized():
                self.send_error(401, "Unauthorized")
                return
            if os.getenv("LOG_LEVEL", "INFO").upper() not in ["DEBUG", "TRACE"]:
                self.send_error(403, "Debug mode required to download logs.")
                return

            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Disposition", "attachment; filename=vpn_full_debug.log")
                self.end_headers()

                self.wfile.write(b"=== SERVICE LOG ===\n\n")
                if SERVICE_LOG.exists():
                    with open(SERVICE_LOG, "rb") as f:
                        shutil.copyfileobj(f, self.wfile)

                self.wfile.write(b"\n\n=== CLIENT LOG ===\n\n")
                if CLIENT_LOG.exists():
                    with open(CLIENT_LOG, "rb") as f:
                        shutil.copyfileobj(f, self.wfile)
            except OSError:
                logger.debug("Error while streaming logs to client (connection may have closed)")
            return

        if request_path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def _handle_pair(self, length: int) -> None:
        """
        Handle a TOFU Ed25519 public key pairing request from a Rust client.

        Accepts a JSON payload in the request body containing a base64-encoded "public_key",
        stores the decoded key as the module-level paired Ed25519 public key, and responds with
        HTTP 200 and "OK" on success. Pairing is rejected with HTTP 403 if an API token is
        configured (pairing disabled) or if a key is already paired. Missing or invalid payloads
        result in HTTP 400.

        Parameters:
            length (int): Number of bytes to read from the request body (Content-Length).
        """
        global _paired_pubkey
        if os.getenv("API_TOKEN"):
            self.send_error(403, "Pairing disabled: Manual API_TOKEN configured")
            return

        with _pairing_lock:
            if _paired_pubkey is not None:
                self.send_error(403, "Already paired. Trust On First Use (TOFU) locking active.")
                return

            try:
                raw_data = self.rfile.read(length).decode("utf-8")
                data = json.loads(raw_data)
                pubkey_b64 = data.get("public_key")
                if not pubkey_b64:
                    self.send_error(400, "Missing public_key")
                    return

                pubkey_bytes = base64.b64decode(pubkey_b64)
                _paired_pubkey = Ed25519PublicKey.from_public_bytes(pubkey_bytes)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]

                logger.info("TOFU Pairing successful. Rust Host Agent trusted.")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
            except (ValueError, KeyError, TypeError) as e:  # fmt: skip
                logger.warning(f"Pairing failed: {e}")
                self.send_error(400, "Invalid pairing payload")

    def _handle_connect(self) -> None:
        """
        Initiate a VPN connection by terminating any running VPN processes and requesting a start via the control IPC.

        Terminates existing VPN-related processes, sends a "START" command to the control IPC,
        and writes an HTTP response reflecting the outcome:
        - Responds 200 with body "OK" when the start command was accepted.
        - Responds 503 with an explanatory message when the control IPC is unavailable.
        """
        logger.info("User requested Connection")
        _kill_and_poll()

        success: bool = send_ipc_message(IPC_CONTROL_PORT, "START\n")
        if success:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_error(503, "Service not ready (IPC absent)")

    def _handle_disconnect(self) -> None:
        """
        Handle an HTTP disconnect request and cleanly terminate VPN client processes.
        """
        logger.info("User requested Disconnect")
        _kill_and_poll()

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def _handle_submit(self, length: int) -> None:
        """
        Handle form-encoded submissions containing either a callback URL or user-provided input.
        Forwards the payload to the service input IPC. Prevents memory exhaustion attacks.
        Safely utilizes strict parsing to prevent dictionary inference errors.
        """
        try:
            raw_data: str = self.rfile.read(length).decode("utf-8")
            data: dict[str, list[str]] = urllib.parse.parse_qs(raw_data, strict_parsing=True)

            if user_input_list := (data.get("callback_url") or data.get("user_input") or []):
                user_input: str = user_input_list[0]
                sanitized_input: str = user_input.strip().replace("\r", "").replace("\n", "")
                logger.info(f"User submitted input (Length: {len(sanitized_input)})")

                success: bool = send_ipc_message(IPC_STDIN_PORT, sanitized_input + "\n")
                if success:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"OK")
                else:
                    self.send_error(503, "Service not ready (IPC absent)")
            else:
                self.send_error(400, "Empty input")
        except (ValueError, KeyError, TypeError):  # fmt: skip
            logger.warning("Invalid input format received", exc_info=True)
            self.send_error(400, "Bad Request")
        except Exception:
            logger.exception("Internal input processing error")
            self.send_error(500, "Internal server error")

    def do_POST(self) -> None:
        """
        Route POST requests for VPN control, enforcing payload size limits and authorization before
        dispatching to endpoint handlers.

        Supports the following endpoints:
        - /api/pair: Accepts TOFU Ed25519 pairing requests; allowed without prior authorization.
        - /connect: Starts a VPN connection; requires authorization.
        - /disconnect: Stops the VPN client processes; requires authorization.
        - /submit: Forwards form-encoded input (expects 'callback_url' or 'user_input') to the VPN client;
          requires authorization.

        Behavior:
        - Validates Content-Length and rejects requests larger than 8192 bytes (413) or negative lengths (400).
        - Returns 401 for unauthorized requests (except /api/pair) and 404 for unknown endpoints.
        """
        raw_path: str = self.path if hasattr(self, "path") else ""
        request_path: str = urllib.parse.unquote(urllib.parse.urlsplit(raw_path).path).lower()

        try:
            length: int = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):  # fmt: skip
            length = 0

        if length < 0 or length > 8192:
            self.send_error(400 if length < 0 else 413, "Invalid Payload Size")
            return

        # Explicitly allow unauthenticated pairing
        if request_path == "/api/pair":
            self._handle_pair(length)
            return

        if not self._is_authorized():
            self.send_error(401, "Unauthorized")
            return

        if request_path == "/connect":
            self._handle_connect()
        elif request_path == "/disconnect":
            self._handle_disconnect()
        elif request_path == "/submit":
            self._handle_submit(length)
        else:
            self.send_error(404, "Endpoint not found")


class VPNServer(socketserver.ThreadingTCPServer):
    """Custom ThreadingTCPServer that safely enables address reuse."""

    allow_reuse_address: ClassVar[bool] = True  # type: ignore[misc] # pyright: ignore[reportIncompatibleVariableOverride]

    def handle_error(self, request: Any, client_address: Any) -> None:
        """
        Gracefully catch and suppress BrokenPipeError and ConnectionResetError.
        These occur harmlessly when a web browser requests an asset (like an image)
        but drops the TCP connection before the server finishes sending the bytes.
        """
        exc_type, _exc_value, _traceback = sys.exc_info()
        if exc_type and issubclass(exc_type, (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


if __name__ == "__main__":
    target_dir: Path = Path("/var/www/html")

    try:
        if target_dir.exists() and target_dir.is_dir():
            os.chdir(target_dir)
        else:
            # Fallback for local Windows development environments
            local_web_dir = (Path(__file__).parent.parent / "web").resolve()
            if local_web_dir.exists() and local_web_dir.is_dir():
                os.chdir(local_web_dir)
            else:
                logger.error("Failed to locate web assets directory. Exiting to prevent source exposure.")
                sys.exit(1)
    except PermissionError:
        logger.exception("Permission denied changing to target web directory.")
        sys.exit(1)

    init_runtime_dir()

    # Dynamic cache busting and ephemeral token injection for the frontend GUI.
    try:
        index_path = Path("index.html")

        if index_path.exists():
            content_sig = b""
            for ext in [".css", ".js", ".png", ".svg", ".ico", ".jpg"]:
                for asset_file in sorted(Path(".").rglob(f"*{ext}")):
                    if asset_file.is_file():
                        content_sig += asset_file.read_bytes()

            # Fix: Deterministic fallback to ensure reproducible cache busting hashes across restarts
            if content_sig:
                build_hash = hashlib.md5(content_sig, usedforsecurity=False).hexdigest()[:8]
            else:
                build_hash = hashlib.md5(index_path.read_bytes(), usedforsecurity=False).hexdigest()[:8]

            # Update HTML file references universally
            content = index_path.read_text("utf-8")
            content = re.sub(
                r'href="([^"]+\.(?:css|ico|svg|png|jpg))(\?v=[a-zA-Z0-9]+)?"', rf'href="\1?v={build_hash}"', content
            )
            content = re.sub(
                r'src="([^"]+\.(?:js|png|jpg|svg|ico))(\?v=[a-zA-Z0-9]+)?"', rf'src="\1?v={build_hash}"', content
            )

            # Use Regex to dynamically inject the Ephemeral Token, replacing either the placeholder or old tokens
            content = re.sub(
                r'<meta name="session-token" content="[^"]+" */?>',
                f'<meta name="session-token" content="{EPHEMERAL_TOKEN}" />',
                content,
            )

            index_path.write_text(content, "utf-8")

            logger.info(f"Injected cache-busting hash {build_hash} and Ephemeral UI Token into static assets")
    except Exception:
        logger.exception("Failed to apply cache busting to HTML. Browsers may serve stale assets.")

    if not os.getenv("API_TOKEN") and _paired_pubkey is None:
        logger.warning("No API_TOKEN set and no TOFU key paired. Awaiting POST /api/pair.")

    beacon: Beacon = Beacon()
    beacon.start()

    with VPNServer(("", PORT), Handler) as httpd:
        logger.info(f"Server listening on {PORT}")
        httpd.serve_forever()
