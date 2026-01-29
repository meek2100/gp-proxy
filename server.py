# File: server.py
import http.server
import json
import logging
import os
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import deque
from pathlib import Path
from typing import Any, TypedDict

# --- Configuration ---
PORT = 8001
UDP_BEACON_PORT = 32800  # New Discovery Port
FIFO_STDIN = Path("/tmp/gp-stdin")
FIFO_CONTROL = Path("/tmp/gp-control")
CLIENT_LOG = Path("/tmp/gp-logs/gp-client.log")
MODE_FILE = Path("/tmp/gp-mode")
SERVICE_LOG = Path("/tmp/gp-logs/gp-service.log")


# --- UDP BEACON (New Feature) ---
class Beacon(threading.Thread):
    def __init__(self) -> None:  # Added -> None
        super().__init__()
        self.daemon = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", UDP_BEACON_PORT))
        # Use a localized logger or print if logger isn't ready, but here it's fine

    def run(self) -> None:  # Added -> None
        logger.info(f"UDP Beacon active on port {UDP_BEACON_PORT}")
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                message = data.decode("utf-8").strip()

                if message == "GP_DISCOVER":
                    response = json.dumps({"ip": self.get_best_ip(), "port": PORT, "hostname": socket.gethostname()})
                    self.sock.sendto(response.encode("utf-8"), addr)
            except Exception as e:
                logger.error(f"Beacon error: {e}")

    def get_best_ip(self) -> str:  # Added -> str
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return str(ip)  # Explicit cast to match return type
        except Exception:
            return "127.0.0.1"


# --- Logging Setup ---
# OPTIMIZATION: Removed StreamHandler to prevent duplicate logs in Docker
# The entrypoint.sh 'tail -F' process already streams this file to stdout.
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "DEBUG").upper(),
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    handlers=[
        logging.FileHandler(SERVICE_LOG),
        # logging.StreamHandler(sys.stderr),  <-- REMOVED
    ],
)
logger = logging.getLogger()

last_known_state: str | None = None


class VPNState(TypedDict):
    """Type definition for the VPN state response."""

    state: str
    url: str
    prompt: str
    input_type: str
    options: list[str]
    error: str
    log: str
    debug_mode: bool
    vpn_mode: str


class LogAnalysis(TypedDict):
    """Internal type for the result of log analysis."""

    state: str
    prompt: str
    prompt_type: str
    options: list[str]
    error: str
    sso_url: str


def strip_ansi(text: str) -> str:
    """
    Aggressively remove ANSI escape sequences to reveal pure text.
    Handles colors, cursor movements, and line clearing.
    """
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)


def _check_connected(clean_lines: list[str]) -> LogAnalysis | None:
    """Helper: Check if connected successfully."""
    for line in reversed(clean_lines):
        if "Connected" in line and "to" in line:
            return {
                "state": "connected",
                "prompt": "",
                "prompt_type": "text",
                "options": [],
                "error": "",
                "sso_url": "",
            }
    return None


def _check_error(clean_lines: list[str]) -> LogAnalysis | None:
    """Helper: Check for specific failure messages."""
    for line in reversed(clean_lines):
        if "Login failed" in line or "GP response error" in line:
            error_msg = line
            if "512" in line:
                error_msg = "Gateway Rejected Connection (Error 512). Check Gateway selection."
            return {
                "state": "error",
                "prompt": "",
                "prompt_type": "text",
                "options": [],
                "error": error_msg,
                "sso_url": "",
            }
    return None


def _check_input_request(clean_lines: list[str]) -> LogAnalysis | None:
    """Helper: Check if the VPN client is asking for user input."""
    for line in reversed(clean_lines):
        # Gateway Selection
        if "Which gateway do you want to connect to" in line:
            input_options: list[str] = []
            gateway_regex = re.compile(r"(?:>|\s)*([A-Za-z0-9\-\.]+\s+\([A-Za-z0-9\-\.]+\))")
            seen: set[str] = set()
            for scan_line in clean_lines:
                m = gateway_regex.search(scan_line)
                if m:
                    opt = m.group(1).strip()
                    if opt not in seen and "Which gateway" not in opt:
                        seen.add(opt)
                        input_options.append(opt)
            return {
                "state": "input",
                "prompt": "Select Gateway",
                "prompt_type": "select",
                "options": sorted(input_options),
                "error": "",
                "sso_url": "",
            }

        # Password Prompt
        if "password:" in line.lower():
            return {
                "state": "input",
                "prompt": "Enter Password",
                "prompt_type": "password",
                "options": [],
                "error": "",
                "sso_url": "",
            }

        # Username Prompt
        if "username:" in line.lower():
            return {
                "state": "input",
                "prompt": "Enter Username",
                "prompt_type": "text",
                "options": [],
                "error": "",
                "sso_url": "",
            }
    return None


def analyze_log_lines(clean_lines: list[str], full_log_content: str) -> LogAnalysis:
    """
    Analyze cleaned log lines to determine the current VPN state.
    Orchestrates helper functions to keep complexity low (C901).
    """
    # 1. Check Connected
    res = _check_connected(clean_lines)
    if res:
        return res

    # 2. Check Errors
    res = _check_error(clean_lines)
    if res:
        return res

    # 3. Check Input
    analysis_acc: LogAnalysis = {
        "state": "idle",
        "prompt": "",
        "prompt_type": "text",
        "options": [],
        "error": "",
        "sso_url": "",
    }

    input_res = _check_input_request(clean_lines)
    if input_res:
        analysis_acc = input_res

    # 4. Check SSO / Authentication
    if "Manual Authentication Required" in full_log_content or "auth server started" in full_log_content:
        if analysis_acc["state"] != "input":
            analysis_acc["state"] = "auth"

        url_pattern = re.compile(r'(https?://[^\s"<>]+)')
        found_urls = url_pattern.findall(full_log_content)
        if found_urls:
            local_urls = [u for u in found_urls if str(PORT) not in u and "127.0.0.1" not in u]
            analysis_acc["sso_url"] = local_urls[-1] if local_urls else found_urls[-1]

    return analysis_acc


def get_vpn_state() -> VPNState:
    """
    Parse the VPN log to determine the current state of the connection process.

    Returns:
        VPNState: A dictionary containing the current status, prompts, and debug logs.
    """
    global last_known_state
    is_debug = os.getenv("LOG_LEVEL", "INFO").upper() in ["DEBUG", "TRACE"]
    vpn_mode = os.getenv("VPN_MODE", "standard")

    # 1. Check Mode File
    if MODE_FILE.exists():
        try:
            content = MODE_FILE.read_text().strip()
            if content == "active":
                pass
            elif content == "idle":
                # FIX 3: Returned a valid VPNState object, not a string "127.0.0.1"
                # The "127.0.0.1" string was a copy-paste error from get_best_ip()
                return {
                    "state": "idle",
                    "url": "",
                    "prompt": "",
                    "input_type": "text",
                    "options": [],
                    "error": "",
                    "log": "Ready.",
                    "debug_mode": is_debug,
                    "vpn_mode": vpn_mode,
                }
        except Exception:
            # FIX 3 (continued): Return valid object on error too
            pass

    log_content = ""
    analysis: LogAnalysis = {
        "state": "idle",
        "prompt": "",
        "prompt_type": "text",
        "options": [],
        "error": "",
        "sso_url": "",
    }

    # 2. Parse Logs (Optimized with Seek)
    if CLIENT_LOG.exists():
        try:
            file_size = CLIENT_LOG.stat().st_size
            with open(CLIENT_LOG, errors="replace") as f:
                # Optimization: Only read the last 64KB
                if file_size > 65536:
                    f.seek(file_size - 65536)
                    f.readline()  # Discard partial line

                lines = list(deque(f, maxlen=300))
                log_content = "".join(lines)
                clean_lines = [strip_ansi(line).strip() for line in lines[-100:]]

                # Delegate to simplified analyzer
                analysis = analyze_log_lines(clean_lines, log_content)

        except Exception as e:
            logger.error(f"Log parse error: {e}")

    # State Transition Logging
    if analysis["state"] != last_known_state:
        logger.info(f"State Transition: {last_known_state} -> {analysis['state']}")
        last_known_state = analysis["state"]

    return {
        "state": analysis["state"],
        "url": analysis["sso_url"],
        "prompt": analysis["prompt"],
        "input_type": analysis["prompt_type"],
        "options": analysis["options"],
        "error": analysis["error"],
        "log": log_content,
        "debug_mode": is_debug,
        "vpn_mode": vpn_mode,
    }


class Handler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP Request Handler for the VPN Web UI.
    Handles API endpoints for status, connections, and log downloads.
    """

    # FIX: Reverted arg name to 'format' to match BaseHTTPRequestHandler signature (Pyright)
    # FIX: Added noqa: A002 to suppress Ruff shadowing warning
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Redirect default HTTP logs to the unified logger."""
        # OPTIMIZATION: Log status polling at DEBUG level to prevent log flooding
        if "status.json" in args[0]:
            logger.debug("%s - - %s", self.client_address[0], format % args)
        else:
            logger.info("%s - - %s", self.client_address[0], format % args)

    def do_GET(self) -> None:
        """Handle GET requests."""
        if self.path.startswith("/status.json"):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(json.dumps(get_vpn_state()).encode("utf-8"))
            return

        if self.path == "/download_logs":
            # Security Check: Only allow download if debug is enabled
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
            except Exception:
                pass
            return

        if self.path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self) -> None:
        """Handle POST requests for connection control."""
        if self.path == "/connect":
            logger.info("User requested Connection")
            # Force clean slate: kill both client and service
            subprocess.run(["sudo", "pkill", "gpclient"], stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "pkill", "gpservice"], stderr=subprocess.DEVNULL)
            time.sleep(0.5)
            try:
                # Platform-safe dynamic check for Windows dev
                if sys.platform != "win32":
                    if not FIFO_CONTROL.exists():
                        os.mkfifo(FIFO_CONTROL)
                        os.chmod(FIFO_CONTROL, 0o666)

                with open(FIFO_CONTROL, "w") as f:
                    f.write("START\n")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
            except Exception:
                self.send_error(500, "Failed to start")
            return

        if self.path == "/disconnect":
            logger.info("User requested Disconnect")
            # Kill everything to return to standby
            subprocess.run(["sudo", "pkill", "gpclient"], stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "pkill", "gpservice"], stderr=subprocess.DEVNULL)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
            return

        if self.path == "/submit":
            try:
                length = int(self.headers.get("Content-Length", 0))
                data = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
                user_input = data.get("callback_url", [""])[0] or data.get("user_input", [""])[0]

                if user_input:
                    logger.info(f"User submitted input (Length: {len(user_input)})")
                    with open(FIFO_STDIN, "w") as fifo:
                        fifo.write(user_input.strip() + "\n")
                        fifo.flush()
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"OK")
                else:
                    self.send_error(400, "Empty input")
            except Exception as e:
                logger.error(f"Input error: {e}")
                self.send_error(500, str(e))
            return


if __name__ == "__main__":
    os.chdir("/var/www/html")

    # FIX: Platform-safe check
    if sys.platform != "win32":
        if not FIFO_CONTROL.exists():
            # Use getattr to avoid linter errors on Windows dev machines
            os.mkfifo(FIFO_CONTROL)
            os.chmod(FIFO_CONTROL, 0o666)

    # START BEACON
    beacon = Beacon()
    beacon.start()

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("", PORT), Handler) as httpd:
        logger.info(f"Server listening on {PORT}")
        httpd.serve_forever()
