# File: server.py
import errno
import http.server
import json
import logging
import os
import re
import shutil
import socket
import socketserver
import stat
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
UDP_BEACON_PORT = 32800
RUNTIME_DIR = Path("/tmp/gp-runtime")
FIFO_STDIN = RUNTIME_DIR / "gp-stdin"
FIFO_CONTROL = RUNTIME_DIR / "gp-control"
MODE_FILE = RUNTIME_DIR / "gp-mode"
CLIENT_LOG = Path("/tmp/gp-logs/gp-client.log")
SERVICE_LOG = Path("/tmp/gp-logs/gp-service.log")

O_NONBLOCK: int = getattr(os, "O_NONBLOCK", 0)

# --- Pre-compiled Regex (Optimization) ---
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
GATEWAY_REGEX = re.compile(r"(?:>|\s)*([A-Za-z0-9\-\.]+\s+\([A-Za-z0-9\-\.]+\))")
URL_PATTERN = re.compile(r'(https?://[^\s"<>]+)')


# --- State Management (Thread Safety) ---
class StateManager:
    """
    Thread-safe manager for the VPN state.
    Prevents race conditions between the log analyzer thread and HTTP request threads.
    """

    def __init__(self) -> None:
        """
        Initialize a thread-safe state manager.

        Creates a private lock for synchronizing access and initializes the internal last-state tracker to None.
        """
        self._lock = threading.Lock()
        self._last_state: str | None = None

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


state_manager = StateManager()


# --- UDP BEACON ---
class Beacon(threading.Thread):
    """
    Background thread that listens for UDP broadcast packets.
    Used by the Desktop Client to auto-discover this container's IP address
    on the local network without user intervention.
    """

    def __init__(self) -> None:
        """
        Initialize the Beacon thread by marking it as a daemon and opening an IPv4 UDP socket bound to all interfaces
        on UDP_BEACON_PORT.

        The socket is created for datagram (UDP) communication and bound to ("", UDP_BEACON_PORT) so the Beacon can
        receive broadcast discovery packets.
        """
        super().__init__()
        self.daemon = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", UDP_BEACON_PORT))

    def run(self) -> None:
        """
        Listen for "GP_DISCOVER" UDP packets and respond with a JSON payload containing the best IP, server port,
        and hostname.

        This method runs indefinitely; on receiving a "GP_DISCOVER" message it sends a UDP response to the sender
        with the fields `ip`, `port`, and `hostname`.
        """
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

    def get_best_ip(self) -> str:
        """
        Selects the container's primary outbound IP address.

        Attempts to determine the best local IPv4 address by creating a UDP socket and letting the OS assign the
        outbound interface. Falls back to "127.0.0.1" if network information cannot be obtained.

        Returns:
            ip (str): The chosen IPv4 address as a string; "127.0.0.1" on failure.
        """
        try:
            # Connect to a non-routable address to force the OS to select the default interface IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("10.255.255.255", 1))
                return str(s.getsockname()[0])
        except OSError:
            # Fallback for environments without standard networking (e.g., testing)
            return "127.0.0.1"


# --- Logging Setup ---
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "DEBUG").upper(),
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    handlers=[
        logging.FileHandler(SERVICE_LOG),
    ],
)
logger = logging.getLogger()


class VPNState(TypedDict):
    """Type definition for the VPN state response."""

    state: str
    url: str
    prompt: str
    input_type: str
    options: list[str]
    error: str
    log: str | None
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
    Remove ANSI escape sequences (colors, cursor movements, and line-control codes) from the given text.

    Returns:
        cleaned (str): The input string with ANSI escape sequences removed.
    """
    return ANSI_ESCAPE.sub("", text)


def _check_connected(clean_lines: list[str]) -> LogAnalysis | None:
    """
    Determine whether the provided cleaned log lines indicate a successful VPN connection.

    Returns:
        LogAnalysis | None: A LogAnalysis mapping with state "connected" (and empty prompt/options/error/sso_url)
        if a successful connection is detected, `None` otherwise.
    """
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
    """
    Detects whether the VPN client log requests user input (gateway selection, password, or username).

    Parameters:
        clean_lines (list[str]): Log lines already stripped of ANSI sequences, in chronological order.

    Returns:
        LogAnalysis | None: `LogAnalysis` with state `"input"` and fields describing the prompt when an input
        request is found; `None` if no input prompt is detected.
    """
    for line in reversed(clean_lines):
        if "Which gateway do you want to connect to" in line:
            input_options: list[str] = []
            seen: set[str] = set()
            for scan_line in clean_lines:
                m = GATEWAY_REGEX.search(scan_line)
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

        if "password:" in line.lower():
            return {
                "state": "input",
                "prompt": "Enter Password",
                "prompt_type": "password",
                "options": [],
                "error": "",
                "sso_url": "",
            }

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
    Determine the current VPN state and any required user interaction by inspecting cleaned log lines and the full
    log text.

    Parameters:
        clean_lines (list[str]): Log lines with ANSI sequences removed, in chronological order.
        full_log_content (str): Entire raw log content (used to detect authentication events and extract SSO URLs).

    Returns:
        analysis (LogAnalysis): Mapping with keys:
                - state: One of "idle", "connected", "error", "input", or "auth".
                - prompt: Text to present to the user (empty if none).
                - prompt_type: Type of prompt ("text", "password", or "select").
                - options: List of selectable options when prompt_type is "select".
                - error: Error message when state is "error", empty otherwise.
                - sso_url: Extracted single SSO URL when available, empty otherwise.
    """
    # 1. Check Connected
    res = _check_connected(clean_lines)
    if res:
        return res

    res = _check_error(clean_lines)
    if res:
        return res

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

    # Detect connecting state to improve UI responsiveness
    if analysis_acc["state"] == "idle":
        for line in reversed(clean_lines):
            if "Connecting" in line:
                analysis_acc["state"] = "connecting"
                break

    if "Manual Authentication Required" in full_log_content or "auth server started" in full_log_content:
        if analysis_acc["state"] != "input":
            analysis_acc["state"] = "auth"

        found_urls = URL_PATTERN.findall(full_log_content)
        if found_urls:
            local_urls = [u for u in found_urls if str(PORT) not in u and "127.0.0.1" not in u]
            analysis_acc["sso_url"] = local_urls[-1] if local_urls else found_urls[-1]

    return analysis_acc


def get_vpn_state() -> VPNState:
    """
    Determine the current VPN service status by inspecting the runtime mode file and recent client log output.

    Reads MODE_FILE (if present) to detect an explicit "idle" mode and otherwise parses the tail of CLIENT_LOG to
    extract connection state, prompts, options, errors, and SSO URLs. May update the global state_manager with the
    detected state (which can produce a log entry on transition).

    Returns:
        VPNState: A dictionary containing:
            - state: current state name (e.g., "idle", "input", "connected", "error", "auth").
            - url: an SSO or callback URL if discovered, otherwise empty string.
            - prompt: user-facing prompt text when input is required, otherwise empty string.
            - input_type: type of expected input ("text", "password", or "select").
            - options: list of selectable options when applicable.
            - error: error message text when in an error state, otherwise empty string.
            - log: recent client log content when debug logging is enabled, otherwise None.
            - debug_mode: `True` when LOG_LEVEL is DEBUG or TRACE, otherwise `False`.
            - vpn_mode: runtime VPN mode string from the VPN_MODE environment variable.
    """
    is_debug = os.getenv("LOG_LEVEL", "INFO").upper() in ["DEBUG", "TRACE"]
    vpn_mode = os.getenv("VPN_MODE", "standard")

    if MODE_FILE.exists():
        try:
            content = MODE_FILE.read_text().strip()
            if content == "idle":
                return {
                    "state": "idle",
                    "url": "",
                    "prompt": "",
                    "input_type": "text",
                    "options": [],
                    "error": "",
                    "log": "Ready." if is_debug else None,
                    "debug_mode": is_debug,
                    "vpn_mode": vpn_mode,
                }
        except Exception:
            logger.debug("Failed to read MODE_FILE, proceeding with log analysis")

    log_content = ""
    analysis: LogAnalysis = {
        "state": "idle",
        "prompt": "",
        "prompt_type": "text",
        "options": [],
        "error": "",
        "sso_url": "",
    }

    if CLIENT_LOG.exists():
        try:
            file_size = CLIENT_LOG.stat().st_size
            with open(CLIENT_LOG, errors="replace") as f:
                if file_size > 65536:
                    f.seek(file_size - 65536)
                    f.readline()

                lines = list(deque(f, maxlen=300))
                log_content = "".join(lines)
                clean_lines = [strip_ansi(line).strip() for line in lines[-100:]]

                analysis = analyze_log_lines(clean_lines, log_content)

        except Exception as e:
            logger.exception(f"Log parse error: {e}")

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
    }


def init_runtime_dir() -> None:
    """
    Create the secure runtime directory and ensure required FIFOs exist.

    On non-Windows systems, creates RUNTIME_DIR with mode 0o700 and ensures FIFO_STDIN and FIFO_CONTROL
    exist as FIFOs with mode 0o600. If a path exists but is not a FIFO, an error is logged. Any exceptions
    encountered during setup are caught and logged. On Windows, this function is a no-op.
    """
    if sys.platform != "win32":
        try:
            # Create directory with 0o700 permissions
            RUNTIME_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

            # Setup FIFOs
            for fifo_path in [FIFO_STDIN, FIFO_CONTROL]:
                try:
                    os.mkfifo(fifo_path, mode=0o600)
                except FileExistsError:
                    if not stat.S_ISFIFO(fifo_path.stat().st_mode):
                        logger.error(f"{fifo_path} exists but is not a FIFO.")

        except Exception as e:
            logger.exception(f"Failed to initialize runtime dir: {e}")


def write_fifo_nonblocking(fifo_path: Path, data: str) -> bool:
    """
    Perform a non-blocking write of `data` to the FIFO at `fifo_path`.

    Parameters:
        fifo_path (Path): Path to the FIFO (named pipe) to write to.
        data (str): UTF-8 text to write into the FIFO.

    Returns:
        bool: `True` if the data was written successfully, `False` if no reader was available or an error occurred.
    """
    fd = None
    try:
        # Open in non-blocking mode using the safe constant
        fd = os.open(fifo_path, os.O_WRONLY | O_NONBLOCK)
        os.write(fd, data.encode("utf-8"))
        return True
    except OSError as e:
        if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.ENXIO):
            logger.warning(f"No reader connected to {fifo_path}")
            return False
        logger.exception(f"FIFO write error: {e}")
        return False
    finally:
        if fd is not None:
            os.close(fd)


class Handler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP Request Handler for the VPN Web UI.
    Handles API endpoints for status, connections, and log downloads.
    """

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """
        Log HTTP requests to the module logger, using DEBUG for requests to status.json and INFO for all other requests.

        The message is emitted with the client's IP address prefixed and the handler's formatted message.
        """
        if "status.json" in args[0]:
            logger.debug("%s - - %s", self.client_address[0], format % args)
        else:
            logger.info("%s - - %s", self.client_address[0], format % args)

    def do_GET(self) -> None:
        """
        Handle incoming HTTP GET requests for status, log download, and static file serving.

        Routes:
        - /status.json: Returns the current VPN status as JSON with no-cache headers.
        - /download_logs: Sends a combined service and client log attachment; allowed only when log level is DEBUG
          or TRACE.
        - /: Serves the index.html page by rewriting the path to /index.html.
        - All other paths: Delegates to the superclass to serve static files or default handling.
        """
        if self.path.startswith("/status.json"):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(json.dumps(get_vpn_state()).encode("utf-8"))
            return

        if self.path == "/download_logs":
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
                logger.debug("Error while streaming logs to client (connection may have closed)")
            return

        if self.path == "/":
            self.path = "/index.html"
        return super().do_GET()

    # --- ACTION HANDLERS (Reduce Complexity) ---

    def _handle_connect(self) -> None:
        """
        Handle an HTTP request to initiate a VPN connection.

        Attempts to stop existing gpclient/gpservice processes, signals the service to start by writing "START\n"
        to the control FIFO, and sends an HTTP response to the requester: 200 with body "OK" when the FIFO write
        succeeds, 503 if no FIFO reader is present, or 501 on Windows where this operation is not implemented.
        """
        logger.info("User requested Connection")
        pkill = shutil.which("pkill")
        if pkill:
            subprocess.run([pkill, "gpclient"], stderr=subprocess.DEVNULL)
            subprocess.run([pkill, "gpservice"], stderr=subprocess.DEVNULL)

        time.sleep(0.5)

        if sys.platform != "win32":
            success = write_fifo_nonblocking(FIFO_CONTROL, "START\n")
            if success:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
            else:
                self.send_error(503, "Service not ready (FIFO reader absent)")
        else:
            self.send_error(501, "Not implemented for this platform")

    def _handle_disconnect(self) -> None:
        """
        Handle an HTTP disconnect request and terminate any running VPN client processes.

        Attempts to invoke `pkill` for `gpclient` and `gpservice` if available, then responds with HTTP 200 and
        body "OK".
        """
        logger.info("User requested Disconnect")
        pkill = shutil.which("pkill")
        if pkill:
            subprocess.run([pkill, "gpclient"], stderr=subprocess.DEVNULL)
            subprocess.run([pkill, "gpservice"], stderr=subprocess.DEVNULL)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def _handle_submit(self) -> None:
        """
        Handle form-encoded submissions containing either a callback URL or user-provided input and forward them to
        the service input FIFO.

        Reads the request body as application/x-www-form-urlencoded, extracts the first non-empty value from the
        `callback_url` or `user_input` fields, and, on non-Windows platforms, attempts a non-blocking write of the
        trimmed input (with a trailing newline) to FIFO_STDIN. Responds with:
        - 200 and "OK" when the write succeeds.
        - 503 when the FIFO write fails due to no reader (service not ready).
        - 501 on Windows (endpoint not implemented for this platform).
        - 400 when no input is provided.
        - 500 on unexpected errors (exception details are logged).
        """
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
            user_input = data.get("callback_url", [""])[0] or data.get("user_input", [""])[0]

            if user_input:
                logger.info(f"User submitted input (Length: {len(user_input)})")
                if sys.platform != "win32":
                    success = write_fifo_nonblocking(FIFO_STDIN, user_input.strip() + "\n")
                    if success:
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b"OK")
                    else:
                        self.send_error(503, "Service not ready (FIFO reader absent)")
                else:
                    self.send_error(501, "Not implemented for this platform")
            else:
                self.send_error(400, "Empty input")
        except Exception as e:
            logger.exception(f"Input error: {e}")
            self.send_error(500, "Internal server error")

    def do_POST(self) -> None:
        """Handle POST requests for connection control."""
        if self.path == "/connect":
            self._handle_connect()
        elif self.path == "/disconnect":
            self._handle_disconnect()
        elif self.path == "/submit":
            self._handle_submit()
        else:
            self.send_error(404, "Endpoint not found")


if __name__ == "__main__":
    os.chdir("/var/www/html")

    # Secure FIFO initialization
    init_runtime_dir()

    # START BEACON
    beacon = Beacon()
    beacon.start()

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("", PORT), Handler) as httpd:
        logger.info(f"Server listening on {PORT}")
        httpd.serve_forever()
