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
from pathlib import Path
from typing import Any, TypedDict

# --- Configuration ---
PORT: int = 8001
UDP_BEACON_PORT: int = 32800
RUNTIME_DIR: Path = Path("/tmp/gp-runtime")
IPC_STDIN_PORT: int = int(os.getenv("IPC_STDIN_PORT", "32802"))
IPC_CONTROL_PORT: int = int(os.getenv("IPC_CONTROL_PORT", "32801"))
MODE_FILE: Path = RUNTIME_DIR / "gp-mode"
CLIENT_LOG: Path = Path("/tmp/gp-logs/gp-client.log")
SERVICE_LOG: Path = Path("/tmp/gp-logs/gp-service.log")

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
    vpn_mode: str  # The configured network mode (standard, socks, gateway)
    server_ip: str  # The dynamically detected best outbound IP


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
        and sets up I/O caching properties.
        """
        self._lock: threading.Lock = threading.Lock()
        self._last_state: str | None = None

        # Caching mechanisms to optimize I/O
        self._log_mtime: float = -1.0
        self._log_size: int = -1
        self._cached_analysis: LogAnalysis = {
            "state": "idle",
            "prompt": "",
            "prompt_type": "text",
            "options": [],
            "error": None,
            "sso_url": "",
        }
        self._cached_log: str = ""

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
        with self._lock:
            try:
                st = log_path.stat()
                if st.st_mtime == self._log_mtime and st.st_size == self._log_size:
                    return self._cached_analysis, self._cached_log

                # Update cache signature
                self._log_mtime = st.st_mtime
                self._log_size = st.st_size

                file_size: int = st.st_size
                # Open in binary mode to prevent UTF-8 boundary splitting when seeking
                with open(log_path, "rb") as f:
                    if file_size > 65536:
                        f.seek(file_size - 65536)
                        f.readline()  # Align to the next newline boundary

                    data: str = f.read().decode("utf-8", errors="replace")
                    lines: list[str] = data.splitlines(keepends=True)
                    if lines and not lines[-1].endswith("\n"):
                        lines.pop()

                    lines = lines[-300:]
                    log_content = "".join(lines)

                    # Analyze the full log buffer to ensure rapid state transitions aren't swallowed
                    clean_lines: list[str] = [strip_ansi(line).strip() for line in lines]

                    analysis = analyze_log_lines(clean_lines, log_content)

                    self._cached_analysis = analysis
                    self._cached_log = log_content
                    return analysis, log_content

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
            except Exception as e:
                logger.exception(f"Log parse error: {e}")
                return self._cached_analysis, self._cached_log


state_manager = StateManager()


def get_best_ip() -> str:
    """
    Selects the container's primary outbound IP address.
    Attempts to determine the best local IPv4 address by creating a UDP socket.

    Returns:
        str: The chosen IPv4 address as a string; "127.0.0.1" on failure.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return str(s.getsockname()[0])
    except OSError:
        return "127.0.0.1"


# --- UDP BEACON ---
class Beacon(threading.Thread):
    """
    Background thread that listens for UDP broadcast packets.
    Used by the Desktop Client to auto-discover this container's IP address
    and session token on the local network without user intervention.
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
        Listen for "GP_DISCOVER" UDP packets and respond with a JSON payload containing the best IP, server port,
        hostname, and the required API token for zero-touch authentication.
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
                            "token": os.getenv("API_TOKEN", ""),
                        }
                    )
                    self.sock.sendto(response.encode("utf-8"), addr)
            except Exception as e:
                logger.error(f"Beacon error: {e}")


# --- Logging Setup ---
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "DEBUG").upper(),
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    handlers=[
        logging.FileHandler(SERVICE_LOG) if Path("/tmp/gp-logs").exists() else logging.StreamHandler(),
    ],
)
logger: logging.Logger = logging.getLogger()


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
    """Forward scans the logs to gather all available gateway options."""
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
    """Extracts the most recent valid SSO URL from the full log content."""
    found_urls: list[str] = URL_PATTERN.findall(full_log_content)
    if found_urls:
        local_urls: list[str] = [u for u in found_urls if str(port) not in u and "127.0.0.1" not in u]
        return local_urls[-1] if local_urls else found_urls[-1]
    return ""


def _evaluate_line_state(line: str, clean_lines: list[str], analysis_acc: LogAnalysis) -> bool:
    """
    Evaluates a single chronological log line and mutates the state dictionary directly.
    Returns True if state found.
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
    vpn_mode: str = os.getenv("VPN_MODE", "standard")
    server_ip: str = get_best_ip()

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
                    "server_ip": server_ip,
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
        "server_ip": server_ip,
    }


def init_runtime_dir() -> None:
    """
    Create the secure runtime directory.
    On non-Windows systems, creates RUNTIME_DIR with mode 0o700.
    """
    try:
        if sys.platform != "win32":
            RUNTIME_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        else:
            RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.exception(f"Failed to initialize runtime dir: {e}")


def send_ipc_message(port: int, data: str) -> bool:
    """
    Perform a cross-platform socket connection to dispatch an IPC payload to the supervisor loop.
    Replaces POSIX FIFOs to guarantee out-of-container testing compatibility on Windows.

    Parameters:
        port (int): The local TCP port of the target IPC proxy.
        data (str): UTF-8 text to write into the socket.

    Returns:
        bool: `True` if the data was written successfully, `False` if no listener was available.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect(("127.0.0.1", port))
            s.sendall(data.encode("utf-8"))
        return True
    except OSError as e:
        logger.warning(f"IPC connection failed on port {port}: {e}")
        return False


def _kill_and_poll() -> None:
    """
    Terminates active OpenConnect processes and actively polls until they exit
    to prevent race conditions when generating new VPN sessions.
    Strictly typed to prevent Subprocess NoneType execution crashes.
    """
    pkill: str | None = shutil.which("pkill")
    if pkill is not None:
        subprocess.run([pkill, "gpclient"], stderr=subprocess.DEVNULL)
        subprocess.run([pkill, "gpservice"], stderr=subprocess.DEVNULL)

        pgrep: str | None = shutil.which("pgrep")
        if pgrep is not None:
            for _ in range(50):
                # Strict Python 3.14 types - Subprocess run output is implicitly bytes without text=True
                res1: subprocess.CompletedProcess[bytes] = subprocess.run(
                    [pgrep, "gpclient"], stdout=subprocess.DEVNULL
                )
                res2: subprocess.CompletedProcess[bytes] = subprocess.run(
                    [pgrep, "gpservice"], stdout=subprocess.DEVNULL
                )
                if res1.returncode != 0 and res2.returncode != 0:
                    break
                time.sleep(0.1)
        else:
            time.sleep(1.0)


class Handler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP Request Handler for the VPN Web UI.
    Handles API endpoints for status, connections, and log downloads.
    """

    def _is_authorized(self) -> bool:
        """
        Validates the request against the configured pre-shared API_TOKEN.
        Enforces a strict fail-closed zero-trust model if no token is configured.

        Returns:
            bool: `True` if authorized, `False` otherwise.
        """
        expected_token = os.getenv("API_TOKEN")
        if not expected_token:
            return False

        auth_header = self.headers.get("Authorization", "")
        if auth_header == f"Bearer {expected_token}":
            return True

        return False

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """
        Log HTTP requests to the module logger. Avoids index errors on missing args.
        """
        if args and "status.json" in str(args[0]):
            logger.debug("%s - - %s", self.client_address[0], format % args)
        else:
            logger.info("%s - - %s", self.client_address[0], format % args)

    def end_headers(self) -> None:
        """
        Inject optimal caching headers before completing the header block.
        """
        base_path: str = urllib.parse.urlparse(self.path).path

        if base_path in ["/", "/index.html", "/status.json"]:
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
        elif base_path.endswith((".css", ".js", ".png", ".ico")):
            self.send_header("Cache-Control", "public, max-age=31536000, immutable")

        super().end_headers()

    def do_GET(self) -> None:
        """
        Handle incoming HTTP GET requests for status, log download, and static file serving.
        """
        if self.path.startswith("/status.json"):
            if not self._is_authorized():
                self.send_error(401, "Unauthorized")
                return
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(get_vpn_state()).encode("utf-8"))
            return

        if self.path == "/download_logs":
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
            except Exception:
                logger.debug("Error while streaming logs to client (connection may have closed)")
            return

        if self.path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def _handle_connect(self) -> None:
        """
        Handle an HTTP request to initiate a VPN connection.
        Ensures existing processes are dead before writing to the control IPC.
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
        Safely falls back on dictionary access to prevent IndexError on empty bodies.
        """
        try:
            data: dict[str, list[str]] = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))

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
        except Exception:
            logger.exception("Input error")
            self.send_error(500, "Internal server error")

    def do_POST(self) -> None:
        """
        Handle incoming HTTP POST requests for connection control routing.
        Validates the authorization token before routing to explicit handlers.
        Globally enforces payload size limits.
        """
        if not self._is_authorized():
            self.send_error(401, "Unauthorized")
            return

        try:
            length: int = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        except TypeError:
            length = 0

        if length > 8192:  # Prevent memory exhaustion (DOS)
            self.send_error(413, "Payload Too Large")
            return

        if self.path == "/connect":
            self._handle_connect()
        elif self.path == "/disconnect":
            self._handle_disconnect()
        elif self.path == "/submit":
            self._handle_submit(length)
        else:
            self.send_error(404, "Endpoint not found")


class VPNServer(socketserver.ThreadingTCPServer):
    """Custom ThreadingTCPServer that safely enables address reuse."""

    allow_reuse_address = True


if __name__ == "__main__":
    target_dir: Path = Path("/var/www/html")
    if target_dir.exists() and target_dir.is_dir():
        os.chdir(target_dir)
    else:
        # Fallback for local Windows development environments
        local_web_dir = Path(__file__).parent / "web"
        if local_web_dir.exists() and local_web_dir.is_dir():
            os.chdir(local_web_dir)
        else:
            os.chdir(Path(__file__).parent)

    init_runtime_dir()

    beacon: Beacon = Beacon()
    beacon.start()

    with VPNServer(("", PORT), Handler) as httpd:
        logger.info(f"Server listening on {PORT}")
        httpd.serve_forever()
