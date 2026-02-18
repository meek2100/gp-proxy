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
from pathlib import Path
from typing import Any, TypedDict

# --- Configuration ---
PORT: int = 8001
UDP_BEACON_PORT: int = 32800
RUNTIME_DIR: Path = Path("/tmp/gp-runtime")
FIFO_STDIN: Path = RUNTIME_DIR / "gp-stdin"
FIFO_CONTROL: Path = RUNTIME_DIR / "gp-control"
MODE_FILE: Path = RUNTIME_DIR / "gp-mode"
CLIENT_LOG: Path = Path("/tmp/gp-logs/gp-client.log")
SERVICE_LOG: Path = Path("/tmp/gp-logs/gp-service.log")

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
        self._lock: threading.Lock = threading.Lock()
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
        """
        super().__init__()
        self.daemon = True
        self.sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", UDP_BEACON_PORT))

    def run(self) -> None:
        """
        Listen for "GP_DISCOVER" UDP packets and respond with a JSON payload containing the best IP, server port,
        and hostname.
        """
        logger.info(f"UDP Beacon active on port {UDP_BEACON_PORT}")
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                message: str = data.decode("utf-8").strip()

                if message == "GP_DISCOVER":
                    response: str = json.dumps(
                        {"ip": self.get_best_ip(), "port": PORT, "hostname": socket.gethostname()}
                    )
                    self.sock.sendto(response.encode("utf-8"), addr)
            except Exception as e:
                logger.error(f"Beacon error: {e}")

    def get_best_ip(self) -> str:
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


class VPNState(TypedDict):
    """Type definition for the VPN state response sent to the frontend."""

    state: str
    url: str
    prompt: str
    input_type: str
    options: list[str]
    error: str | None
    log: str | None
    debug_mode: bool
    vpn_mode: str


class LogAnalysis(TypedDict):
    """Internal type for the result of log analysis."""

    state: str
    prompt: str
    prompt_type: str
    options: list[str]
    error: str | None
    sso_url: str


def strip_ansi(text: str) -> str:
    """
    Remove ANSI escape sequences (colors, cursor movements, and line-control codes) from the given text.

    Parameters:
        text (str): The raw text containing ANSI codes.

    Returns:
        str: The input string with ANSI escape sequences removed.
    """
    return ANSI_ESCAPE.sub("", text)


def _check_connected(clean_lines: list[str]) -> LogAnalysis | None:
    """
    Determine whether the provided cleaned log lines indicate a successful VPN connection.

    Parameters:
        clean_lines (list[str]): Log lines stripped of ANSI sequences.

    Returns:
        LogAnalysis | None: Connected state mapping if found, otherwise None.
    """
    for line in reversed(clean_lines):
        if "Connected" in line and "to" in line:
            return {
                "state": "connected",
                "prompt": "",
                "prompt_type": "text",
                "options": [],
                "error": None,
                "sso_url": "",
            }
    return None


def _check_error(clean_lines: list[str]) -> LogAnalysis | None:
    """
    Check for specific failure messages in the log lines.

    Parameters:
        clean_lines (list[str]): Log lines stripped of ANSI sequences.

    Returns:
        LogAnalysis | None: Error state mapping if a failure is detected, otherwise None.
    """
    for line in reversed(clean_lines):
        if "Login failed" in line or "GP response error" in line:
            error_msg: str = line
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
        LogAnalysis | None: `LogAnalysis` with state `"input"` and prompt fields, or None.
    """
    for line in reversed(clean_lines):
        if "Which gateway do you want to connect to" in line:
            input_options: list[str] = []
            seen: set[str] = set()
            for scan_line in clean_lines:
                m = GATEWAY_REGEX.search(scan_line)
                if m:
                    opt: str = m.group(1).strip()
                    if opt not in seen and "Which gateway" not in opt:
                        seen.add(opt)
                        input_options.append(opt)
            return {
                "state": "input",
                "prompt": "Select Gateway",
                "prompt_type": "select",
                "options": sorted(input_options),
                "error": None,
                "sso_url": "",
            }

        if "password:" in line.lower():
            return {
                "state": "input",
                "prompt": "Enter Password",
                "prompt_type": "password",
                "options": [],
                "error": None,
                "sso_url": "",
            }

        if "username:" in line.lower():
            return {
                "state": "input",
                "prompt": "Enter Username",
                "prompt_type": "text",
                "options": [],
                "error": None,
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
        LogAnalysis: Mapping representing the current operational state of the VPN.
    """
    res: LogAnalysis | None = _check_connected(clean_lines)
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
        "error": None,
        "sso_url": "",
    }

    input_res: LogAnalysis | None = _check_input_request(clean_lines)
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

        found_urls: list[str] = URL_PATTERN.findall(full_log_content)
        if found_urls:
            local_urls: list[str] = [u for u in found_urls if str(PORT) not in u and "127.0.0.1" not in u]
            analysis_acc["sso_url"] = local_urls[-1] if local_urls else found_urls[-1]

    return analysis_acc


def get_vpn_state() -> VPNState:
    """
    Determine the current VPN service status by inspecting the runtime mode file and recent client log output.

    Reads MODE_FILE (if present) to detect an explicit "idle" mode and otherwise parses the tail of CLIENT_LOG to
    extract connection state, prompts, options, errors, and SSO URLs. May update the global state_manager with the
    detected state.

    Returns:
        VPNState: A dictionary containing the serializable current state.
    """
    is_debug: bool = os.getenv("LOG_LEVEL", "INFO").upper() in ["DEBUG", "TRACE"]
    vpn_mode: str = os.getenv("VPN_MODE", "standard")

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
                }
        except Exception:
            logger.debug("Failed to read MODE_FILE, proceeding with log analysis")

    log_content: str = ""
    analysis: LogAnalysis = {
        "state": "idle",
        "prompt": "",
        "prompt_type": "text",
        "options": [],
        "error": None,
        "sso_url": "",
    }

    if CLIENT_LOG.exists():
        try:
            file_size: int = CLIENT_LOG.stat().st_size
            with open(CLIENT_LOG, errors="replace") as f:
                if file_size > 65536:
                    f.seek(file_size - 65536)
                    f.readline()

                data: str = f.read()

                # Prevent parsing broken partial lines if file is being actively written to
                lines: list[str] = data.splitlines(keepends=True)
                if lines and not lines[-1].endswith("\n"):
                    lines.pop()

                lines = lines[-300:]
                log_content = "".join(lines)
                clean_lines: list[str] = [strip_ansi(line).strip() for line in lines[-100:]]

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
    exist as FIFOs with mode 0o600.
    """
    if sys.platform != "win32":
        try:
            RUNTIME_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
            for fifo_path in [FIFO_STDIN, FIFO_CONTROL]:
                try:
                    os.mkfifo(fifo_path, mode=0o600)
                except FileExistsError:
                    if not stat.S_ISFIFO(fifo_path.stat().st_mode):
                        logger.error(f"{fifo_path} exists but is not a FIFO.")
        except Exception:
            logger.exception("Failed to initialize runtime dir")


def write_fifo_nonblocking(fifo_path: Path, data: str) -> bool:
    """
    Perform a non-blocking write of `data` to the FIFO at `fifo_path`.

    Parameters:
        fifo_path (Path): Path to the FIFO (named pipe) to write to.
        data (str): UTF-8 text to write into the FIFO.

    Returns:
        bool: `True` if the data was written successfully, `False` if no reader was available or an error occurred.
    """
    fd: int | None = None
    try:
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


def _kill_and_poll() -> None:
    """
    Terminates active OpenConnect processes and actively polls until they exit
    to prevent race conditions when generating new VPN sessions.
    """
    pkill: str | None = shutil.which("pkill")
    if pkill:
        subprocess.run([pkill, "gpclient"], stderr=subprocess.DEVNULL)
        subprocess.run([pkill, "gpservice"], stderr=subprocess.DEVNULL)

        pgrep: str | None = shutil.which("pgrep")
        if pgrep:
            for _ in range(20):
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

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """
        Log HTTP requests to the module logger.
        """
        if "status.json" in args[0]:
            logger.debug("%s - - %s", self.client_address[0], format % args)
        else:
            logger.info("%s - - %s", self.client_address[0], format % args)

    def end_headers(self) -> None:
        """
        Inject optimal caching headers before completing the header block.
        Works in tandem with Dockerfile build-time query strings to provide
        instant page loads without serving stale assets.
        """
        # Parse the raw path to ignore query parameters (like ?v=1738200)
        base_path: str = urllib.parse.urlparse(self.path).path

        if base_path in ["/", "/index.html", "/status.json"]:
            # Never cache the HTML or dynamic status payload
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
        elif base_path.endswith((".css", ".js", ".png", ".ico")):
            # Cache static assets for 1 year (relying on build-time hashes to bust cache)
            self.send_header("Cache-Control", "public, max-age=31536000, immutable")

        super().end_headers()

    def do_GET(self) -> None:
        """
        Handle incoming HTTP GET requests for status, log download, and static file serving.
        """
        if self.path.startswith("/status.json"):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
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

    def _handle_connect(self) -> None:
        """
        Handle an HTTP request to initiate a VPN connection.
        Ensures existing processes are dead before writing to the control FIFO.
        """
        logger.info("User requested Connection")
        _kill_and_poll()

        if sys.platform != "win32":
            success: bool = write_fifo_nonblocking(FIFO_CONTROL, "START\n")
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
        Handle an HTTP disconnect request and cleanly terminate VPN client processes.
        """
        logger.info("User requested Disconnect")
        _kill_and_poll()

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def _handle_submit(self) -> None:
        """
        Handle form-encoded submissions containing either a callback URL or user-provided input.
        Forwards the payload to the service input FIFO.
        """
        try:
            length: int = int(self.headers.get("Content-Length", 0))
            data: dict[str, list[str]] = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
            user_input_list: list[str] = data.get("callback_url", [""])
            if not user_input_list[0]:
                user_input_list = data.get("user_input", [""])
            user_input: str = user_input_list[0]

            if user_input:
                logger.info(f"User submitted input (Length: {len(user_input)})")
                if sys.platform != "win32":
                    success: bool = write_fifo_nonblocking(FIFO_STDIN, user_input.strip() + "\n")
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
        except Exception:
            logger.exception("Input error")
            self.send_error(500, "Internal server error")

    def do_POST(self) -> None:
        """Handle POST requests for connection control routing."""
        if self.path == "/connect":
            self._handle_connect()
        elif self.path == "/disconnect":
            self._handle_disconnect()
        elif self.path == "/submit":
            self._handle_submit()
        else:
            self.send_error(404, "Endpoint not found")


if __name__ == "__main__":
    target_dir: Path = Path("/var/www/html")
    if target_dir.exists() and target_dir.is_dir():
        os.chdir(str(target_dir))
    else:
        # Fallback for local Windows development environments
        local_web_dir = Path(__file__).parent / "web"
        if local_web_dir.exists() and local_web_dir.is_dir():
            os.chdir(str(local_web_dir))
        else:
            os.chdir(str(Path(__file__).parent))

    init_runtime_dir()

    beacon: Beacon = Beacon()
    beacon.start()

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("", PORT), Handler) as httpd:
        logger.info(f"Server listening on {PORT}")
        httpd.serve_forever()
