# File: backend/utils.py
"""
Container Agent - Shared Utilities.

Provides centralized configuration, logging initialization, and IPC networking
tools to ensure consistency across all Python background daemons. Implements
safe cross-platform pathing and thread-safe singleton patterns.
"""

import logging
import os
import socket
import sys
import tempfile
import threading
from pathlib import Path

# --- Global Paths & Thread Locks ---
_is_win: bool = sys.platform == "win32"
_tmp_base: Path = Path(tempfile.gettempdir()) if _is_win else Path("/tmp")

# Fallbacks to user temp directories during local Windows development
RUNTIME_DIR: Path = Path(os.getenv("GP_RUNTIME_DIR", str(_tmp_base / "gp-runtime")))
_log_dir: Path = Path(os.getenv("GP_LOG_DIR", str(_tmp_base / "gp-logs")))
CLIENT_LOG: Path = _log_dir / "gp-client.log"
SERVICE_LOG: Path = _log_dir / "gp-service.log"

_logger_lock: threading.Lock = threading.Lock()


# --- IPC Port Configuration ---
def _parse_port(env_var: str, default: int) -> int:
    """
    Parse an environment variable as a TCP port number, returning a safe default when absent or invalid.

    Parameters:
        env_var (str): Name of the environment variable to read.
        default (int): Port to return if the environment value is missing, non-integer, or outside 1-65535.

    Returns:
        int: The parsed port (1-65535) if valid, otherwise `default`.
    """
    val = os.getenv(env_var, "").strip()
    if not val:
        return default
    try:
        port = int(val)
    except ValueError:
        return default
    return port if 1 <= port <= 65535 else default


IPC_CONTROL_PORT: int = _parse_port("IPC_CONTROL_PORT", 32801)
IPC_STDIN_PORT: int = _parse_port("IPC_STDIN_PORT", 32802)


def setup_logger(name: str) -> logging.Logger:
    """
    Create or retrieve a logger configured with standardized formatting and handlers.

    Log level is taken from the LOG_LEVEL environment variable (default "INFO").
    If the designated log directory exists, output is written to the service log file;
    otherwise, output goes to the standard stream. Thread-safe to prevent duplicate
    handlers during highly concurrent API request bursts.

    Parameters:
        name (str): Name of the logger to create or retrieve.

    Returns:
        logging.Logger: The configured logger instance.
    """
    log_level: str = os.getenv("LOG_LEVEL", "INFO").upper()

    logger: logging.Logger = logging.getLogger(name)
    logger.setLevel(log_level)

    # Thread-safe lock prevents race conditions instantiating duplicate file handlers
    with _logger_lock:
        if not logger.handlers:
            logger.propagate = False
            formatter: logging.Formatter = logging.Formatter(
                fmt="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ"
            )

            handler: logging.Handler
            if _log_dir.exists():
                handler = logging.FileHandler(SERVICE_LOG)
            else:
                handler = logging.StreamHandler()

            handler.setLevel(log_level)
            handler.setFormatter(formatter)
            logger.addHandler(handler)

    return logger


def send_ipc_message(port: int, data: str) -> bool:
    """
    Perform a cross-platform socket connection to dispatch an IPC payload.
    Utilizes local TCP sockets as the primary production IPC strategy, ensuring robust
    compatibility across containerized and native execution environments.

    Parameters:
        port (int): The local TCP port of the target IPC proxy.
        data (str): UTF-8 text to write into the socket.

    Returns:
        bool: `True` if the data was written successfully, `False` if no listener was available.
    """
    logger: logging.Logger = setup_logger("ipc_client")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect(("127.0.0.1", port))
            s.sendall(data.encode("utf-8"))
    except OSError as e:
        logger.warning(f"IPC connection failed on port {port}: {e}")
        return False
    else:
        return True
