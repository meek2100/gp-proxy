# File: backend/utils.py
"""
Container Agent - Shared Utilities.

Provides centralized configuration, logging initialization, and IPC networking
tools to ensure consistency across all Python background daemons.
"""

import logging
import os
import socket
from pathlib import Path

# --- Global Paths ---
RUNTIME_DIR: Path = Path("/tmp/gp-runtime")
CLIENT_LOG: Path = Path("/tmp/gp-logs/gp-client.log")
SERVICE_LOG: Path = Path("/tmp/gp-logs/gp-service.log")


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
    If /tmp/gp-logs exists, output is written to the service log file; otherwise
    output goes to the standard stream. Repeated calls for the same logger name
    will not add duplicate handlers.

    Parameters:
        name (str): Name of the logger to create or retrieve.

    Returns:
        logging.Logger: The configured logger instance.
    """
    log_level: str = os.getenv("LOG_LEVEL", "INFO").upper()

    logger: logging.Logger = logging.getLogger(name)

    # Prevent duplicate handlers if called multiple times in the same process
    # Uses hasHandlers() to properly inspect the entire logger hierarchy
    logger.setLevel(log_level)
    if not logger.handlers:
        logger.propagate = False
        formatter: logging.Formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ"
        )

        handler: logging.Handler
        if Path("/tmp/gp-logs").exists():
            handler = logging.FileHandler(SERVICE_LOG)
        else:
            handler = logging.StreamHandler()

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
