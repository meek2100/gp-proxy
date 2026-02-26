# File: backend/stdin_proxy.py
"""
Container Agent - Standard Input Proxy.

Bridges the Python HTTP server and the OpenConnect subprocess. It listens on a local
TCP port for sensitive authentication payloads (like passwords or SAML callbacks) submitted
via the web UI, and pipes them directly into stdout. The bash entrypoint captures this
stream and injects it securely into the running VPN client's stdin.
"""

import logging
import select
import socket
import sys

from utils import IPC_STDIN_PORT, setup_logger

logger: logging.Logger = setup_logger("stdin_proxy")


def main() -> None:
    """
    Proxy a local TCP port to this process's standard output.
    
    Binds to 127.0.0.1:IPC_STDIN_PORT, accepts incoming connections, and writes all received bytes to sys.stdout.buffer as they arrive. Transient socket errors during accept/recv are logged and the daemon continues; a KeyboardInterrupt exits the process cleanly (status 0). If binding the listen socket fails (e.g., port conflict), the function logs a fatal error and exits with status 1.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", IPC_STDIN_PORT))
            s.listen(1)

            while True:
                try:
                    # Non-blocking wait for 2 seconds to ensure interruptibility
                    r: list[socket.socket]
                    r, _, _ = select.select([s], [], [], 2.0)
                    if r:
                        c, _addr = s.accept()
                        c.settimeout(5.0)  # Prevent zombie connections from dead senders
                        with c:
                            while True:
                                data: bytes = c.recv(4096)
                                if not data:
                                    break
                                sys.stdout.buffer.write(data)
                                sys.stdout.buffer.flush()
                except (OSError, TimeoutError):  # fmt: skip
                    # Log transient socket errors and continue the daemon loop
                    logger.exception("Socket error during accept/recv")
                except KeyboardInterrupt:
                    # Honor intentional shutdowns cleanly
                    sys.exit(0)
    except OSError:
        # Only crash on unrecoverable initialization errors (e.g., port conflict)
        logger.exception(f"Fatal bind error on port {IPC_STDIN_PORT}")
        sys.exit(1)


if __name__ == "__main__":
    main()
