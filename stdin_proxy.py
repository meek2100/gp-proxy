# File: stdin_proxy.py
import logging
import os
import select
import socket
import sys

# Configure standard logging to match the project's formatting requirements
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger: logging.Logger = logging.getLogger(__name__)


def main() -> None:
    """
    Proxies incoming TCP socket payloads directly to standard output.

    This script acts as a bridge between the Python HTTP server and the
    OpenConnect subprocess. It listens on a local TCP port and pipes any
    received data (like passwords or 2FA codes) directly into stdout, which
    the bash entrypoint captures and pipes into the VPN client.

    Returns:
        None: Exits cleanly when the socket is closed or the process terminates.
    """
    port: int = int(os.getenv("IPC_STDIN_PORT") or "32802")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            s.listen(1)

            while True:
                try:
                    # Non-blocking wait for 2 seconds to ensure interruptibility
                    r: list[socket.socket]
                    r, _, _ = select.select([s], [], [], 2.0)
                    if r:
                        c, _ = s.accept()
                        c.settimeout(5.0)  # Prevent zombie connections from dead senders
                        with c:
                            while True:
                                data: bytes = c.recv(4096)
                                if not data:
                                    break
                                sys.stdout.buffer.write(data)
                                sys.stdout.buffer.flush()
                except OSError:
                    # Log transient socket errors and continue the daemon loop
                    logger.exception("Socket error during accept/recv")
                except KeyboardInterrupt:
                    # Honor intentional shutdowns cleanly
                    sys.exit(0)
    except OSError:
        # Only crash on unrecoverable initialization errors (e.g., port conflict)
        logger.exception(f"Fatal bind error on port {port}")
        sys.exit(1)


if __name__ == "__main__":
    main()
