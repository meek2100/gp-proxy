# File: stdin_proxy.py
import os
import socket
import sys


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
    port: int = int(os.getenv("IPC_STDIN_PORT", "32802"))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(1)
        while True:
            try:
                c: socket.socket
                c, _ = s.accept()
                with c:
                    data: bytes = c.recv(4096)
                    if data:
                        sys.stdout.buffer.write(data)
                        sys.stdout.buffer.flush()
            except Exception:
                # Exit cleanly if the process is terminated or the pipe breaks
                break


if __name__ == "__main__":
    main()
