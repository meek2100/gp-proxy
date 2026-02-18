# File: control_listener.py
import os
import select
import socket
import sys


def main() -> None:
    """
    Listens on a local TCP socket for a control command with a strict timeout.

    This script is polled by the bash entrypoint's main watchdog loop. It waits
    up to 2 seconds for the Python HTTP server to send a control command
    (like "START"). If a command is received, it prints it to stdout for bash
    to evaluate. If nothing is received, it exits cleanly to allow the bash loop
    to continue its other watchdog duties.

    Returns:
        None: Outputs the received command to stdout via sys.exit/sys.stdout.
    """
    port: int = int(os.getenv("IPC_CONTROL_PORT", "32801"))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            s.listen(1)

            # Non-blocking wait for 2 seconds
            r: list[socket.socket]
            r, _, _ = select.select([s], [], [], 2.0)
            if r:
                c: socket.socket
                c, _ = s.accept()
                with c:
                    data: bytes = c.recv(1024)
                    # Use sys.stdout to avoid Ruff T201 'print' violations
                    sys.stdout.write(data.decode("utf-8").strip() + "\n")
                    sys.stdout.flush()
    except Exception:
        sys.exit(0)


if __name__ == "__main__":
    main()
