# File: control_listener.py
import os
import select
import socket
import sys


def main() -> None:
    """
    Listens on a local TCP socket for a control command with a strict timeout.

    This script acts as a persistent background process polled by the bash entrypoint's
    main watchdog loop. It waits indefinitely for the Python HTTP server to send a
    control command (like "START"). When a command is received, it prints it to stdout
    where the bash pipe reads it. The loop guarantees it remains alive to service
    subsequent connection requests.

    Returns:
        None: Outputs received commands to stdout until process termination.
    """
    port: int = int(os.getenv("IPC_CONTROL_PORT") or "32801")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            s.listen(1)

            while True:
                try:
                    # Non-blocking wait for 2 seconds to ensure interruptibility during teardown
                    r: list[socket.socket]
                    r, _, _ = select.select([s], [], [], 2.0)
                    if r:
                        c: socket.socket
                        c, _ = s.accept()
                        c.settimeout(5.0)  # Prevent zombie connections from dead senders
                        with c:
                            data: bytes = c.recv(1024)
                            if data:
                                try:
                                    # Use sys.stdout to avoid Ruff T201 'print' violations
                                    sys.stdout.write(data.decode("utf-8").strip() + "\n")
                                    sys.stdout.flush()
                                except UnicodeDecodeError as exc:
                                    sys.stderr.write(f"[control_listener] Malformed input ignored: {exc}\n")
                                    sys.stderr.flush()
                except OSError as exc:
                    # Log transient socket errors and continue the daemon loop
                    sys.stderr.write(f"[control_listener] Socket error: {exc}\n")
                    sys.stderr.flush()
                except KeyboardInterrupt:
                    # Honor intentional shutdowns
                    sys.exit(0)
                except SystemExit:
                    # Honor intentional shutdowns
                    sys.exit(0)
    except OSError as e:
        # Only crash on unrecoverable initialization errors
        sys.stderr.write(f"[control_listener] Fatal error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
