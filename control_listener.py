# File: control_listener.py
import os
import select
import socket
import sys


def _process_connection(c: socket.socket) -> None:
    """
    Reads from the client socket buffer, splitting on newlines to ensure
    complete commands are forwarded to stdout.
    """
    buffer: str = ""
    while True:
        data: bytes = c.recv(1024)
        if not data:
            break
        try:
            buffer += data.decode("utf-8")
            if "\n" in buffer:
                lines: list[str] = buffer.split("\n")
                # Process all fully delimited commands
                for line in lines[:-1]:
                    cleaned: str = line.strip()
                    if cleaned:
                        sys.stdout.write(cleaned + "\n")
                        sys.stdout.flush()
                # Keep the remainder fragment in the buffer
                buffer = lines[-1]
        except UnicodeDecodeError as exc:
            sys.stderr.write(f"[control_listener] Malformed input ignored: {exc}\n")
            sys.stderr.flush()
            break

    # Process any remaining buffer content after the connection cleanly closes
    cleaned_rem: str = buffer.strip()
    if cleaned_rem:
        sys.stdout.write(cleaned_rem + "\n")
        sys.stdout.flush()


def _run_server_loop(s: socket.socket) -> None:
    """
    Maintains the non-blocking accept loop for incoming IPC connections.
    """
    while True:
        try:
            # Non-blocking wait for 2 seconds to ensure interruptibility during teardown
            r: list[socket.socket]
            r, _, _ = select.select([s], [], [], 2.0)
            if r:
                c, _ = s.accept()
                c.settimeout(5.0)  # Prevent zombie connections from dead senders
                with c:
                    _process_connection(c)
        except OSError as exc:
            # Log transient socket errors and continue the daemon loop
            sys.stderr.write(f"[control_listener] Socket error: {exc}\n")
            sys.stderr.flush()
        except KeyboardInterrupt:
            # Honor intentional shutdowns
            sys.exit(0)


def main() -> None:
    """
    Initializes a local TCP socket for receiving control commands and delegates
    to the server loop. Acts as a persistent background daemon polled by the bash entrypoint.
    """
    port: int = int(os.getenv("IPC_CONTROL_PORT") or "32801")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            s.listen(1)
            _run_server_loop(s)
    except OSError as e:
        # Only crash on unrecoverable initialization errors
        sys.stderr.write(f"[control_listener] Fatal error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
