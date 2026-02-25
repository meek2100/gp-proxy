# File: backend/control_listener.py
"""
Container Agent - Control IPC Listener.

Acts as a persistent background daemon that receives control commands (like START/STOP)
over a local TCP socket from the Python HTTP server (`server.py`) and pipes them to stdout.
The `entrypoint.sh` supervisor loop polls this output to orchestrate the OpenConnect process
lifecycle safely outside the web server's execution context.
"""

import logging
import select
import socket
import sys

from utils import IPC_CONTROL_PORT, setup_logger

logger: logging.Logger = setup_logger("control_listener")


def _process_connection(c: socket.socket) -> None:
    """
    Reads from the client socket buffer into a bytearray, splitting on newlines
    to ensure complete commands are forwarded to stdout without mangling
    multi-byte UTF-8 characters across network chunk boundaries.
    """
    buffer = bytearray()
    while True:
        data: bytes = c.recv(1024)
        if not data:
            break

        buffer.extend(data)

        while b"\n" in buffer:
            line_bytes, buffer = buffer.split(b"\n", 1)
            try:
                cleaned: str = line_bytes.decode("utf-8").strip()
                if cleaned:
                    sys.stdout.write(cleaned + "\n")
                    sys.stdout.flush()
            except UnicodeDecodeError as exc:
                logger.error(f"Malformed input ignored: {exc}")

    # Process any remaining buffer content after the connection cleanly closes
    if buffer:
        try:
            cleaned_rem: str = buffer.decode("utf-8").strip()
            if cleaned_rem:
                sys.stdout.write(cleaned_rem + "\n")
                sys.stdout.flush()
        except UnicodeDecodeError as exc:
            logger.error(f"Malformed trailing input ignored: {exc}")


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
                c, _addr = s.accept()
                c.settimeout(5.0)  # Prevent zombie connections from dead senders
                with c:
                    _process_connection(c)
        except OSError as exc:
            # Log transient socket errors and continue the daemon loop
            logger.warning(f"Socket error: {exc}")
        except KeyboardInterrupt:
            # Honor intentional shutdowns
            sys.exit(0)


def main() -> None:
    """
    Initializes a local TCP socket for receiving control commands and delegates
    to the server loop. Acts as a persistent background daemon polled by the bash entrypoint.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", IPC_CONTROL_PORT))
            s.listen(1)
            _run_server_loop(s)
    except OSError as e:
        # Only crash on unrecoverable initialization errors
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
