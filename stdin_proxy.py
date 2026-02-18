# File: stdin_proxy.py
import socket
import sys


def main() -> None:
    """Proxies incoming TCP socket payloads directly to standard output."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 32802))
        s.listen(1)
        while True:
            try:
                c, _ = s.accept()
                with c:
                    data = c.recv(4096)
                    if data:
                        sys.stdout.buffer.write(data)
                        sys.stdout.flush()
            except Exception:
                # Exit cleanly if the process is terminated or the pipe breaks
                break


if __name__ == "__main__":
    main()
