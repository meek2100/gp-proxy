# File: tests/test_fifo_ingestion.py
"""
Tests for verifying that data sent via IPC reaches a consumer reading from a pipe.
"""

import os
import socket
import subprocess
import sys
import threading
import time

import pytest

from backend.utils import IPC_STDIN_PORT


def test_pipe_pipeline_flow() -> None:
    """
    Verifies that data sent via IPC reaches a consumer reading from a pipe.
    Simulates the entrypoint.sh architecture using cross-platform pipes.
    """
    # Use os.pipe() which works on both Unix and Windows for redirection
    r, w = os.pipe()

    received_data: list[str] = []

    def mock_client_reader() -> None:
        # Simulation of the background reader
        with os.fdopen(r, "rb") as f:
            while True:
                line = f.readline()
                if not line:
                    break
                received_data.append(line.decode().strip())

    client_thread = threading.Thread(target=mock_client_reader)
    client_thread.daemon = True
    client_thread.start()

    # Start the stdin_proxy in a subprocess
    # We pass the write end of the pipe as stdout
    proxy_proc = subprocess.Popen(
        [sys.executable, "-u", "backend/stdin_proxy.py"],
        stdout=w,
        env=dict(os.environ, PYTHONPATH="."),
    )

    try:
        # Wait for proxy to bind using a deadline-based probe
        deadline = time.time() + 5.0
        bound = False
        while time.time() < deadline:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    s.connect(("127.0.0.1", IPC_STDIN_PORT))
                    bound = True
                    break
            except OSError, TimeoutError:
                time.sleep(0.1)

        if not bound:
            raise AssertionError("stdin_proxy failed to bind within 5 seconds")

        # Send data to the proxy socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("127.0.0.1", IPC_STDIN_PORT))
            test_payload = "globalprotectcallback://test-token\n"
            s.sendall(test_payload.encode())

        # Poll for delivery
        deadline = time.time() + 5.0
        received = False
        while time.time() < deadline:
            if "globalprotectcallback://test-token" in received_data:
                received = True
                break
            time.sleep(0.1)

        assert received, f"Data failed to reach consumer! Got: {received_data}"

    finally:
        proxy_proc.terminate()
        proxy_proc.wait()
        os.close(w)  # Reader will see EOF


if __name__ == "__main__":
    pytest.main([__file__])  # pyright: ignore[reportUnknownMemberType]
