# File: tests/test_callback_e2e.py
"""
Tests for verifying end-to-end callback content delivery through the IPC pipeline.
"""

import os
import socket
import subprocess
import sys
import threading
import time

import pytest

from backend.utils import IPC_STDIN_PORT


def test_callback_content_verification():
    """
    Verifies that the exact callback content travels from the server/socket
    all the way to a consumer using in-memory verification to avoid Windows file locks.
    """
    r, w = os.pipe()

    # Use a real globalprotectcallback string
    expected_callback = "globalprotectcallback://lehvpn.snapone.com/SAML20/SP/ACS?v=1&t=12345"
    received_content = []

    def mock_gpclient_consumer():
        with os.fdopen(r, "rb") as f_in:
            while True:
                line = f_in.readline()
                if not line:
                    break
                received_content.append(line.decode().strip())

    consumer_thread = threading.Thread(target=mock_gpclient_consumer)
    consumer_thread.daemon = True
    consumer_thread.start()

    # Start stdin_proxy redirected to pipe
    proxy_proc = subprocess.Popen(
        [sys.executable, "-u", "backend/stdin_proxy.py"], stdout=w, env={**os.environ, "PYTHONPATH": "."}
    )

    try:
        time.sleep(1)  # Wait for proxy

        # Simulate the server's send_ipc_message with the actual callback
        payload = expected_callback.strip().replace("\r", "").replace("\n", "") + "\n"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("127.0.0.1", IPC_STDIN_PORT))
            s.sendall(payload.encode())

        # Give it time to flush
        time.sleep(2)

        assert expected_callback in received_content, f"Content mismatch! Got: {received_content}"

    finally:
        proxy_proc.terminate()
        proxy_proc.wait()
        os.close(w)


if __name__ == "__main__":
    pytest.main([__file__])
