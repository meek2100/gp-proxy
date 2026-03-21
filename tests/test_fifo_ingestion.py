import os
import time
import socket
import threading
import subprocess
import pytest
import sys
from backend.utils import IPC_STDIN_PORT

def test_pipe_pipeline_flow():
    """
    Verifies that data sent via IPC reaches a consumer reading from a pipe.
    Simulates the entrypoint.sh architecture using cross-platform pipes.
    """
    # Use os.pipe() which works on both Unix and Windows for redirection
    r, w = os.pipe()

    received_data = []

    def mock_client_reader():
        # Simulation of the background reader
        with os.fdopen(r, 'rb') as f:
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
        env={**os.environ, "PYTHONPATH": "."}
    )

    try:
        time.sleep(1) # Wait for proxy to bind
        
        # Send data to the proxy socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("127.0.0.1", IPC_STDIN_PORT))
            test_payload = "globalprotectcallback://test-token\n"
            s.sendall(test_payload.encode())

        # Give it a moment to traverse
        time.sleep(1)
        
        assert "globalprotectcallback://test-token" in received_data
        
    finally:
        proxy_proc.terminate()
        proxy_proc.wait()
        os.close(w) # Reader will see EOF

if __name__ == "__main__":
    pytest.main([__file__])
