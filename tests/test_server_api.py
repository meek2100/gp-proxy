# File: tests/test_server_api.py
# pyright: reportPrivateUsage=false
"""Integration and API handler tests for server.py.

Covers HTTP APIs, OS teardown functions, and the UDP beacon.
"""

import base64
import json
import os
import sys
from io import BytesIO
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

# Add backend directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

import server


class TestBeacon:
    """Test UDP Beacon background thread."""

    def test_beacon_initialization_and_run(self) -> None:
        """Test the beacon's initialization, socket binding, and main loop with a response."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket

            beacon = server.Beacon()
            assert beacon.daemon is True
            mock_socket.bind.assert_called_with(("", server.UDP_BEACON_PORT))

            # Simulate one valid message and then raise an exception to trigger the exception branch
            mock_socket.recvfrom.side_effect = [
                (b"GP_DISCOVER", ("127.0.0.1", 12345)),
                OSError("Stop loop"),
            ]

            with patch("server.get_best_ip", return_value="192.168.1.5"):
                with patch("socket.gethostname", return_value="test-host"):
                    with patch("server.logger") as mock_logger:
                        # Break the infinite loop AFTER the logger is called
                        mock_logger.exception.side_effect = KeyboardInterrupt("Stop loop")
                        with patch("time.sleep"):  # Mock sleep from exception block
                            # Let it run and crash to exit
                            try:
                                beacon.run()
                            except KeyboardInterrupt:
                                pass

            # Verify response sent
            mock_socket.sendto.assert_called_once()
            call_args = mock_socket.sendto.call_args[0]
            response_dict = json.loads(call_args[0].decode())
            assert response_dict["ip"] == "192.168.1.5"
            assert response_dict["hostname"] == "test-host"
            assert response_dict["port"] == server.PORT

            # Verify logger caught the OS error
            mock_logger.exception.assert_called_with("Beacon error")


class TestKillAndPoll:
    """Test OS-specific process teardown functions."""

    def test_kill_and_poll_windows_success(self) -> None:
        """Test Windows process killing and polling loop success."""
        with patch("sys.platform", "win32"):
            with patch("shutil.which", side_effect=lambda x: "C:\\Windows\\System32\\" + str(x) + ".exe"):  # pyright: ignore[reportUnknownLambdaType]
                with patch("os.path.exists", return_value=True):
                    with patch("subprocess.run") as mock_run:
                        # Setup returns:
                        # 3 calls to taskkill
                        # 3 calls to tasklist (where they find nothing, meaning success)
                        mock_proc = MagicMock()
                        mock_proc.stdout = b"No tasks."
                        mock_run.return_value = mock_proc

                        result = server._kill_and_poll_windows()
                        assert result is True
                        assert mock_run.call_count == 6

    def test_kill_and_poll_unix_success(self) -> None:
        """Test Unix process killing and polling loop success."""
        with patch("sys.platform", "linux"):
            with patch("shutil.which", return_value="/usr/bin/tool"):
                with patch("subprocess.run") as mock_run:
                    # Mock sudo probe to fail, so it just runs commands directly for testing
                    mock_sudo_probe = MagicMock()
                    mock_sudo_probe.returncode = 1

                    mock_proc = MagicMock()
                    mock_proc.returncode = 1  # 1 means process not found by pgrep

                    # For sudo probe, then pkill x2, pgrep x3
                    mock_run.side_effect = [
                        mock_sudo_probe,  # sudo probe
                        MagicMock(),  # pkill gost
                        MagicMock(),  # pkill stdin_proxy
                        MagicMock(),  # pkill gpclient
                        MagicMock(),  # pkill gpservice
                        mock_proc,  # pgrep 1
                        mock_proc,  # pgrep 2
                        mock_proc,  # pgrep 3
                    ]

                    result = server._kill_and_poll_unix()
                    assert result is True

    def test_kill_and_poll_wrapper(self) -> None:
        """Test the overarching _kill_and_poll function resets state objects."""
        with patch("server._kill_and_poll_unix", return_value=True):
            with patch("sys.platform", "linux"):
                with patch("server.MODE_FILE"):
                    with patch("server.CLIENT_LOG"):
                        with patch("builtins.open", MagicMock()):
                            result = server._kill_and_poll()
                            assert result is True


def _create_mock_handler(path: str = "/", method: str = "GET", headers: dict[str, str] | None = None) -> Any:
    """Create an initialized mock HTTP handler."""
    handler = server.Handler.__new__(server.Handler)  # pyright: ignore[reportUnknownArgumentType]
    handler.rfile = BytesIO()
    handler.wfile = BytesIO()
    handler.headers = headers or {}  # pyright: ignore[reportAttributeAccessIssue]
    handler.path = path
    handler.command = method
    handler.client_address = ("127.0.0.1", 12345)
    return handler


class TestHTTPHandlerAPI:
    """Test the HTTP Request Handler APIs."""

    def test_do_get_status_authorized(self) -> None:
        """Test /status.json with auth responds 200."""
        handler = _create_mock_handler("/status.json", headers={"Authorization": f"Bearer {server.EPHEMERAL_TOKEN}"})

        # We need to mock send_response, send_header, end_headers because Handler isn't fully initialized via Server
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.send_error = MagicMock()

        with patch("server.get_vpn_state", return_value={"state": "connected"}):
            handler.do_GET()

            handler.send_response.assert_called_with(200)
            output = handler.wfile.getvalue()
            assert b'"state": "connected"' in output

    def test_do_get_status_unauthorized(self) -> None:
        """Test /status.json without auth responds 401."""
        handler = _create_mock_handler("/status.json", headers={})
        handler.send_error = MagicMock()

        handler.do_GET()
        handler.send_error.assert_called_with(401, "Unauthorized")

    def test_do_post_connect(self) -> None:
        """Test /connect endpoint triggers start sequence."""
        handler = _create_mock_handler(
            "/connect", "POST", headers={"Authorization": f"Bearer {server.EPHEMERAL_TOKEN}", "Content-Length": "0"}
        )
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()

        with patch("server._kill_and_poll", return_value=True):
            with patch("server.send_ipc_message", return_value=True):
                handler.do_POST()

                handler.send_response.assert_called_with(200)
                assert handler.wfile.getvalue() == b"OK"

    def test_do_post_submit_success(self) -> None:
        """Test /submit endpoint parsing and IPC forwarding."""
        payload = b"user_input=mypassword123"
        handler = _create_mock_handler(
            "/submit",
            "POST",
            headers={"Authorization": f"Bearer {server.EPHEMERAL_TOKEN}", "Content-Length": str(len(payload))},
        )
        handler.rfile = BytesIO(payload)
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()

        with patch("server.send_ipc_message", return_value=True) as mock_ipc:
            handler.do_POST()

            mock_ipc.assert_called_with(server.IPC_STDIN_PORT, "mypassword123\n")
            handler.send_response.assert_called_with(200)

    def test_do_post_pair_success(self) -> None:
        """Test the Trust On First Use pairing mechanism."""
        from cryptography.hazmat.primitives.asymmetric import ed25519  # pyright: ignore[reportUnknownVariableType]

        private_key = ed25519.Ed25519PrivateKey.generate()  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        public_key = private_key.public_key()  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        from cryptography.hazmat.primitives import serialization  # pyright: ignore[reportUnknownVariableType]

        key_bytes = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        pubkey_b64 = base64.b64encode(key_bytes).decode("utf-8")  # pyright: ignore[reportUnknownArgumentType]

        payload_data = json.dumps({"public_key": pubkey_b64}).encode("utf-8")

        handler = _create_mock_handler("/api/pair", "POST", headers={"Content-Length": str(len(payload_data))})
        handler.rfile = BytesIO(payload_data)
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.send_error = MagicMock()

        with patch("server._paired_pubkey", None):
            with patch.dict(os.environ, {}, clear=True):
                handler.do_POST()
                handler.send_response.assert_called_with(200)
