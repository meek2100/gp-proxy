"""
Tests for backend/stdin_proxy.py

Verifies the stdin proxy daemon that bridges HTTP server and OpenConnect subprocess.
"""

import select
import socket
import sys
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

# Add backend directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from stdin_proxy import main


class TestStdinProxyMain:
    """Test the main stdin proxy functionality."""

    def test_main_creates_socket_with_correct_settings(self) -> None:
        """Test that main creates a TCP socket with correct options."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = KeyboardInterrupt()

                with pytest.raises(SystemExit) as exc_info:
                    main()

                assert exc_info.value.code == 0
                # Verify socket creation
                mock_socket_class.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
                # Verify SO_REUSEADDR is set
                mock_socket.setsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def test_main_binds_to_correct_address(self) -> None:
        """Test that main binds to 127.0.0.1 and IPC_STDIN_PORT."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = KeyboardInterrupt()
                with patch("stdin_proxy.IPC_STDIN_PORT", 32802):
                    with pytest.raises(SystemExit):
                        main()

                    mock_socket.bind.assert_called_once_with(("127.0.0.1", 32802))

    def test_main_starts_listening(self) -> None:
        """Test that main starts listening on the socket."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = KeyboardInterrupt()

                with pytest.raises(SystemExit):
                    main()

                mock_socket.listen.assert_called_once_with(1)

    def test_main_accepts_connection_and_writes_to_stdout(self) -> None:
        """Test that received data is written to stdout buffer."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_client = MagicMock()
            mock_client.recv.side_effect = [b"password123\n", b""]
            mock_socket.accept.return_value = (mock_client, ("127.0.0.1", 12345))
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = [
                    ([mock_socket], [], []),  # Connection ready
                    KeyboardInterrupt(),  # Exit after processing
                ]
                mock_stdout_buffer = BytesIO()
                with patch("stdin_proxy.sys.stdout") as mock_stdout:
                    mock_stdout.buffer = mock_stdout_buffer
                    with pytest.raises(SystemExit):
                        main()

                    output = mock_stdout_buffer.getvalue()
                    assert output == b"password123\n"

    def test_main_handles_multiple_data_chunks(self) -> None:
        """Test handling multiple recv calls from a single connection."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_client = MagicMock()
            mock_client.recv.side_effect = [b"chunk1", b"chunk2", b"chunk3", b""]
            mock_socket.accept.return_value = (mock_client, ("127.0.0.1", 12345))
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = [
                    ([mock_socket], [], []),
                    KeyboardInterrupt(),
                ]
                mock_stdout_buffer = BytesIO()
                with patch("stdin_proxy.sys.stdout") as mock_stdout:
                    mock_stdout.buffer = mock_stdout_buffer
                    with pytest.raises(SystemExit):
                        main()

                    output = mock_stdout_buffer.getvalue()
                    assert output == b"chunk1chunk2chunk3"

    def test_main_select_timeout_continues_loop(self) -> None:
        """Test that select timeout doesn't break the loop."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = [
                    ([], [], []),  # Timeout, no connection
                    ([], [], []),  # Another timeout
                    KeyboardInterrupt(),  # Exit
                ]
                with pytest.raises(SystemExit):
                    main()

                # Should call select with 2.0 second timeout
                assert mock_select.call_count == 3
                first_call = mock_select.call_args_list[0]
                assert first_call[0] == ([mock_socket], [], [], 2.0)

    def test_main_sets_client_timeout(self) -> None:
        """Test that accepted client sockets have timeout set to 5 seconds."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_client = MagicMock()
            mock_client.recv.return_value = b""
            mock_socket.accept.return_value = (mock_client, ("127.0.0.1", 12345))
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = [
                    ([mock_socket], [], []),
                    KeyboardInterrupt(),
                ]
                with pytest.raises(SystemExit):
                    main()

                mock_client.settimeout.assert_called_once_with(5.0)

    def test_main_handles_oserror_during_accept(self) -> None:
        """Test that OSError during accept is logged and loop continues."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = [
                    ([mock_socket], [], []),  # Connection ready
                    KeyboardInterrupt(),
                ]
                mock_socket.accept.side_effect = OSError("Accept failed")

                with patch("stdin_proxy.logger") as mock_logger:
                    with pytest.raises(SystemExit):
                        main()

                    # Should log the exception
                    mock_logger.exception.assert_called_once()

    def test_main_handles_timeout_error(self) -> None:
        """Test that TimeoutError during recv is logged and loop continues."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_client = MagicMock()
            mock_client.recv.side_effect = TimeoutError("Recv timeout")
            mock_socket.accept.return_value = (mock_client, ("127.0.0.1", 12345))
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = [
                    ([mock_socket], [], []),
                    KeyboardInterrupt(),
                ]
                with patch("stdin_proxy.logger") as mock_logger:
                    with pytest.raises(SystemExit):
                        main()

                    # Should log the exception
                    mock_logger.exception.assert_called_once()

    def test_main_keyboard_interrupt_exits_cleanly(self) -> None:
        """Test that KeyboardInterrupt causes clean exit with code 0."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = KeyboardInterrupt()

                with pytest.raises(SystemExit) as exc_info:
                    main()

                assert exc_info.value.code == 0

    def test_main_fatal_bind_error_exits_with_code_1(self) -> None:
        """Test that fatal bind error exits with code 1."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_socket.bind.side_effect = OSError("Address already in use")
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("stdin_proxy.logger") as mock_logger:
                with pytest.raises(SystemExit) as exc_info:
                    main()

                assert exc_info.value.code == 1
                # Should log fatal error
                mock_logger.exception.assert_called_once()

    def test_main_uses_context_manager_for_client(self) -> None:
        """Test that client socket is properly closed using context manager."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_client = MagicMock()
            mock_client.recv.return_value = b""
            mock_socket.accept.return_value = (mock_client, ("127.0.0.1", 12345))
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = [
                    ([mock_socket], [], []),
                    KeyboardInterrupt(),
                ]
                with pytest.raises(SystemExit):
                    main()

                # Context manager should call __enter__ and __exit__
                mock_client.__enter__.assert_called_once()
                mock_client.__exit__.assert_called_once()

    def test_main_flushes_stdout_buffer(self) -> None:
        """Test that stdout buffer is flushed after each write."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_client = MagicMock()
            mock_client.recv.side_effect = [b"data1", b"data2", b""]
            mock_socket.accept.return_value = (mock_client, ("127.0.0.1", 12345))
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = [
                    ([mock_socket], [], []),
                    KeyboardInterrupt(),
                ]
                mock_stdout_buffer = MagicMock(spec=BytesIO)
                with patch("stdin_proxy.sys.stdout") as mock_stdout:
                    mock_stdout.buffer = mock_stdout_buffer
                    with pytest.raises(SystemExit):
                        main()

                    # flush should be called after each write
                    assert mock_stdout_buffer.flush.call_count >= 2


class TestBinaryDataHandling:
    """Test handling of binary data."""

    def test_handles_raw_binary_data(self) -> None:
        """Test that raw binary data is passed through unchanged."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_client = MagicMock()
            binary_data = b"\x00\x01\x02\xff\xfe\xfd"
            mock_client.recv.side_effect = [binary_data, b""]
            mock_socket.accept.return_value = (mock_client, ("127.0.0.1", 12345))
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = [
                    ([mock_socket], [], []),
                    KeyboardInterrupt(),
                ]
                mock_stdout_buffer = BytesIO()
                with patch("stdin_proxy.sys.stdout") as mock_stdout:
                    mock_stdout.buffer = mock_stdout_buffer
                    with pytest.raises(SystemExit):
                        main()

                    output = mock_stdout_buffer.getvalue()
                    assert output == binary_data

    def test_handles_unicode_utf8_bytes(self) -> None:
        """Test that UTF-8 encoded Unicode is passed through correctly."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_client = MagicMock()
            unicode_data = "Hello 世界".encode("utf-8")
            mock_client.recv.side_effect = [unicode_data, b""]
            mock_socket.accept.return_value = (mock_client, ("127.0.0.1", 12345))
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = [
                    ([mock_socket], [], []),
                    KeyboardInterrupt(),
                ]
                mock_stdout_buffer = BytesIO()
                with patch("stdin_proxy.sys.stdout") as mock_stdout:
                    mock_stdout.buffer = mock_stdout_buffer
                    with pytest.raises(SystemExit):
                        main()

                    output = mock_stdout_buffer.getvalue()
                    assert output == unicode_data
                    assert output.decode("utf-8") == "Hello 世界"


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_recv_closes_connection(self) -> None:
        """Test that empty recv (connection closed) is handled."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_client = MagicMock()
            mock_client.recv.return_value = b""  # Connection closed
            mock_socket.accept.return_value = (mock_client, ("127.0.0.1", 12345))
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = [
                    ([mock_socket], [], []),
                    KeyboardInterrupt(),
                ]
                mock_stdout_buffer = BytesIO()
                with patch("stdin_proxy.sys.stdout") as mock_stdout:
                    mock_stdout.buffer = mock_stdout_buffer
                    with pytest.raises(SystemExit):
                        main()

                    # Should handle gracefully without error
                    output = mock_stdout_buffer.getvalue()
                    assert output == b""

    def test_large_recv_buffer(self) -> None:
        """Test handling data larger than recv buffer size."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_client = MagicMock()
            large_data = b"X" * 10000
            mock_client.recv.side_effect = [large_data[:4096], large_data[4096:8192], large_data[8192:], b""]
            mock_socket.accept.return_value = (mock_client, ("127.0.0.1", 12345))
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = [
                    ([mock_socket], [], []),
                    KeyboardInterrupt(),
                ]
                mock_stdout_buffer = BytesIO()
                with patch("stdin_proxy.sys.stdout") as mock_stdout:
                    mock_stdout.buffer = mock_stdout_buffer
                    with pytest.raises(SystemExit):
                        main()

                    output = mock_stdout_buffer.getvalue()
                    assert output == large_data

    def test_multiple_sequential_connections(self) -> None:
        """Test handling multiple connections sequentially."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_client1 = MagicMock()
            mock_client1.recv.side_effect = [b"conn1", b""]
            mock_client2 = MagicMock()
            mock_client2.recv.side_effect = [b"conn2", b""]

            mock_socket.accept.side_effect = [
                (mock_client1, ("127.0.0.1", 12345)),
                (mock_client2, ("127.0.0.1", 12346)),
            ]
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = [
                    ([mock_socket], [], []),  # First connection
                    ([mock_socket], [], []),  # Second connection
                    KeyboardInterrupt(),
                ]
                mock_stdout_buffer = BytesIO()
                with patch("stdin_proxy.sys.stdout") as mock_stdout:
                    mock_stdout.buffer = mock_stdout_buffer
                    with pytest.raises(SystemExit):
                        main()

                    output = mock_stdout_buffer.getvalue()
                    assert b"conn1" in output
                    assert b"conn2" in output


class TestRealWorldScenarios:
    """Test realistic scenarios."""

    def test_password_submission(self) -> None:
        """Test submitting a password through the proxy."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_client = MagicMock()
            password = b"MySecureP@ssw0rd\n"
            mock_client.recv.side_effect = [password, b""]
            mock_socket.accept.return_value = (mock_client, ("127.0.0.1", 12345))
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = [
                    ([mock_socket], [], []),
                    KeyboardInterrupt(),
                ]
                mock_stdout_buffer = BytesIO()
                with patch("stdin_proxy.sys.stdout") as mock_stdout:
                    mock_stdout.buffer = mock_stdout_buffer
                    with pytest.raises(SystemExit):
                        main()

                    output = mock_stdout_buffer.getvalue()
                    assert output == password

    def test_globalprotect_callback_url(self) -> None:
        """Test submitting a GlobalProtect callback URL."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_client = MagicMock()
            callback_url = b"globalprotect://callback?user=test&token=abc123\n"
            mock_client.recv.side_effect = [callback_url, b""]
            mock_socket.accept.return_value = (mock_client, ("127.0.0.1", 12345))
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("select.select") as mock_select:
                mock_select.side_effect = [
                    ([mock_socket], [], []),
                    KeyboardInterrupt(),
                ]
                mock_stdout_buffer = BytesIO()
                with patch("stdin_proxy.sys.stdout") as mock_stdout:
                    mock_stdout.buffer = mock_stdout_buffer
                    with pytest.raises(SystemExit):
                        main()

                    output = mock_stdout_buffer.getvalue()
                    assert output == callback_url