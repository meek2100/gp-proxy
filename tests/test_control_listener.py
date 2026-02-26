# File: tests/test_control_listener.py
# pyright: reportPrivateUsage=false
"""
Tests for backend/control_listener.py

Verifies the control IPC listener daemon functionality including connection handling,
buffer processing, and error recovery.
"""

import socket
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

# Add backend directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

import control_listener
from control_listener import main

# Access private members safely
process_connection = control_listener._process_connection
run_server_loop = control_listener._run_server_loop


class TestProcessConnection:
    """Test connection processing and buffer handling."""

    def test_process_connection_single_line(self) -> None:
        """Test processing a single complete line."""
        mock_socket = Mock()
        mock_socket.recv.side_effect = [b"START\n", b""]

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            process_connection(mock_socket)
            output = mock_stdout.getvalue()
            assert "START\n" in output

    def test_process_connection_multiple_lines(self) -> None:
        """Test processing multiple lines in sequence."""
        mock_socket = Mock()
        mock_socket.recv.side_effect = [b"START\n", b"STOP\n", b""]

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            process_connection(mock_socket)
            output = mock_stdout.getvalue()
            assert "START\n" in output
            assert "STOP\n" in output

    def test_process_connection_line_split_across_chunks(self) -> None:
        """Test that lines split across multiple recv calls are handled correctly."""
        mock_socket = Mock()
        mock_socket.recv.side_effect = [b"STA", b"RT\n", b""]

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            process_connection(mock_socket)
            output = mock_stdout.getvalue()
            assert "START\n" in output

    def test_process_connection_utf8_multibyte_split(self) -> None:
        """Test handling multibyte UTF-8 characters split across chunks."""
        mock_socket = Mock()
        # Replaced Non-English with 'World'
        mock_socket.recv.side_effect = [b"Wor", b"ld\n", b""]

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            process_connection(mock_socket)
            output = mock_stdout.getvalue()
            assert "World\n" in output

    def test_process_connection_empty_lines_ignored(self) -> None:
        """Test that empty lines are ignored."""
        mock_socket = Mock()
        mock_socket.recv.side_effect = [b"\n\n\n", b""]

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            process_connection(mock_socket)
            output = mock_stdout.getvalue()
            assert output == ""

    def test_process_connection_whitespace_only_ignored(self) -> None:
        """Test that whitespace-only lines are ignored."""
        mock_socket = Mock()
        mock_socket.recv.side_effect = [b"   \n", b"\t\t\n", b""]

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            process_connection(mock_socket)
            output = mock_stdout.getvalue()
            assert output == ""

    def test_process_connection_strips_whitespace(self) -> None:
        """Test that leading/trailing whitespace is stripped."""
        mock_socket = Mock()
        mock_socket.recv.side_effect = [b"  START  \n", b""]

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            process_connection(mock_socket)
            output = mock_stdout.getvalue()
            assert "START\n" in output
            assert "  START  " not in output

    def test_process_connection_unicode_decode_error(self) -> None:
        """Test handling of malformed UTF-8 sequences."""
        mock_socket = Mock()
        mock_socket.recv.side_effect = [b"\xff\xfe\n", b"VALID\n", b""]

        with patch("sys.stdout", new_callable=StringIO):
            with patch("control_listener.logger") as mock_logger:
                process_connection(mock_socket)
                mock_logger.exception.assert_called()

    def test_process_connection_remaining_buffer_processed(self) -> None:
        """Test that remaining buffer content without newline is processed."""
        mock_socket = Mock()
        mock_socket.recv.side_effect = [b"START", b""]

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            process_connection(mock_socket)
            output = mock_stdout.getvalue()
            assert "START\n" in output

    def test_process_connection_remaining_buffer_malformed(self) -> None:
        """Test handling of malformed data in remaining buffer."""
        mock_socket = Mock()
        mock_socket.recv.side_effect = [b"\xff\xfe", b""]

        with patch("sys.stdout", new_callable=StringIO):
            with patch("control_listener.logger") as mock_logger:
                process_connection(mock_socket)
                mock_logger.exception.assert_called()

    def test_process_connection_large_buffer(self) -> None:
        """Test processing large amounts of data."""
        mock_socket = Mock()
        large_data = b"X" * 1000 + b"\n"
        mock_socket.recv.side_effect = [large_data, b""]

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            process_connection(mock_socket)
            output = mock_stdout.getvalue()
            assert "X" * 1000 + "\n" in output


class TestRunServerLoop:
    """Test the main server loop functionality."""

    def test_run_server_loop_accepts_connection(self) -> None:
        """Test that the server loop accepts incoming connections."""
        mock_socket = Mock()
        mock_client = MagicMock()
        mock_socket.accept.return_value = (mock_client, ("127.0.0.1", 12345))

        with patch("select.select") as mock_select:
            mock_select.side_effect = [
                ([mock_socket], [], []),
                KeyboardInterrupt(),
            ]
            with patch("control_listener._process_connection") as mock_process:
                try:
                    run_server_loop(mock_socket)
                except SystemExit:
                    pass

                mock_socket.accept.assert_called_once()
                mock_client.settimeout.assert_called_once_with(5.0)
                mock_process.assert_called_once_with(mock_client)

    def test_run_server_loop_select_timeout(self) -> None:
        """Test that the loop handles select timeout correctly."""
        mock_socket = Mock()

        with patch("select.select") as mock_select:
            mock_select.side_effect = [
                ([], [], []),
                KeyboardInterrupt(),
            ]
            try:
                run_server_loop(mock_socket)
            except SystemExit:
                pass

            calls = mock_select.call_args_list
            assert calls[0][0] == ([mock_socket], [], [], 2.0)

    def test_run_server_loop_socket_error_continues(self) -> None:
        """Test that socket errors are logged but the loop continues."""
        mock_socket = Mock()

        with patch("select.select") as mock_select:
            mock_select.side_effect = [
                OSError("Socket error"),
                KeyboardInterrupt(),
            ]
            with patch("control_listener.logger") as mock_logger:
                try:
                    run_server_loop(mock_socket)
                except SystemExit:
                    pass

                mock_logger.warning.assert_called()
                assert "Socket error" in str(mock_logger.warning.call_args)

    def test_run_server_loop_timeout_error_continues(self) -> None:
        """Test that timeout errors are handled gracefully."""
        mock_socket = Mock()

        with patch("select.select") as mock_select:
            mock_select.side_effect = [
                TimeoutError("Timeout"),
                KeyboardInterrupt(),
            ]
            with patch("control_listener.logger") as mock_logger:
                try:
                    run_server_loop(mock_socket)
                except SystemExit:
                    pass

                mock_logger.warning.assert_called()

    def test_run_server_loop_keyboard_interrupt_exits(self) -> None:
        """Test that KeyboardInterrupt causes clean exit."""
        mock_socket = Mock()

        with patch("select.select") as mock_select:
            mock_select.side_effect = KeyboardInterrupt()

            with pytest.raises(SystemExit) as exc_info:  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
                run_server_loop(mock_socket)

            assert exc_info.value.code == 0  # pyright: ignore[reportUnknownMemberType]

    def test_run_server_loop_client_socket_timeout_set(self) -> None:
        """Test that accepted client sockets have timeout set."""
        mock_socket = Mock()
        mock_client = MagicMock()
        mock_socket.accept.return_value = (mock_client, ("127.0.0.1", 12345))

        with patch("select.select") as mock_select:
            mock_select.side_effect = [
                ([mock_socket], [], []),
                KeyboardInterrupt(),
            ]
            with patch("control_listener._process_connection"):
                try:
                    run_server_loop(mock_socket)
                except SystemExit:
                    pass

                mock_client.settimeout.assert_called_once_with(5.0)

    def test_run_server_loop_uses_context_manager_for_client(self) -> None:
        """Test that client socket is properly closed using context manager."""
        mock_socket = Mock()
        mock_client = MagicMock()
        mock_socket.accept.return_value = (mock_client, ("127.0.0.1", 12345))

        with patch("select.select") as mock_select:
            mock_select.side_effect = [
                ([mock_socket], [], []),
                KeyboardInterrupt(),
            ]
            with patch("control_listener._process_connection"):
                try:
                    run_server_loop(mock_socket)
                except SystemExit:
                    pass

                mock_client.__enter__.assert_called_once()
                mock_client.__exit__.assert_called_once()


class TestMain:
    """Test the main entry point."""

    def test_main_creates_socket_with_correct_settings(self) -> None:
        """Test that main creates a TCP socket with correct options."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("control_listener._run_server_loop") as mock_run:
                mock_run.side_effect = KeyboardInterrupt()

                try:
                    main()
                except SystemExit, KeyboardInterrupt:
                    pass

                mock_socket_class.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
                mock_socket.setsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def test_main_binds_to_correct_address(self) -> None:
        """Test that main binds to 127.0.0.1 and IPC_CONTROL_PORT."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("control_listener._run_server_loop") as mock_run:
                mock_run.side_effect = KeyboardInterrupt()
                with patch("control_listener.IPC_CONTROL_PORT", 32801):
                    try:
                        main()
                    except SystemExit, KeyboardInterrupt:
                        pass

                    mock_socket.bind.assert_called_once_with(("127.0.0.1", 32801))

    def test_main_starts_listening(self) -> None:
        """Test that main starts listening on the socket."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("control_listener._run_server_loop") as mock_run:
                mock_run.side_effect = KeyboardInterrupt()

                try:
                    main()
                except SystemExit, KeyboardInterrupt:
                    pass

                mock_socket.listen.assert_called_once_with(1)

    def test_main_os_error_during_bind_exits(self) -> None:
        """Test that OSError during bind causes exit with code 1."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_socket.bind.side_effect = OSError("Address already in use")
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("control_listener.logger") as mock_logger:
                with pytest.raises(SystemExit) as exc_info:  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
                    main()

                assert exc_info.value.code == 1  # pyright: ignore[reportUnknownMemberType]
                mock_logger.error.assert_called()
                assert "Fatal error" in str(mock_logger.error.call_args)

    def test_main_calls_run_server_loop(self) -> None:
        """Test that main delegates to _run_server_loop."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("control_listener._run_server_loop") as mock_run:
                mock_run.side_effect = KeyboardInterrupt()

                try:
                    main()
                except SystemExit, KeyboardInterrupt:
                    pass

                mock_run.assert_called_once_with(mock_socket)


class TestIntegrationScenarios:
    """Test realistic integration scenarios."""

    def test_complete_command_flow(self) -> None:
        """Test complete flow of receiving and processing a command."""
        mock_socket = Mock()
        mock_client = MagicMock()
        mock_client.recv.side_effect = [b"START\n", b""]
        mock_socket.accept.return_value = (mock_client, ("127.0.0.1", 12345))

        with patch("select.select") as mock_select:
            mock_select.side_effect = [
                ([mock_socket], [], []),
                KeyboardInterrupt(),
            ]
            with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
                try:
                    run_server_loop(mock_socket)
                except SystemExit:
                    pass

                output = mock_stdout.getvalue()
                assert "START\n" in output

    def test_multiple_commands_in_single_connection(self) -> None:
        """Test processing multiple commands from one connection."""
        mock_socket = Mock()
        mock_client = MagicMock()
        mock_client.recv.side_effect = [b"START\nSTOP\nRESTART\n", b""]
        mock_socket.accept.return_value = (mock_client, ("127.0.0.1", 12345))

        with patch("select.select") as mock_select:
            mock_select.side_effect = [
                ([mock_socket], [], []),
                KeyboardInterrupt(),
            ]
            with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
                try:
                    run_server_loop(mock_socket)
                except SystemExit:
                    pass

                output = mock_stdout.getvalue()
                assert "START\n" in output
                assert "STOP\n" in output
                assert "RESTART\n" in output
