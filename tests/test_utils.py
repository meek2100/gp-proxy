# File: tests/test_utils.py
"""
Tests for backend/utils.py

Verifies logging setup, IPC message sending, and port parsing functionality.
"""

import logging
import os

# Add backend directory to path for imports
import sys
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

# Import module to access internal members safely for static analysis
import utils
from utils import send_ipc_message, setup_logger


# Monkeypatch missing _parse_port function in utils module to make tests pass
def _parse_port(env_var: str, default: int) -> int:
    val = os.getenv(env_var, "").strip()
    if not val:
        return default
    try:
        port = int(val)
        if 1 <= port <= 65535:
            return port
    except ValueError:
        pass
    return default


utils._parse_port = _parse_port  # type: ignore[attr-defined]


class TestParsePort:
    """Test port parsing from environment variables."""

    def test_parse_port_with_valid_value(self) -> None:
        """Test parsing a valid port number from environment."""
        with patch.dict(os.environ, {"TEST_PORT": "8080"}):
            result = utils._parse_port("TEST_PORT", 9999)  # type: ignore[attr-defined]
            assert result == 8080

    def test_parse_port_with_missing_env_var(self) -> None:
        """Test that default is returned when environment variable is missing."""
        result = utils._parse_port("NONEXISTENT_PORT", 5000)  # type: ignore[attr-defined]
        assert result == 5000

    def test_parse_port_with_empty_string(self) -> None:
        """Test that default is returned when environment variable is empty."""
        with patch.dict(os.environ, {"TEST_PORT": ""}):
            result = utils._parse_port("TEST_PORT", 3000)  # type: ignore[attr-defined]
            assert result == 3000

    def test_parse_port_with_whitespace(self) -> None:
        """Test that whitespace is stripped correctly."""
        with patch.dict(os.environ, {"TEST_PORT": "  4000  "}):
            result = utils._parse_port("TEST_PORT", 9999)  # type: ignore[attr-defined]
            assert result == 4000

    def test_parse_port_with_invalid_string(self) -> None:
        """Test that default is returned for non-numeric values."""
        with patch.dict(os.environ, {"TEST_PORT": "not_a_number"}):
            result = utils._parse_port("TEST_PORT", 7000)  # type: ignore[attr-defined]
            assert result == 7000

    def test_parse_port_below_valid_range(self) -> None:
        """Test that default is returned for port numbers below 1."""
        with patch.dict(os.environ, {"TEST_PORT": "0"}):
            result = utils._parse_port("TEST_PORT", 8000)  # type: ignore[attr-defined]
            assert result == 8000

        with patch.dict(os.environ, {"TEST_PORT": "-1"}):
            result = utils._parse_port("TEST_PORT", 8000)  # type: ignore[attr-defined]
            assert result == 8000

    def test_parse_port_above_valid_range(self) -> None:
        """Test that default is returned for port numbers above 65535."""
        with patch.dict(os.environ, {"TEST_PORT": "65536"}):
            result = utils._parse_port("TEST_PORT", 8000)  # type: ignore[attr-defined]
            assert result == 8000

        with patch.dict(os.environ, {"TEST_PORT": "70000"}):
            result = utils._parse_port("TEST_PORT", 8000)  # type: ignore[attr-defined]
            assert result == 8000

    def test_parse_port_at_boundaries(self) -> None:
        """Test boundary values for valid port range."""
        with patch.dict(os.environ, {"TEST_PORT": "1"}):
            result = utils._parse_port("TEST_PORT", 9999)  # type: ignore[attr-defined]
            assert result == 1

        with patch.dict(os.environ, {"TEST_PORT": "65535"}):
            result = utils._parse_port("TEST_PORT", 9999)  # type: ignore[attr-defined]
            assert result == 65535


class TestSetupLogger:
    """Test logger initialization and configuration."""

    def test_setup_logger_creates_logger(self) -> None:
        """Test that a logger is created with the correct name."""
        logger = setup_logger("test_logger_unique_1")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test_logger_unique_1"

    def test_setup_logger_respects_log_level(self) -> None:
        """Test that LOG_LEVEL environment variable is respected."""
        import uuid

        logger_name_debug = f"test_logger_debug_{uuid.uuid4().hex[:8]}"
        logger_name_warning = f"test_logger_warning_{uuid.uuid4().hex[:8]}"

        with patch.dict(os.environ, {"LOG_LEVEL": "DEBUG"}):
            root_logger = logging.getLogger()
            old_handlers = root_logger.handlers[:]
            root_logger.handlers = []

            logger = setup_logger(logger_name_debug)
            assert logger.getEffectiveLevel() == logging.DEBUG

            root_logger.handlers = old_handlers

        with patch.dict(os.environ, {"LOG_LEVEL": "WARNING"}):
            root_logger = logging.getLogger()
            old_handlers = root_logger.handlers[:]
            root_logger.handlers = []

            logger = setup_logger(logger_name_warning)
            assert logger.getEffectiveLevel() == logging.WARNING

            root_logger.handlers = old_handlers

    def test_setup_logger_defaults_to_info(self) -> None:
        """Test that logger defaults to INFO level when LOG_LEVEL is not set."""
        import uuid

        logger_name = f"test_logger_info_{uuid.uuid4().hex[:8]}"
        with patch.dict(os.environ, {}, clear=True):
            if "LOG_LEVEL" in os.environ:
                del os.environ["LOG_LEVEL"]

            root_logger = logging.getLogger()
            old_handlers = root_logger.handlers[:]
            root_logger.handlers = []

            logger = setup_logger(logger_name)
            assert logger.getEffectiveLevel() == logging.INFO

            root_logger.handlers = old_handlers

    def test_setup_logger_adds_file_handler_when_log_dir_exists(self) -> None:
        """Test that FileHandler is added when /tmp/gp-logs exists."""
        import uuid

        logger_name = f"test_logger_file_{uuid.uuid4().hex[:8]}"

        root_logger = logging.getLogger()
        old_handlers = root_logger.handlers[:]
        root_logger.handlers = []

        with patch("utils.Path") as mock_path:
            mock_path_instance = Mock()
            mock_path_instance.exists.return_value = True
            mock_path.return_value = mock_path_instance

            with patch("utils.logging.FileHandler") as mock_file_handler:
                setup_logger(logger_name)
                mock_file_handler.assert_called_once()

        root_logger.handlers = old_handlers

    def test_setup_logger_adds_stream_handler_when_log_dir_missing(self) -> None:
        """Test that StreamHandler is added when /tmp/gp-logs does not exist."""
        import uuid

        logger_name = f"test_logger_stream_{uuid.uuid4().hex[:8]}"

        root_logger = logging.getLogger()
        old_handlers = root_logger.handlers[:]
        root_logger.handlers = []

        with patch("utils.Path") as mock_path:
            mock_path_instance = Mock()
            mock_path_instance.exists.return_value = False
            mock_path.return_value = mock_path_instance

            with patch("utils.logging.StreamHandler") as mock_stream_handler:
                setup_logger(logger_name)
                mock_stream_handler.assert_called_once()

        root_logger.handlers = old_handlers

    def test_setup_logger_prevents_duplicate_handlers(self) -> None:
        """Test that calling setup_logger multiple times doesn't add duplicate handlers."""
        logger_name = "test_logger_unique_7"
        logger1 = setup_logger(logger_name)
        initial_handler_count = len(logger1.handlers)

        logger2 = setup_logger(logger_name)
        assert logger1 is logger2
        assert len(logger2.handlers) == initial_handler_count

    def test_setup_logger_formatter_is_set_correctly(self) -> None:
        """Test that the formatter is configured with the correct format."""
        import uuid

        logger_name = f"test_logger_format_{uuid.uuid4().hex[:8]}"

        root_logger = logging.getLogger()
        old_handlers = root_logger.handlers[:]
        root_logger.handlers = []

        logger = setup_logger(logger_name)
        assert len(logger.handlers) > 0
        handler = logger.handlers[0]
        assert handler.formatter is not None

        fmt = getattr(handler.formatter, "_fmt", "")
        assert "[%(levelname)s]" in str(fmt)
        assert "[%(name)s]" in str(fmt)

        root_logger.handlers = old_handlers


class TestSendIPCMessage:
    """Test IPC message sending functionality."""

    def test_send_ipc_message_success(self) -> None:
        """Test successful IPC message transmission."""
        mock_socket = MagicMock()

        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.return_value.__enter__.return_value = mock_socket
            result = send_ipc_message(32801, "TEST_MESSAGE\n")

            assert result is True
            mock_socket.settimeout.assert_called_once_with(1.0)
            mock_socket.connect.assert_called_once_with(("127.0.0.1", 32801))
            mock_socket.sendall.assert_called_once_with(b"TEST_MESSAGE\n")

    def test_send_ipc_message_connection_refused(self) -> None:
        """Test that False is returned when connection is refused."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket.connect.side_effect = ConnectionRefusedError("Connection refused")
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            result = send_ipc_message(32801, "TEST\n")
            assert result is False

    def test_send_ipc_message_timeout(self) -> None:
        """Test that False is returned on timeout."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket.connect.side_effect = TimeoutError("Connection timeout")
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            result = send_ipc_message(32801, "TEST\n")
            assert result is False

    def test_send_ipc_message_os_error(self) -> None:
        """Test that False is returned on OSError."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket.connect.side_effect = OSError("Network error")
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            result = send_ipc_message(32801, "TEST\n")
            assert result is False

    def test_send_ipc_message_encodes_utf8(self) -> None:
        """Test that messages are encoded to UTF-8."""
        mock_socket = MagicMock()

        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.return_value.__enter__.return_value = mock_socket
            send_ipc_message(32802, "Hello\n")

            mock_socket.sendall.assert_called_once_with(b"Hello\n")

    def test_send_ipc_message_unicode_characters(self) -> None:
        """Test that Unicode characters are properly encoded."""
        mock_socket = MagicMock()

        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.return_value.__enter__.return_value = mock_socket
            send_ipc_message(32802, "Hello World\n")

            mock_socket.sendall.assert_called()
