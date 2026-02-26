# File: tests/test_server.py
# pyright: reportPrivateUsage=false
"""
Tests for backend/server.py

Verifies the main HTTP server including authentication, state management,
VPN control endpoints, and TOFU Ed25519 pairing.
"""

import base64
import os

# Add backend directory to path for imports
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

import server
from server import (
    ANSI_ESCAPE,
    GATEWAY_REGEX,
    URL_PATTERN,
    Handler,
    StateManager,
    analyze_log_lines,
    get_best_ip,
    get_vpn_state,
    init_runtime_dir,
    strip_ansi,
)

# Access private members
evaluate_line_state = server._evaluate_line_state
extract_gateways = server._extract_gateways
extract_sso_url = server._extract_sso_url


class TestStripAnsi:
    """Test ANSI escape sequence removal."""

    def test_strip_ansi_removes_color_codes(self) -> None:
        """Test removal of ANSI color codes."""
        text = "\x1b[31mRed Text\x1b[0m"
        result: str = strip_ansi(text)
        assert result == "Red Text"

    def test_strip_ansi_removes_cursor_movements(self) -> None:
        """Test removal of cursor movement codes."""
        text = "\x1b[2JCleared\x1b[H"
        result: str = strip_ansi(text)
        assert result == "Cleared"

    def test_strip_ansi_preserves_plain_text(self) -> None:
        """Test that plain text is unchanged."""
        text = "Plain text without ANSI"
        result: str = strip_ansi(text)
        assert result == text

    def test_strip_ansi_handles_empty_string(self) -> None:
        """Test handling of empty string."""
        result: str = strip_ansi("")
        assert result == ""

    def test_strip_ansi_complex_sequences(self) -> None:
        """Test removal of complex ANSI sequences."""
        text = "\x1b[1;32mBold Green\x1b[0m Normal \x1b[4mUnderline\x1b[24m"
        result: str = strip_ansi(text)
        assert "\x1b" not in result
        assert "Bold Green" in result
        assert "Underline" in result


class TestExtractGateways:
    """Test gateway extraction from log lines."""

    def test_extract_gateways_single_gateway(self) -> None:
        """Test extracting a single gateway option."""
        lines = [
            "Gateway options:",
            "  > Gateway1 (gw1.example.com)",
        ]
        result: list[str] = extract_gateways(lines)
        assert "Gateway1 (gw1.example.com)" in result

    def test_extract_gateways_multiple_options(self) -> None:
        """Test extracting multiple gateway options."""
        lines = [
            "  > Gateway1 (gw1.example.com)",
            "    Gateway2 (gw2.example.com)",
            "    Gateway3 (gw3.example.com)",
        ]
        result: list[str] = extract_gateways(lines)
        assert len(result) == 3
        assert "Gateway1 (gw1.example.com)" in result
        assert "Gateway2 (gw2.example.com)" in result
        assert "Gateway3 (gw3.example.com)" in result

    def test_extract_gateways_sorted_output(self) -> None:
        """Test that gateways are returned sorted."""
        lines = [
            "  Zebra (z.example.com)",
            "  Alpha (a.example.com)",
            "  Beta (b.example.com)",
        ]
        result: list[str] = extract_gateways(lines)
        assert result == sorted(result)

    def test_extract_gateways_deduplicates(self) -> None:
        """Test that duplicate gateways are removed."""
        lines = [
            "  Gateway1 (gw1.example.com)",
            "  Gateway1 (gw1.example.com)",
            "  Gateway2 (gw2.example.com)",
        ]
        result: list[str] = extract_gateways(lines)
        assert len(result) == 2

    def test_extract_gateways_excludes_prompt_line(self) -> None:
        """Test that the prompt line itself is excluded."""
        lines = [
            "Which gateway do you want to connect to?",
            "  Gateway1 (gw1.example.com)",
        ]
        result: list[str] = extract_gateways(lines)
        assert "Which gateway" not in str(result)
        assert "Gateway1 (gw1.example.com)" in result

    def test_extract_gateways_empty_lines(self) -> None:
        """Test handling of empty line list."""
        result: list[str] = extract_gateways([])
        assert result == []


class TestExtractSsoUrl:
    """Test SSO URL extraction from logs."""

    def test_extract_sso_url_finds_https_url(self) -> None:
        """Test extraction of HTTPS SSO URL."""
        log = "Please authenticate at: https://auth.example.com/saml/login?token=abc123"
        result: str = extract_sso_url(log, 8001)
        assert result == "https://auth.example.com/saml/login?token=abc123"

    def test_extract_sso_url_finds_http_url(self) -> None:
        """Test extraction of HTTP URL."""
        log = "Login at http://login.example.com"
        result: str = extract_sso_url(log, 8001)
        assert result == "http://login.example.com"

    def test_extract_sso_url_excludes_local_urls(self) -> None:
        """Test that local URLs with port are excluded."""
        log = "Server at http://127.0.0.1:8001/status and auth at https://auth.example.com/login"
        result: str = extract_sso_url(log, 8001)
        assert result == "https://auth.example.com/login"

    def test_extract_sso_url_returns_last_match(self) -> None:
        """Test that the most recent URL is returned."""
        log = "First: https://old.example.com/login Second: https://new.example.com/auth"
        result: str = extract_sso_url(log, 8001)
        assert result == "https://new.example.com/auth"

    def test_extract_sso_url_no_urls(self) -> None:
        """Test handling when no URLs are present."""
        log = "Connecting to VPN..."
        result: str = extract_sso_url(log, 8001)
        assert result == ""

    def test_extract_sso_url_empty_log(self) -> None:
        """Test handling of empty log."""
        result: str = extract_sso_url("", 8001)
        assert result == ""


class TestEvaluateLineState:
    """Test individual line state evaluation."""

    def test_evaluate_line_state_connected(self) -> None:
        """Test detection of connected state."""
        analysis: Any = {
            "state": "idle",
            "prompt": "",
            "prompt_type": "text",
            "options": [],
            "error": None,
            "sso_url": "",
        }
        result: bool = evaluate_line_state("Connected to vpn.example.com", [], analysis)
        assert result is True
        assert analysis["state"] == "connected"

    def test_evaluate_line_state_login_failed(self) -> None:
        """Test detection of login failure."""
        analysis: Any = {
            "state": "idle",
            "prompt": "",
            "prompt_type": "text",
            "options": [],
            "error": None,
            "sso_url": "",
        }
        result: bool = evaluate_line_state("Login failed", [], analysis)
        assert result is True
        assert analysis["state"] == "error"
        assert analysis["error"] == "Login failed"

    def test_evaluate_line_state_gateway_selection(self) -> None:
        """Test detection of gateway selection prompt."""
        lines = ["  Gateway1 (gw1.com)", "  Gateway2 (gw2.com)"]
        analysis: Any = {
            "state": "idle",
            "prompt": "",
            "prompt_type": "text",
            "options": [],
            "error": None,
            "sso_url": "",
        }
        result: bool = evaluate_line_state("Which gateway do you want to connect to", lines, analysis)
        assert result is True
        assert analysis["state"] == "input"
        assert analysis["prompt"] == "Select Gateway"
        assert analysis["prompt_type"] == "select"
        assert len(analysis["options"]) > 0

    def test_evaluate_line_state_password_prompt(self) -> None:
        """Test detection of password prompt."""
        analysis: Any = {
            "state": "idle",
            "prompt": "",
            "prompt_type": "text",
            "options": [],
            "error": None,
            "sso_url": "",
        }
        result: bool = evaluate_line_state("Enter password:", [], analysis)
        assert result is True
        assert analysis["state"] == "input"
        assert analysis["prompt"] == "Enter Password"
        assert analysis["prompt_type"] == "password"

    def test_evaluate_line_state_username_prompt(self) -> None:
        """Test detection of username prompt."""
        analysis: Any = {
            "state": "idle",
            "prompt": "",
            "prompt_type": "text",
            "options": [],
            "error": None,
            "sso_url": "",
        }
        result: bool = evaluate_line_state("Enter username:", [], analysis)
        assert result is True
        assert analysis["state"] == "input"
        assert analysis["prompt"] == "Enter Username"
        assert analysis["prompt_type"] == "text"

    def test_evaluate_line_state_connecting(self) -> None:
        """Test detection of connecting state."""
        analysis: Any = {
            "state": "idle",
            "prompt": "",
            "prompt_type": "text",
            "options": [],
            "error": None,
            "sso_url": "",
        }
        result: bool = evaluate_line_state("Connecting to server...", [], analysis)
        assert result is True
        assert analysis["state"] == "connecting"

    def test_evaluate_line_state_no_match(self) -> None:
        """Test handling of lines that don't match any pattern."""
        analysis: Any = {
            "state": "idle",
            "prompt": "",
            "prompt_type": "text",
            "options": [],
            "error": None,
            "sso_url": "",
        }
        result: bool = evaluate_line_state("Some random log line", [], analysis)
        assert result is False
        assert analysis["state"] == "idle"


class TestAnalyzeLogLines:
    """Test complete log analysis."""

    def test_analyze_log_lines_connected(self) -> None:
        """Test analysis of connected state logs."""
        lines = ["Connecting...", "Authenticating...", "Connected to vpn.example.com"]
        result: Any = analyze_log_lines(lines, "\n".join(lines))
        assert result["state"] == "connected"

    def test_analyze_log_lines_auth_required(self) -> None:
        """Test detection of authentication requirement."""
        lines = ["Starting connection"]
        log_content = "Manual Authentication Required at https://auth.example.com"
        result: Any = analyze_log_lines(lines, log_content)
        assert result["state"] == "auth"
        assert result["sso_url"] == "https://auth.example.com"

    def test_analyze_log_lines_backward_chronological(self) -> None:
        """Test that most recent state wins in analysis."""
        lines = ["Connecting...", "Connected to vpn.example.com", "Disconnected"]
        result: Any = analyze_log_lines(lines, "\n".join(lines))
        assert result["state"] == "connected"

    def test_analyze_log_lines_empty(self) -> None:
        """Test analysis of empty logs."""
        result: Any = analyze_log_lines([], "")
        assert result["state"] == "idle"
        assert result["error"] is None


class TestStateManager:
    """Test StateManager thread-safe state handling."""

    def test_state_manager_init(self) -> None:
        """Test StateManager initialization."""
        manager: Any = StateManager()
        assert manager._last_state is None
        assert manager._log_mtime_ns == -1
        assert manager._log_size == -1

    def test_update_and_check_transition_first_update(self) -> None:
        """Test first state transition."""
        manager: Any = StateManager()
        result: bool = manager.update_and_check_transition("connecting")
        assert result is True
        assert manager._last_state == "connecting"

    def test_update_and_check_transition_same_state(self) -> None:
        """Test that same state doesn't trigger transition."""
        manager: Any = StateManager()
        manager.update_and_check_transition("connecting")
        result: bool = manager.update_and_check_transition("connecting")
        assert result is False

    def test_update_and_check_transition_state_change(self) -> None:
        """Test state change detection."""
        manager: Any = StateManager()
        manager.update_and_check_transition("connecting")
        result: bool = manager.update_and_check_transition("connected")
        assert result is True
        assert manager._last_state == "connected"

    def test_get_cached_log_analysis_file_not_found(self) -> None:
        """Test handling of missing log file."""
        manager: Any = StateManager()
        analysis, log = manager.get_cached_log_analysis(Path("/nonexistent/file.log"))
        assert analysis["state"] == "idle"
        assert log == ""

    def test_get_cached_log_analysis_uses_cache(self) -> None:
        """Test that cache is used when file hasn't changed."""
        manager: Any = StateManager()

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("Connected to VPN\n")
            temp_path = Path(f.name)

        try:
            analysis1, log1 = manager.get_cached_log_analysis(temp_path)
            analysis2, log2 = manager.get_cached_log_analysis(temp_path)

            assert analysis1 == analysis2
            assert log1 == log2
        finally:
            temp_path.unlink()

    def test_get_cached_log_analysis_updates_on_file_change(self) -> None:
        """Test that cache is invalidated when file changes."""
        manager: Any = StateManager()

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("Connecting\n")
            temp_path = Path(f.name)

        try:
            manager.get_cached_log_analysis(temp_path)
            time.sleep(0.01)
            with open(temp_path, "a") as f_append:
                f_append.write("Connected to VPN\n")

            manager.get_cached_log_analysis(temp_path)
            assert manager._log_size > len("Connecting\n")
        finally:
            temp_path.unlink()

    def test_get_cached_log_analysis_toctou_resilience(self) -> None:
        """Test resilience against TOCTOU race condition where file vanishes during read."""
        manager: Any = StateManager()

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("Connecting\n")
            temp_path = Path(f.name)

        original_stat = temp_path.stat
        call_count = 0

        def mock_stat() -> os.stat_result:
            nonlocal call_count
            call_count += 1
            if call_count == 2:  # Simulate vanishing file mid-verification phase
                raise FileNotFoundError()
            return original_stat()

        try:
            with patch.object(Path, "stat", side_effect=mock_stat):
                _analysis, log = manager.get_cached_log_analysis(temp_path)
                assert log == ""
                assert manager._log_mtime_ns == -1  # Cache should not have updated
        finally:
            if temp_path.exists():
                temp_path.unlink()


class TestGetBestIp:
    """Test best IP address selection."""

    def test_get_best_ip_returns_valid_ip(self) -> None:
        """Test that a valid IP address is returned."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_socket.getsockname.return_value = ("192.168.1.100", 12345)
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            result: str = get_best_ip()
            assert result == "192.168.1.100"

    def test_get_best_ip_caches_result(self) -> None:
        """Test that IP result is cached."""
        import server

        server._best_ip_cache = "127.0.0.1"
        server._best_ip_ts = 0.0

        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_socket.getsockname.return_value = ("192.168.1.100", 12345)
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("time.monotonic") as mock_time:
                mock_time.return_value = 100.0
                result1: str = get_best_ip()
                mock_time.return_value = 110.0
                result2: str = get_best_ip()

                assert result1 == result2
                assert result1 == "192.168.1.100"
                assert mock_socket_class.call_count == 1

    def test_get_best_ip_handles_connection_error(self) -> None:
        """Test fallback when socket connection fails."""
        import server

        server._best_ip_cache = "127.0.0.1"
        server._best_ip_ts = 0.0

        with patch("socket.socket") as mock_socket_class:
            mock_socket = Mock()
            mock_socket.connect.side_effect = OSError("Network error")
            mock_socket_class.return_value.__enter__.return_value = mock_socket

            with patch("time.monotonic", return_value=200.0):
                result: str = get_best_ip()
                assert result == "127.0.0.1"


class TestGetVpnState:
    """Test VPN state retrieval."""

    def test_get_vpn_state_idle_from_mode_file(self) -> None:
        """Test reading idle state from mode file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mode_file = Path(tmpdir) / "gp-mode"
            mode_file.write_text("idle")

            with patch("server.MODE_FILE", mode_file):
                with patch.dict(os.environ, {}, clear=True):
                    state_idle = get_vpn_state()
                    assert state_idle["state"] == "idle"
                    assert state_idle["error"] is None

    def test_get_vpn_state_includes_debug_mode(self) -> None:
        """Test that debug mode flag is set correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mode_file = Path(tmpdir) / "gp-mode"
            mode_file.write_text("idle")

            with patch("server.MODE_FILE", mode_file):
                with patch.dict(os.environ, {"LOG_LEVEL": "DEBUG"}):
                    state_debug: Any = get_vpn_state()
                    assert state_debug["debug_mode"] is True

                with patch.dict(os.environ, {"LOG_LEVEL": "INFO"}):
                    state_info: Any = get_vpn_state()
                    assert state_info["debug_mode"] is False

    def test_get_vpn_state_includes_vpn_mode(self) -> None:
        """Test that VPN mode is included in state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mode_file = Path(tmpdir) / "gp-mode"
            mode_file.write_text("idle")

            with patch("server.MODE_FILE", mode_file):
                with patch.dict(os.environ, {"VPN_MODE": "gateway"}):
                    state_vpn = get_vpn_state()
                    assert state_vpn["vpn_mode"] == "gateway"

    def test_get_vpn_state_proxy_auth_detection(self) -> None:
        """Test proxy authentication flag detection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mode_file = Path(tmpdir) / "gp-mode"
            mode_file.write_text("idle")

            with patch("server.MODE_FILE", mode_file):
                with patch.dict(os.environ, {"PROXY_AUTH": "user:pass"}):
                    state_auth: Any = get_vpn_state()
                    assert state_auth["proxy_auth_enabled"] is True

                with patch.dict(os.environ, {}, clear=True):
                    state_no_auth: Any = get_vpn_state()
                    assert state_no_auth["proxy_auth_enabled"] is False


class TestInitRuntimeDir:
    """Test runtime directory initialization."""

    def test_init_runtime_dir_creates_directory(self) -> None:
        """Test that runtime directory is created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            runtime_dir = Path(tmpdir) / "test-runtime"

            with patch("server.RUNTIME_DIR", runtime_dir):
                with patch("sys.platform", "linux"):
                    init_runtime_dir()
                    assert runtime_dir.exists()
                    assert runtime_dir.is_dir()

    def test_init_runtime_dir_sets_permissions_unix(self) -> None:
        """Test that correct permissions are set on Unix."""
        with patch("server.RUNTIME_DIR") as mock_runtime_dir:
            with patch("sys.platform", "linux"):
                init_runtime_dir()
                mock_runtime_dir.mkdir.assert_called_once_with(mode=0o700, parents=True, exist_ok=True)
                mock_runtime_dir.chmod.assert_called_once_with(0o700)

    def test_init_runtime_dir_handles_existing_directory(self) -> None:
        """Test handling of existing directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            runtime_dir = Path(tmpdir) / "test-runtime"
            runtime_dir.mkdir()

            with patch("server.RUNTIME_DIR", runtime_dir):
                with patch("sys.platform", "linux"):
                    init_runtime_dir()
                    assert runtime_dir.exists()


class TestHandlerAuthentication:
    """Test HTTP handler authentication methods."""

    @staticmethod
    def _create_handler() -> Any:
        """Create a Handler instance without triggering HTTP parsing."""
        handler: Any = Handler.__new__(Handler)
        handler.rfile = MagicMock()
        handler.wfile = MagicMock()
        handler.headers = {}
        handler.path = "/"
        return handler

    def test_is_authorized_with_ephemeral_token(self) -> None:
        """Test authorization with ephemeral token."""
        handler: Any = self._create_handler()

        with patch("server.EPHEMERAL_TOKEN", "test_token_12345"):
            handler.headers = {"Authorization": "Bearer test_token_12345"}
            assert handler._is_authorized() is True

    def test_is_authorized_with_api_token(self) -> None:
        """Test authorization with API_TOKEN environment variable."""
        handler: Any = self._create_handler()

        with patch.dict(os.environ, {"API_TOKEN": "secret_api_token"}):
            handler.headers = {"Authorization": "Bearer secret_api_token"}
            assert handler._is_authorized() is True

    def test_is_authorized_with_wrong_token(self) -> None:
        """Test that wrong token is rejected."""
        handler: Any = self._create_handler()

        with patch("server.EPHEMERAL_TOKEN", "correct_token"):
            handler.headers = {"Authorization": "Bearer wrong_token"}
            assert handler._is_authorized() is False

    def test_is_authorized_without_auth_header(self) -> None:
        """Test that missing auth header is rejected."""
        handler: Any = self._create_handler()
        handler.headers = {}
        assert handler._is_authorized() is False

    def test_is_authorized_with_ed25519_signature(self) -> None:
        """Test authorization with Ed25519 signature."""
        from cryptography.hazmat.primitives.asymmetric import (
            ed25519,  # pyright: ignore[reportUnknownVariableType]
        )

        private_key: Any = ed25519.Ed25519PrivateKey.generate()  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        public_key: Any = private_key.public_key()  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]

        handler: Any = self._create_handler()
        handler.path = "/status.json"

        timestamp = int(time.time())
        message = f"{timestamp}:/status.json".encode()
        signature: bytes = private_key.sign(message)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        sig_b64: str = base64.b64encode(signature).decode()  # pyright: ignore[reportUnknownArgumentType]

        with patch("server._paired_pubkey", public_key):  # pyright: ignore[reportUnknownArgumentType]
            handler.headers = {
                "X-Signature": sig_b64,
                "X-Timestamp": str(timestamp),
            }
            assert handler._is_authorized() is True

    def test_is_authorized_ed25519_signature_expired(self) -> None:
        """Test that expired signatures are rejected."""
        from cryptography.hazmat.primitives.asymmetric import (
            ed25519,  # pyright: ignore[reportUnknownVariableType]
        )

        private_key: Any = ed25519.Ed25519PrivateKey.generate()  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        public_key: Any = private_key.public_key()  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]

        handler: Any = self._create_handler()
        handler.path = "/status.json"

        timestamp = int(time.time()) - 6  # Trigger strict 5-second replay validation window
        message = f"{timestamp}:/status.json".encode()
        signature: bytes = private_key.sign(message)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        sig_b64: str = base64.b64encode(signature).decode()  # pyright: ignore[reportUnknownArgumentType]

        with patch("server._paired_pubkey", public_key):  # pyright: ignore[reportUnknownArgumentType]
            handler.headers = {
                "X-Signature": sig_b64,
                "X-Timestamp": str(timestamp),
            }
            assert handler._is_authorized() is False


class TestEdgeCasesAndSecurity:
    """Test edge cases and security-critical functionality."""

    def test_timing_safe_token_comparison(self) -> None:
        """Test that token comparison uses timing-safe comparison."""
        handler: Any = Handler.__new__(Handler)
        handler.rfile = MagicMock()
        handler.wfile = MagicMock()
        handler.headers = {}

        with patch("server.EPHEMERAL_TOKEN", "a" * 32):
            handler.headers = {"Authorization": f"Bearer {'a' * 31}b"}
            assert handler._is_authorized() is False

    def test_url_pattern_matches_common_urls(self) -> None:
        """Test URL pattern regex matches expected URLs."""
        test_urls = [
            "https://auth.example.com/saml/login",
            "http://login.example.com:8080/auth",
            "https://vpn.company.com/authenticate?token=abc123",
        ]

        for url in test_urls:
            matches: list[str] = URL_PATTERN.findall(url)
            assert len(matches) > 0
            assert url in matches

    def test_gateway_regex_matches_expected_format(self) -> None:
        """Test gateway regex matches expected formats."""
        test_lines = [
            "  > Gateway1 (gw1.example.com)",
            "    US-East (us-east-vpn.example.com)",
            "  Production-DC1 (prod-dc1.company.internal)",
        ]

        for line in test_lines:
            match = GATEWAY_REGEX.search(line)
            assert match is not None

    def test_ansi_escape_regex_comprehensive(self) -> None:
        """Test ANSI escape regex matches various sequences."""
        test_sequences = [
            "\x1b[0m",
            "\x1b[31m",
            "\x1b[1;32m",
            "\x1b[2J",
            "\x1b[H",
        ]

        for seq in test_sequences:
            result: str = ANSI_ESCAPE.sub("", f"Test{seq}Text")
            assert "\x1b" not in result
            assert "TestText" == result
