---
applyTo: "**"
---

# backend/ — Python Container Agent Conventions

Rules in this file apply to all Python source files in `backend/` and its subdirectories.
See the project root `AGENTS.md` for project-level architecture, the sandbox protocol, and security rules.

## Python Language Rules

- **Formatter:** `ruff` with line length 120. **Linter:** `ruff` + strict `mypy`/`pyright`. Project uses **Python 3.14**.
- All module-level files must include descriptive docstrings.
- Do not use subscripted generics for `socket.socket` — `typeshed` strictness rejects type arguments like `[Any, Any]`.
- Overriding class attributes must utilize `typing.ClassVar` to satisfy strict Pyright/Mypy checks.
- Discarded process outputs (`stdout=subprocess.DEVNULL`) must be typed strictly as `CompletedProcess[bytes]`. Use `capture_output=True` when polling processes to satisfy strict Mypy without discarding typing.
- **Exception Syntax:** Multi-target exceptions must strictly use the Python 3 tuple syntax `except (ValueError, KeyError, TypeError):`. If the `ruff format` pre-commit hook strips required parentheses, apply `# fmt: skip` at the end of the line.
- **Network Resilience:** Socket loops using `.settimeout()` must explicitly catch `(OSError, TimeoutError)` tuples to prevent ungraceful daemon crashes during dead client timeouts.

## server.py — Guardrails (DO NOT REMOVE)

- **State Management:** Uses a thread-safe `StateManager` to handle concurrent access from the log analyzer and HTTP requests.
- **Strict I/O Caching:** `StateManager` restricts disk reads for `CLIENT_LOG` by verifying `.stat().st_mtime`, `.st_size`, and `.st_ino` to defend against high-speed rotation replacements. Direct reads on 1-second polling intervals trigger critical CPU/GIL degradation. The file read operation must execute strictly _outside_ the `StateManager` thread lock to prevent serializing concurrent web UI requests.
- **HTTP Network Resiliency:** HTTP Handlers must evaluate `getattr(self, "path", "")` instead of direct `self.path` access to prevent `AttributeError` thread crashes if clients drop the TCP handshake early.
- **Atomic API State:** The nil-check (`_paired_pubkey is None`) **and** the assignment to `_paired_pubkey` must occur inside a single `with _pairing_lock:` acquisition. Splitting the guard across lock boundaries reopens the TOCTOU race.
- **Idempotent Token Injection:** Operations that modify `index.html` on boot must use `re.sub` regex patterns rather than standard string `.replace()`. The payload must be idempotent to guarantee successful updates after container restarts.
- **Deterministic Fallbacks:** When generating cache-busting `build_hash` identifiers, avoid stochastic elements like `time.time()`. Fallback identifiers must remain deterministic to preserve immutable cache semantics across restarts.
- **Process Orchestration:** `_kill_and_poll_unix()` verifies `CAP_KILL` or passwordless `sudo` at boot. If lacking permission to terminate network daemons, it exits with a fatal error instead of failing silently. It relies on `subprocess.run(..., capture_output=True)` to return byte streams satisfying strict Mypy types. Processes refusing to terminate gracefully are escalated to `SIGKILL` (-9).

## Concurrency & Thread Safety

- Python web server instantiation via `socketserver.ThreadingTCPServer` causes concurrent multi-threaded requests.
- Background utility functions, especially module-level initialization blocks like `setup_logger`, MUST be wrapped in explicit `threading.Lock()` acquisitions to prevent duplication.

## IPC Execution (control_listener.py / stdin_proxy.py)

- Control endpoints rely on OS-agnostic local TCP sockets (`127.0.0.1:32801`, `127.0.0.1:32802`) instead of POSIX FIFOs to guarantee out-of-container testing compatibility on Windows.
- Listener endpoints must utilize a non-blocking `select.select` wait approach inside a `while True` loop to act as persistent daemons capable of receiving graceful interrupt signals.
- IPC byte streams must be buffered and split strictly on newlines (`\n`) prior to UTF-8 decoding.

## IPC Payload Sanitization

All HTTP `/submit` parameters mapped into IPC streams MUST be rigorously sanitized for internal newline injections (`\r`, `\n`) prior to socket dispatch. Unfiltered payloads permit arbitrary shell interaction escapes. Handlers must strictly filter standard HTTP errors (`ValueError`, `KeyError`, `TypeError`) before catching generic `Exception` objects.

## System Privileges

Sudoers permissions in the Dockerfile strictly utilize `Cmnd_Alias` to lock down `/usr/bin/pkill` and `/usr/bin/pgrep` to precise `gpclient` and `gpservice` arguments, preventing arbitrary process termination.
