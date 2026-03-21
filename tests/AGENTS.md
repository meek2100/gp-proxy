---
applyTo: "**"
---

# tests/ — Python Test Suite Conventions

Rules in this file apply to all files in `tests/` and its subdirectories.
See `backend/AGENTS.md` for production Python conventions, and the project root `AGENTS.md` for the sandbox protocol.

## Test Runner & Configuration

- Uses `pytest`. Run with `pytest tests/` from the project root.
- Test files map 1:1 to backend modules: `test_server.py` → `server.py`, `test_utils.py` → `utils.py`, etc.
- All test files must add the `backend/` directory to `sys.path` at the top of file to allow direct module imports without installing the package.

## File-Level Suppression

- Add `# pyright: reportPrivateUsage=false` at the top of any test file that accesses private members (prefixed `_`). Do not suppress at a narrower scope.

## Test Structure

- Group tests into classes using the pattern `class Test<SubjectName>:`.
- One class per logical unit under test (e.g., `TestStateManager`, `TestHandlerAuthentication`).
- Every test method starts with `test_` and has a single-line docstring describing what it asserts.
- Each test must assert exactly one behavior. Split multi-behavior validations into separate test methods.

## Private Member Access

- Module-level private functions (e.g., `server._evaluate_line_state`) must be aliased at module scope for readability:
  ```python
  evaluate_line_state = server._evaluate_line_state
  ```
- Access private instance attributes (e.g., `manager._last_state`) using a cast to `Any` via `cast(Any, ...)` or a local `Any`-typed variable to satisfy Pyright without broad suppression.

## Mocking

- Use `unittest.mock.patch` as a context manager or decorator — never apply patches globally across test methods.
- When patching module-level globals in `server` (e.g., `server.EPHEMERAL_TOKEN`, `server._paired_pubkey`), always use the fully qualified `"server.<name>"` patch target.
- Use `tempfile.NamedTemporaryFile` and `tempfile.TemporaryDirectory` with `delete=False` for file-based tests. Always clean up in a `finally` block.

## Concurrency Tests

- Stress tests involving threads (e.g., `test_state_manager_concurrency_stress`) must use a `stop_flag` boolean (not an `Event`) to terminate writer threads, and `ThreadPoolExecutor` for reader pools.
- Join all threads and clean up temp files in a `finally` block — never leave dangling threads across test boundaries.

## Security & Replay Attack Tests

- Replay attack tests must use `int(time.time()) - 6` to reliably exceed the 5-second boundary window enforced by the server.
- Every Ed25519 signing test must generate a fresh `Ed25519PrivateKey` per test method — never reuse keys across tests.
- Timing-safe comparison tests must verify rejection on near-miss tokens (e.g., correct length, one character different) to confirm `hmac.compare_digest()` is in use.

## TOCTOU & Resilience Tests

- Tests simulating file disappearance mid-read must use `patch.object(Path, "stat", side_effect=...)` with a call counter to trigger the failure only on the second stat call.
- After a simulated TOCTOU failure, assert that the cache sentinel values (`_log_mtime_ns == -1`) remain unchanged, confirming the cache was not promoted on a failed read.
