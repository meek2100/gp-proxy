---
applyTo: "**"
---

# web/ — Frontend Conventions

Rules in this file apply to all files in `web/` and its subdirectories.
See the project root `AGENTS.md` for project-level architecture, security rules, and the sandbox protocol.

## DOM Diffing & Rendering

- `index.js` leverages HTML `dataset` attributes (`data.prompt`, `data.type`, `data.options`) on the dynamic input container. Elements are compared against stringified array structures `JSON.stringify()` to ensure they are only rebuilt when types or options fundamentally change; otherwise, only text labels are updated.
- **DOM Diffing Scope:** Query selectors managing UI state must strictly target exact classes (e.g. `.conn-tab-btn`) rather than raw elements (e.g. `<button>`) to prevent dynamic UI injections from hijacking unrelated states.
- Elements managed dynamically (like `btn`) must employ optional chaining (`?.classList`) to prevent crashes during conditional rendering.

## Error State Recovery

- Handlers rendering `data.error` payloads to the screen must actively wipe the DOM content (e.g., `el.innerText = data.error || ""`) when an error resolves to `null`. Omitting the fallback leaves stale error text permanently ghosted on the GUI.

## Network Resilience

- All UI actions that invoke API endpoints (`triggerConnect`, `handleFormSubmit`, etc.) must be wrapped in `try/catch/finally` blocks to ensure the frontend polling loop (`resetPoll`) resurrects if a network exception occurs. This prevents the UI from becoming permanently locked in a 'loading' state.
- 401 exceptions must forcefully command `window.location.reload()` to ensure background loop resurrection and ephemeral token extraction upon credential fixing.

## State Deadlock Prevention

- Generating new SSO links must briefly toggle an `isRestarting` safety flag to suspend polling jitter.

## Dynamic Proxy UI Rendering

- The backend surfaces configured proxies as JSON arrays (`proxy_modes`) along with a `proxy_auth_enabled` boolean. The frontend strictly relies on array matching (`ALL_TABS.includes()`) and DOM class toggling (`hidden-mode`) to safely control layout scaling and proxy info display.

## Ephemeral Token Handling

- The server injects the `EPHEMERAL_TOKEN` into a `<meta name="session-token">` tag in `index.html` on startup. JavaScript must extract this token from the meta tag automatically and attach it to all API `Authorization: Bearer <token>` requests. Do not hardcode or cache the token across sessions.
