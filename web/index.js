// File: web/index.js

// --- Authentication Token Handling ---
let apiToken = localStorage.getItem("api_token");

// Automatically load Ephemeral Session Token from meta tag injection to bypass legacy manual keys
const metaToken = document.querySelector('meta[name="session-token"]')?.getAttribute("content");
if (metaToken && metaToken !== "EPHEMERAL_TOKEN_PLACEHOLDER") {
    apiToken = metaToken;
}

// Automatically extract token from URL if provided (e.g. ?token=secret) and store.
// Syncs across tabs automatically via the storage event to maintain valid legacy session states.
const urlParams = new URLSearchParams(window.location.search);
const urlToken = urlParams.get("token");
if (urlToken) {
    localStorage.setItem("api_token", urlToken);

    // Safety check: Only override the active token if the secure meta injection is missing or uninitialized.
    if (!metaToken || metaToken === "EPHEMERAL_TOKEN_PLACEHOLDER") {
        apiToken = urlToken;
    }

    window.history.replaceState({}, document.title, window.location.pathname);
}

window.addEventListener("storage", (e) => {
    if (e.key === "api_token" && (!metaToken || metaToken === "EPHEMERAL_TOKEN_PLACEHOLDER")) {
        apiToken = e.newValue;
    }
});

/**
 * Helper to construct fetch options incorporating the Authorization header if required.
 * If the apiToken is missing or rejected by the backend, the server will return a 401 Unauthorized,
 * which the polling loop detects to present an error state to the user.
 * @param {string} method - HTTP Method
 * @param {BodyInit|null} body - Request body
 * @returns {RequestInit}
 */
function getFetchOptions(method = "GET", body = null) {
    const headers = {};
    if (apiToken) {
        headers["Authorization"] = `Bearer ${apiToken}`;
    }
    const options = { method, headers };
    if (body) {
        options.body = body;
    }
    return options;
}

/**
 * Initializes the application theme based on local storage or system preferences.
 */
function initTheme() {
    const stored = localStorage.getItem("theme");
    const sysDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    let theme = "light";
    if (stored) {
        theme = stored;
    } else if (sysDark) {
        theme = "dark";
    }
    document.documentElement.setAttribute("data-theme", theme);
    updateAssets(theme);
}

/**
 * Toggles between dark and light themes, saves the preference to localStorage.
 */
function toggleTheme() {
    const current = document.documentElement.getAttribute("data-theme");
    const next = current === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("theme", next);
    updateAssets(next);
}

/**
 * Updates specific images (like logos and favicons) to match the current theme.
 * @param {string} theme - 'dark' or 'light'.
 */
function updateAssets(theme) {
    const logo = document.getElementById("app-logo");
    const favicon = document.getElementById("app-favicon");
    if (theme === "dark") {
        logo.src = "assets/logo-light.png";
        favicon.href = "assets/favicon-light.ico";
    } else {
        logo.src = "assets/logo-dark.png";
        favicon.href = "assets/favicon.ico";
    }
}

// --- APP LOGIC ---
window.vpnState = null;
let pollInterval = null;
let lastAuthUrl = "";
let isRestarting = false;

/**
 * Switches the active connection detail tab on mobile devices.
 * @param {string} tab - The tab to activate ('socks' or 'gateway').
 */
function switchTab(tab) {
    // DOM selection via explicit datasets prevents inner-text language/localization bugs
    const btns = document.querySelectorAll(".conn-tab-btn");
    btns.forEach((b) => b.classList.remove("active"));

    btns.forEach((b) => {
        if (b.dataset.tab === tab) {
            b.classList.add("active");
        }
    });

    document.getElementById("sec-socks").style.display = tab === "socks" ? "block" : "none";
    document.getElementById("sec-gateway").style.display = tab === "gateway" ? "block" : "none";

    // Accessibility focus management on tab change
    const activeSection = document.getElementById(tab === "socks" ? "sec-socks" : "sec-gateway");
    if (activeSection) {
        const header = activeSection.querySelector(".conn-header");
        if (header) {
            header.setAttribute("tabindex", "-1");
            header.focus();
        }
    }
}

/**
 * Updates dynamic IP address fields in the UI based on the current hostname.
 * Provides a basic fallback until updateStatus fetches the true IP from the backend.
 */
function updateIPs() {
    const host = window.location.hostname;
    document.querySelectorAll(".dyn-ip").forEach((el) => (el.innerText = host));
}

/**
 * Copies the text content of a given element to the clipboard and shows visual feedback.
 * Uses a robust fallback for non-secure contexts.
 * @param {HTMLElement} el - The element to copy from.
 */
async function copyToClip(el) {
    const text = el.innerText.trim();
    const originalBg = el.style.backgroundColor;
    const originalColor = el.style.color;

    const triggerSuccess = () => {
        el.style.backgroundColor = "var(--accent-green)";
        el.style.color = "white";
        setTimeout(() => {
            el.style.backgroundColor = originalBg;
            el.style.color = originalColor || "";
        }, 200);
    };

    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
            triggerSuccess();
            return;
        }

        // Fallback for non-secure contexts (e.g., local IP HTTP access)
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.top = "0";
        textArea.style.left = "0";
        textArea.style.position = "fixed";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        const successful = document.execCommand("copy");
        textArea.remove();

        if (successful) {
            triggerSuccess();
        } else {
            console.warn("Fallback clipboard copy failed.");
        }
    } catch (err) {
        console.warn("Clipboard copy failed", err);
    }
}

/**
 * Updates the active view panel, hiding all others.
 * @param {string} viewId - The ID of the view to switch to (e.g. 'idle', 'connecting').
 */
function setView(viewId) {
    ["idle", "connecting", "auth", "input", "connected", "error"].forEach((id) => {
        document.getElementById(`view-${id}`).classList.add("hidden");
    });
    const activeView = document.getElementById(`view-${viewId}`);
    activeView.classList.remove("hidden");

    // Accessibility focus management
    const heading = activeView.querySelector("h3, h2");
    if (heading) {
        heading.focus();
    }

    const card = document.getElementById("main-card");
    if (viewId === "connected") {
        card.classList.add("expanded");
    } else {
        card.classList.remove("expanded");
    }
}

/**
 * Updates the status badge element.
 * @param {string} text - The text to display.
 * @param {string} type - The state classification (e.g. 'idle', 'error').
 */
function setBadge(text, type) {
    const badge = document.getElementById("status-badge");
    const txt = document.getElementById("badge-text");
    badge.className = `badge ${type}`;
    txt.innerText = text;
}

/**
 * Disables the SSO link button after click.
 * @param {HTMLElement} btn - The button clicked.
 */
function handleSSOClick(btn) {
    btn.classList.add("btn-disabled");
    btn.innerText = "Link Opened";
    document.getElementById("btn-restart-auth").classList.remove("hidden");
}

/**
 * Restarts the auth sequence by issuing a new connect command to generate a fresh SSO link.
 */
async function restartAuth() {
    isRestarting = true;
    window.expectedNextState = "auth_refresh";

    // 15-second safety timeout to prevent infinite deadlocks if the backend transitions silently
    setTimeout(() => {
        isRestarting = false;
        window.expectedNextState = null;
    }, 15000);

    window.vpnState = null;
    setBadge("Generating Link...", "connecting");
    document.getElementById("btn-restart-auth").classList.add("hidden");

    try {
        await fetch("/connect", getFetchOptions("POST"));
    } catch (e) {
        console.error("Failed to restart auth:", e);
    } finally {
        resetPoll(1000);
    }
}

/**
 * Resets the SSO button state back to standard operation with a new URL.
 * @param {string} newUrl - The fresh URL to apply.
 */
function resetSSOButtonState(newUrl) {
    const btn = document.getElementById("sso-link");
    if (btn) {
        btn.classList.remove("btn-disabled");
        btn.innerText = "Open SSO Login";
        btn.href = newUrl;
    }
    const restartBtn = document.getElementById("btn-restart-auth");
    if (restartBtn) {
        restartBtn.classList.add("hidden");
    }
}

/**
 * Triggers a new VPN connection sequence.
 */
async function triggerConnect() {
    setBadge("Starting...", "connecting");
    setView("connecting");
    window.expectedNextState = "connecting";
    isRestarting = true;

    setTimeout(() => {
        isRestarting = false;
        window.expectedNextState = null;
    }, 15000);

    try {
        await fetch("/connect", getFetchOptions("POST"));
    } catch (e) {
        console.error("Connect fetch failed:", e);
    } finally {
        resetPoll(1000);
    }
}

/**
 * Disconnects the active VPN session with user confirmation.
 */
async function triggerDisconnect() {
    if (confirm("Disconnect VPN session?")) {
        setBadge("Disconnecting...", "idle");
        window.expectedNextState = "idle";
        isRestarting = true;

        setTimeout(() => {
            isRestarting = false;
            window.expectedNextState = null;
        }, 15000);

        try {
            await fetch("/disconnect", getFetchOptions("POST"));
        } catch (e) {
            console.error("Disconnect fetch failed:", e);
        } finally {
            resetPoll(1000);
        }
    }
}

/**
 * Forcefully resets the connection sequence.
 */
async function confirmReset() {
    if (confirm("Force reset process? This will kill the VPN.")) {
        setBadge("Resetting...", "idle");
        window.expectedNextState = "idle";
        isRestarting = true;

        setTimeout(() => {
            isRestarting = false;
            window.expectedNextState = null;
        }, 15000);

        try {
            await fetch("/disconnect", getFetchOptions("POST"));
        } catch (e) {
            console.error("Force reset fetch failed:", e);
        } finally {
            window.vpnState = null;
            resetPoll(1000);
        }
    }
}

/**
 * Handles form submissions via POST to the backend.
 * @param {Event} event - The form submission event.
 */
async function handleFormSubmit(event) {
    event.preventDefault();
    const formData = new URLSearchParams(new FormData(event.target));

    isRestarting = true;
    window.expectedNextState = "connecting";

    setTimeout(() => {
        isRestarting = false;
        window.expectedNextState = null;
    }, 15000);

    try {
        await fetch("/submit", getFetchOptions("POST", formData));
        setView("connecting");
        setBadge("CONNECTING...", "connecting");
        event.target.reset();
    } catch (e) {
        console.error("Form submit failed:", e);
    } finally {
        resetPoll(1500);
    }
}

/**
 * Fetches the VPN logs through the authorized JS fetch wrapper instead of a static link.
 * @param {Event} event - The click event.
 */
async function downloadLogs(event) {
    if (event) event.preventDefault();
    try {
        const res = await fetch("/download_logs", getFetchOptions("GET"));
        if (!res.ok) {
            throw new Error(`HTTP error! status: ${res.status}`);
        }
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.style.display = "none";
        a.href = url;
        a.download = "vpn_full_debug.log";
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();
    } catch (e) {
        console.error("Failed to download logs:", e);
        alert("Failed to download logs. Ensure debug mode is enabled and you are authorized.");
    }
}
window.downloadLogs = downloadLogs;

/**
 * Periodically fetches and updates the frontend state from the backend.
 * Implements strict DOM diffing for dynamic inputs to preserve user focus.
 * If API token validation fails, presents the user with an authorization error.
 */
async function updateStatus() {
    try {
        const res = await fetch("/status.json?t=" + Date.now(), getFetchOptions("GET"));
        if (!res.ok) {
            if (res.status === 401) {
                setBadge("Unauthorized (Check Key Exchange)", "error");
                setView("error");
            } else {
                throw new Error(`HTTP Error: ${res.status}`);
            }
            resetPoll(5000); // Ensure polling resumes so corrections resolve naturally
            return;
        }
        const data = await res.json();

        // Enforce valid numerical IPv4 address for network settings mapping
        const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        const displayIp = ipv4Regex.test(window.location.hostname)
            ? window.location.hostname
            : data.server_ip || window.location.hostname;

        document.querySelectorAll(".dyn-ip").forEach((el) => {
            if (el.innerText !== displayIp) el.innerText = displayIp;
        });

        const showGateway = data.vpn_mode === "gateway" || data.vpn_mode === "standard";
        const showSocks = data.vpn_mode === "socks" || data.vpn_mode === "standard";

        const secSocks = document.getElementById("sec-socks");
        const secGateway = document.getElementById("sec-gateway");

        if (!showSocks) secSocks.classList.add("hidden");
        else secSocks.classList.remove("hidden");

        if (!showGateway) secGateway.classList.add("hidden");
        else secGateway.classList.remove("hidden");

        // Dynamically toggle the UI labels
        const socksPortEl = document.getElementById("socks-port");
        if (socksPortEl) socksPortEl.innerText = "1080";

        const gatewayMaskEl = document.getElementById("gateway-mask");
        if (gatewayMaskEl) gatewayMaskEl.innerText = "255.255.255.0";

        const authTextEl = document.getElementById("socks-auth-text");
        if (authTextEl) {
            authTextEl.innerText = data.socks_auth_enabled ? "See Env Config" : "None (Network Allowed)";
        }

        if (window.innerWidth < 640 && showSocks && showGateway) {
            if (secSocks.style.display === "" && secGateway.style.display === "") {
                switchTab("socks");
            }
        }

        const debugSec = document.getElementById("debug-section");
        if (data.debug_mode) {
            debugSec.classList.remove("hidden");
            debugSec.style.display = "flex";
            document.getElementById("debug-log").innerText = data.log || "Waiting for logs...";
        } else {
            debugSec.classList.add("hidden");
            debugSec.style.display = "none";
        }

        if (isRestarting) {
            if (data.state === window.expectedNextState || data.state === "error" || data.state === "connected") {
                isRestarting = false;
                window.expectedNextState = null;
            } else if (
                window.expectedNextState === "auth_refresh" &&
                data.state === "auth" &&
                data.url &&
                data.url !== lastAuthUrl
            ) {
                isRestarting = false;
                window.expectedNextState = null;
            } else {
                resetPoll(1000);
                return;
            }
        }

        if (window.vpnState !== data.state) {
            setView(data.state);
            setBadge(data.state.toUpperCase(), data.state === "auth" || data.state === "input" ? "auth" : data.state);
            window.vpnState = data.state;
        }

        if (data.url) {
            if (data.url !== lastAuthUrl) {
                lastAuthUrl = data.url;
                resetSSOButtonState(data.url);
            }
            const btn = document.getElementById("sso-link");
            if (btn && !btn.classList.contains("btn-disabled")) {
                btn.href = data.url;
            }
        }

        const errorMsgEl = document.getElementById("error-message");
        if (errorMsgEl) {
            // Fix: ensures that previously displayed errors are cleared when resolved
            errorMsgEl.innerText = data.error || "";
        }

        if (data.state === "input") {
            const container = document.getElementById("dynamic-input-container");
            // Reliable DOM boundary assertion prevents injection bugs
            const newOptionsStr = data.options ? JSON.stringify(data.options) : "[]";

            // DOM Diffing constraint: Only rebuild input elements when properties fundamentally change.
            const needsFullRebuild =
                container.dataset.type !== data.input_type || container.dataset.options !== newOptionsStr;

            if (needsFullRebuild) {
                container.innerHTML = "";
                container.dataset.prompt = data.prompt;
                container.dataset.type = data.input_type;
                container.dataset.options = newOptionsStr;

                const label = document.createElement("label");
                label.textContent = data.prompt;
                label.htmlFor = "vpn_user_input";
                label.style.display = "block";
                label.style.marginBottom = "8px";
                label.style.fontWeight = "600";
                container.appendChild(label);

                if (data.input_type === "select" && Array.isArray(data.options)) {
                    const select = document.createElement("select");
                    select.id = "vpn_user_input";
                    select.name = "user_input";
                    select.required = true;
                    data.options.forEach((opt) => {
                        const option = document.createElement("option");
                        option.value = opt;
                        option.textContent = opt;
                        select.appendChild(option);
                    });
                    container.appendChild(select);
                } else {
                    const input = document.createElement("input");
                    input.id = "vpn_user_input";
                    input.type = data.input_type === "password" ? "password" : "text";
                    input.name = "user_input";
                    input.required = true;
                    container.appendChild(input);
                }
            } else if (container.dataset.prompt !== data.prompt) {
                // Safely update the label text if only the prompt changed, maintaining focus on the input box
                container.dataset.prompt = data.prompt;
                const label = container.querySelector("label");
                if (label) {
                    label.textContent = data.prompt;
                }
            }
        }

        const fastStates = ["connecting", "auth", "input"];
        const newDelay = fastStates.includes(data.state) ? 1000 : 5000;
        resetPoll(newDelay);
    } catch (e) {
        console.error("Status update failed:", e);
        resetPoll(5000);
    }
}

/**
 * Resets the polling timer to execute `updateStatus`.
 * @param {number} delay - Milliseconds to delay before fetching.
 */
function resetPoll(delay) {
    if (pollInterval) clearTimeout(pollInterval);
    pollInterval = setTimeout(updateStatus, delay);
}

// Initialization
initTheme();
updateIPs();
updateStatus().catch((e) => console.error("Initial status fetch failed:", e));

// Responsive handling
window.addEventListener("resize", () => {
    if (window.innerWidth >= 640) {
        document.getElementById("sec-socks").style.display = "";
        document.getElementById("sec-gateway").style.display = "";
    } else {
        switchTab("socks");
    }
});
