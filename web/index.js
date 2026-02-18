// File: web/index.js

// --- Authentication Token Handling ---
// Automatically extract token from URL if provided (e.g. ?token=secret) and store securely.
const urlParams = new URLSearchParams(window.location.search);
const urlToken = urlParams.get("token");
if (urlToken) {
    localStorage.setItem("api_token", urlToken);
    window.history.replaceState({}, document.title, window.location.pathname);
}
const apiToken = localStorage.getItem("api_token");

/**
 * Helper to construct fetch options incorporating the Authorization header if required.
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
    document.querySelectorAll(".conn-tab-btn").forEach((b) => b.classList.remove("active"));

    const btns = document.querySelectorAll("button");
    btns.forEach((b) => {
        if (b.textContent.toLowerCase().includes(tab === "socks" ? "socks" : "gateway")) {
            b.classList.add("active");
        }
    });

    document.getElementById("sec-socks").style.display = tab === "socks" ? "block" : "none";
    document.getElementById("sec-gateway").style.display = tab === "gateway" ? "block" : "none";
}

/**
 * Updates dynamic IP address fields in the UI based on the current hostname.
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
    window.vpnState = null;
    setBadge("Generating Link...", "connecting");
    document.getElementById("btn-restart-auth").classList.add("hidden");
    await fetch("/connect", getFetchOptions("POST"));
    resetPoll(1000);
}

/**
 * Resets the SSO button state back to standard operation with a new URL.
 * @param {string} newUrl - The fresh URL to apply.
 */
function resetSSOButtonState(newUrl) {
    const btn = document.getElementById("sso-link");
    btn.classList.remove("btn-disabled");
    btn.innerText = "Open SSO Login";
    btn.href = newUrl;
    document.getElementById("btn-restart-auth").classList.add("hidden");
}

/**
 * Triggers a new VPN connection sequence.
 */
async function triggerConnect() {
    setBadge("Starting...", "connecting");
    setView("connecting");
    await fetch("/connect", getFetchOptions("POST"));
    resetPoll(1000);
}

/**
 * Disconnects the active VPN session with user confirmation.
 */
async function triggerDisconnect() {
    if (confirm("Disconnect VPN session?")) {
        setBadge("Disconnecting...", "idle");
        await fetch("/disconnect", getFetchOptions("POST"));
        resetPoll(1000);
    }
}

/**
 * Forcefully resets the connection sequence.
 */
async function confirmReset() {
    if (confirm("Force reset process? This will kill the VPN.")) {
        setBadge("Resetting...", "idle");
        await fetch("/disconnect", getFetchOptions("POST"));
        window.vpnState = null;
        isRestarting = false;
    }
}

/**
 * Handles form submissions via POST to the backend.
 * @param {Event} event - The form submission event.
 */
async function handleFormSubmit(event) {
    event.preventDefault();
    const formData = new URLSearchParams(new FormData(event.target));
    await fetch("/submit", getFetchOptions("POST", formData));
    setView("connecting");
    event.target.reset();
    resetPoll(1000);
}

/**
 * Periodically fetches and updates the frontend state from the backend.
 * Implements strict DOM diffing for dynamic inputs to preserve user focus.
 */
async function updateStatus() {
    try {
        const res = await fetch("/status.json?t=" + Date.now(), getFetchOptions("GET"));
        if (res.status === 401) {
            setBadge("Unauthorized (Check API Token)", "error");
            setView("error");
            return;
        }
        const data = await res.json();

        const showGateway = data.vpn_mode === "gateway" || data.vpn_mode === "standard";
        const showSocks = data.vpn_mode === "socks" || data.vpn_mode === "standard";

        const secSocks = document.getElementById("sec-socks");
        const secGateway = document.getElementById("sec-gateway");

        if (!showSocks) secSocks.classList.add("hidden");
        else secSocks.classList.remove("hidden");

        if (!showGateway) secGateway.classList.add("hidden");
        else secGateway.classList.remove("hidden");

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
            if (data.state === "error" || data.state === "connected") {
                isRestarting = false;
            } else if (data.state === "auth" && data.url && data.url !== lastAuthUrl) {
                isRestarting = false;
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
            if (!btn.classList.contains("btn-disabled")) {
                btn.href = data.url;
            }
        }

        if (data.error) document.getElementById("error-message").innerText = data.error;

        if (data.state === "input") {
            const container = document.getElementById("dynamic-input-container");
            const newOptionsStr = data.options ? data.options.join(",") : "";

            // DOM Diffing constraint: Only rebuild input elements when properties fundamentally change.
            if (
                container.dataset.prompt !== data.prompt ||
                container.dataset.type !== data.input_type ||
                container.dataset.options !== newOptionsStr
            ) {
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
            }
        }

        const fastStates = ["connecting", "auth", "input"];
        const newDelay = fastStates.includes(data.state) ? 1000 : 5000;
        resetPoll(newDelay);
    } catch (e) {
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
updateStatus();

// Responsive handling
window.addEventListener("resize", () => {
    if (window.innerWidth >= 640) {
        document.getElementById("sec-socks").style.display = "";
        document.getElementById("sec-gateway").style.display = "";
    } else {
        switchTab("socks");
    }
});
