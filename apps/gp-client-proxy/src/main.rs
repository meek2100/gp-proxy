// File: apps/gp-client-proxy/src/main.rs
use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use directories::ProjectDirs;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(not(target_os = "windows"))]
use std::process::Command;

// --- EMBEDDED ASSETS ---
#[cfg(target_os = "linux")]
const ICON_PNG: &[u8] = include_bytes!("../assets/icon.png");

#[cfg(target_os = "macos")]
const ICON_ICNS: &[u8] = include_bytes!("../assets/AppIcon.icns");

// Constants
const UDP_PORT: u16 = 32800;
const DISCOVERY_MSG: &str = "GP_DISCOVER";
const PROTOCOL_SCHEME: &str = "globalprotect";
const APP_NAME: &str = "GP Client Proxy";
const CONFIG_FILE_NAME: &str = "proxy_url.txt";

#[cfg(not(target_os = "windows"))]
const BINARY_NAME: &str = "gp-client-proxy";

// --- DATA STRUCTURES ---
#[derive(Deserialize, Debug)]
struct ServerStatus {
    state: String,    // idle, connecting, auth, connected, error
    vpn_mode: String, // standard, gateway, socks

    // Properly deserialized as null when no error is present due to Python server returning `None` instead of `""`
    #[allow(dead_code)]
    error: Option<String>,

    #[serde(default)]
    socks_auth_enabled: bool,
}

#[derive(Deserialize, Debug)]
struct DiscoveryResponse {
    ip: String,
    port: u16,
}

#[derive(Serialize, Debug)]
struct PairRequest {
    public_key: String,
}

#[derive(Clone, Debug)]
struct ProxyConfig {
    base_url: String,
    token: String,
    private_key: Option<[u8; 32]>,
}

impl ProxyConfig {
    /// Builds the frontend URL and appends the legacy API token as a `token` query parameter when configured.
    ///
    /// If the config has an empty token (TOFU mode), returns the base URL unchanged; otherwise returns the base URL with `/?token=<encoded-token>`.
    ///
    /// # Examples
    ///
    /// ```
    /// let cfg_with_token = ProxyConfig { base_url: "https://example.com".into(), token: "s3cr3t".into(), private_key: None };
    /// assert!(cfg_with_token.browser_url().starts_with("https://example.com/?token="));
    ///
    /// let cfg_no_token = ProxyConfig { base_url: "https://example.com".into(), token: "".into(), private_key: None };
    /// assert_eq!(cfg_no_token.browser_url(), "https://example.com");
    /// ```
    fn browser_url(&self) -> String {
        if self.token.is_empty() {
            // When using TOFU, the web interface utilizes a securely injected ephemeral token.
            self.base_url.clone()
        } else {
            format!("{}/?token={}", self.base_url, encode_token(&self.token))
        }
    }
}

/// Percent-encodes a token for safe inclusion in URLs, preserving unreserved characters.
///
/// The returned string encodes every byte outside ASCII letters, digits, and the characters
/// `-`, `_`, `.`, and `~` as `%` followed by two uppercase hex digits.
///
/// # Examples
///
/// ```
/// let s = encode_token("user:pass@host");
/// assert_eq!(s, "user%3Apass%40host");
/// ```
fn encode_token(token: &str) -> String {
    token
        .as_bytes()
        .iter()
        .map(|&b| match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{:02X}", b),
        })
        .collect()
}

/// Adds authentication headers to a ureq request according to the provided ProxyConfig.
///
/// If `config.token` is non-empty, sets `Authorization: Bearer <token>`. Otherwise, if
/// `config.private_key` is present, signs the string `"<timestamp>:<path>"` using Ed25519
/// and sets `X-Timestamp` (seconds since UNIX epoch) and `X-Signature` (base64 of the signature).
/// If neither token nor private key is available, returns the original request unchanged.
///
/// # Parameters
/// - `req` — the request builder to augment.
/// - `config` — proxy configuration that may contain a legacy token or an Ed25519 private key.
/// - `path` — request path used when constructing the signed message (for example `"/connect"`).
///
/// # Returns
/// The request builder with authentication headers applied when possible.
///
/// # Examples
///
/// ```
/// # use crate::ProxyConfig;
/// # fn example() {
/// let cfg = ProxyConfig { base_url: "http://localhost".into(), token: "token123".into(), private_key: None };
/// let req = ureq::get("http://localhost/status.json");
/// let authed = with_auth(req, &cfg, "/status.json");
/// let _resp = authed.call().ok();
/// # }
/// ```
fn with_auth<T>(
    req: ureq::RequestBuilder<T>,
    config: &ProxyConfig,
    path: &str,
) -> ureq::RequestBuilder<T> {
    if !config.token.is_empty() {
        // Legacy manual API_TOKEN locking
        req.header("Authorization", &format!("Bearer {}", config.token))
    } else if let Some(key_bytes) = &config.private_key {
        // Trust On First Use (TOFU) Cryptographic Ed25519 Signing
        let signing_key = SigningKey::from_bytes(key_bytes);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let message = format!("{}:{}", ts, path);
        let signature = signing_key.sign(message.as_bytes());
        let sig_b64 = general_purpose::STANDARD.encode(signature.to_bytes());

        req.header("X-Timestamp", &ts.to_string())
            .header("X-Signature", &sig_b64)
    } else {
        req
    }
}

/// Program entry point that dispatches between the protocol handler, uninstaller, and interactive dashboard.
fn main() -> Result<()> {
    env_logger::init();
    let args: Vec<String> = env::args().collect();

    // MODE 1: PROTOCOL HANDLER (Silent / Background)
    if args.len() > 1 && args[1].starts_with("globalprotect://") {
        match handle_link(&args[1]) {
            Ok(_) => return Ok(()),
            Err(e) => {
                eprintln!("Error handling link: {:#}", e);
                std::process::exit(1);
            }
        }
    }

    // MODE 2: UNINSTALLATION
    if args.len() > 1 && args[1] == "--uninstall" {
        uninstall_process()?;
        return Ok(());
    }

    // MODE 3: DASHBOARD / LAUNCHER (Interactive)
    run_dashboard()?;
    Ok(())
}

// --- HTTP AGENTS ---

/// Create a preconfigured HTTP agent with a 10-second global timeout for standard actions.
fn get_agent() -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .build();
    ureq::Agent::new_with_config(config)
}

/// Create a preconfigured HTTP agent with a fast 2-second global timeout specifically for the status polling loop.
/// This prevents the CLI loop from hanging entirely if the backend blocks unexpectedly.
fn get_fast_agent() -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(2)))
        .build();
    ureq::Agent::new_with_config(config)
}

// =============================================================================
// DASHBOARD LOGIC
// =============================================================================

/// Displays the interactive dashboard and launcher for the GP Client Proxy.
fn run_dashboard() -> Result<()> {
    let mut config = match load_config() {
        Ok(c) => c,
        Err(_) => {
            println!("No configuration found. Starting Setup...");
            return run_setup_wizard();
        }
    };

    let agent = get_agent();
    let fast_agent = get_fast_agent();

    loop {
        clear_screen();
        print_header();

        match load_config() {
            Ok(c) => config = c,
            Err(e) => {
                eprintln!("[WARNING] Failed to reload config: {}", e);
            }
        }

        let status = fetch_status(&config, &fast_agent);

        match &status {
            Ok(s) => {
                println!("SERVER:    Online ({})", config.base_url);
                println!("STATUS:    {}", s.state.to_uppercase());
                println!("MODE:      {}", s.vpn_mode.to_uppercase());

                if s.state == "connected" {
                    println!("\n[i] CONNECTION DETAILS");
                    let host_ip = config
                        .base_url
                        .trim_start_matches("http://")
                        .trim_start_matches("https://")
                        .split(':')
                        .next()
                        .unwrap_or("Unknown");

                    if s.vpn_mode == "socks" || s.vpn_mode == "standard" {
                        let auth_str = if s.socks_auth_enabled {
                            "(Auth Enabled)"
                        } else {
                            "(No Auth)"
                        };
                        println!("SOCKS5 Proxy:  {}:1080 {}", host_ip, auth_str);
                    }
                    if s.vpn_mode == "gateway" || s.vpn_mode == "standard" {
                        println!("Gateway IP:    {}", host_ip);
                        println!("DNS Server:    {}", host_ip);
                    }
                }
            }
            Err(_) => {
                println!("SERVER:    Unreachable ({})", config.base_url);
                println!("STATUS:    OFFLINE (Or Unauthorized)");
            }
        }
        println!("----------------------------------------");
        println!("1. Open Web Dashboard (Browser)");

        if let Ok(s) = &status {
            if s.state == "connected" {
                println!("2. Disconnect VPN");
            } else {
                println!("2. Connect VPN");
            }
        } else {
            println!("2. Retry Connection");
        }

        println!("3. Re-run Setup / Discovery");
        println!("4. Uninstall");
        println!("5. Exit");

        print!("\nSelection > ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim() {
            "1" => {
                let _ = webbrowser::open(&config.browser_url());
            }
            "2" => {
                if let Ok(s) = &status {
                    if s.state == "connected" {
                        println!("Disconnecting...");
                        let req = agent.post(&format!("{}/disconnect", config.base_url));
                        if let Err(e) = with_auth(req, &config, "/disconnect").send_empty() {
                            println!("Error disconnecting: {}", e);
                            thread::sleep(Duration::from_secs(2));
                        } else {
                            thread::sleep(Duration::from_secs(1));
                        }
                    } else {
                        println!("Initiating Connection...");
                        let req = agent.post(&format!("{}/connect", config.base_url));
                        if let Err(e) = with_auth(req, &config, "/connect").send_empty() {
                            println!("Error initiating connection: {}", e);
                            thread::sleep(Duration::from_secs(2));
                        } else {
                            println!("Launching Browser for Auth...");
                            let _ = webbrowser::open(&config.browser_url());
                            poll_for_success(&config, &fast_agent);
                        }
                    }
                }
            }
            "3" => {
                run_setup_wizard()?;
                if let Ok(c) = load_config() {
                    config = c;
                }
            }
            "4" => {
                uninstall_process()?;
                return Ok(());
            }
            "5" => return Ok(()),
            _ => {}
        }
    }
}

/// Polls the proxy server's status endpoint using `get_fast_agent` until connected, error, or timeout.
fn poll_for_success(config: &ProxyConfig, agent: &ureq::Agent) {
    println!("\nWaiting for connection (Press Ctrl+C to cancel)...");
    let start = Instant::now();

    while start.elapsed().as_secs() < 60 {
        if let Ok(s) = fetch_status(config, agent) {
            if s.state == "connected" {
                println!("\n[SUCCESS] VPN is Connected.");
                println!("You may close this window or return to menu.");
                thread::sleep(Duration::from_secs(2));
                return;
            }
            if s.state == "error" {
                println!(
                    "\n[ERROR] Connection Failed: {}",
                    s.error.as_deref().unwrap_or("Unknown error occurred")
                );
                wait_for_enter();
                return;
            }
        }
        thread::sleep(Duration::from_millis(1000));
        print!(".");
        io::stdout().flush().unwrap();
    }
    println!("\nTimeout waiting for connection status.");
    wait_for_enter();
}

/// Fetches the proxy server status by requesting `<base_url>/status.json` and parsing the response.
///
/// # Examples
///
/// ```no_run
/// # use anyhow::Result;
/// # fn try_main(config: &crate::ProxyConfig, agent: &ureq::Agent) -> Result<()> {
/// let status = crate::fetch_status(config, agent)?;
/// # Ok(()) }
/// ```
///
/// # Returns
///
/// The parsed `ServerStatus` on success.
fn fetch_status(config: &ProxyConfig, agent: &ureq::Agent) -> Result<ServerStatus> {
    let req = agent.get(&format!("{}/status.json", config.base_url));
    let resp: ServerStatus = with_auth(req, config, "/status.json")
        .call()?
        .body_mut()
        .read_json()?;
    Ok(resp)
}

fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
}

fn print_header() {
    println!("========================================");
    println!("   {} Manager", APP_NAME);
    println!("========================================");
}

// =============================================================================
// SETUP LOGIC
// =============================================================================

/// Runs an interactive setup wizard to configure and pair with a GP Proxy Server.
///
/// The wizard attempts automatic network discovery, prompts the user to confirm or enter a server URL,
/// and offers either a manual API token or Trust-On-First-Use (TOFU) pairing using an Ed25519 identity.
/// On successful configuration it persists the ProxyConfig, tries to register a system URL handler,
/// opens the web dashboard in the default browser, and polls the server for a successful connection.
///
/// # Errors
///
/// Returns an `Err` if an I/O error, configuration persistence failure, or network error occurs during
/// discovery, pairing, or saving the configuration.
///
/// # Examples
///
/// ```rust,no_run
/// // Run the interactive setup wizard (will prompt on stdin/stdout).
/// let _ = run_setup_wizard();
/// ```
fn run_setup_wizard() -> Result<()> {
    clear_screen();
    print_header();
    println!("Scanning network for GP Proxy Server...");

    let mut found_url = String::new();

    match try_discover() {
        Ok(resp) => {
            println!("[SUCCESS] FOUND SERVER: {}:{}", resp.ip, resp.port);
            found_url = format!("http://{}:{}", resp.ip, resp.port);
        }
        Err(_) => {
            println!("[ERROR] No server found automatically.");
        }
    }

    println!(
        "\nPress [Enter] to use: {}",
        if found_url.is_empty() {
            "Manual Entry"
        } else {
            &found_url
        }
    );
    if !found_url.is_empty() {
        println!("Or type a new IP (e.g., 192.168.1.50)");
    } else {
        println!("Please enter Server IP (e.g., 192.168.1.50)");
    }

    print!("> ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();

    let final_url = if input.is_empty() {
        if found_url.is_empty() {
            println!("[ERROR] IP required.");
            wait_for_enter();
            return Ok(());
        }
        found_url
    } else if input.contains("://") {
        input.to_string()
    } else {
        // Attempt basic HTTPS inference if a standard TLS port is supplied
        if input.ends_with(":443") || input.ends_with(":8443") {
            format!("https://{}", input)
        } else {
            format!("http://{}:8001", input)
        }
    };

    println!("\n[OPTIONAL] Does the server require a manual API Token?");
    println!("(Leave blank to automatically use Trust-On-First-Use Pairing)");
    print!("Token > ");
    io::stdout().flush()?;
    let mut token_input = String::new();
    io::stdin().read_line(&mut token_input)?;
    let final_token = token_input.trim().to_string();

    let mut private_key_opt: Option<[u8; 32]> = None;

    if final_token.is_empty() {
        println!("\nGenerating Ed25519 identity and attempting TOFU pairing...");
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let pubkey_b64 = general_purpose::STANDARD.encode(verifying_key.as_bytes());

        let pair_req = PairRequest {
            public_key: pubkey_b64,
        };

        let agent = get_agent();
        let resp = agent
            .post(&format!("{}/api/pair", final_url))
            .send_json(&pair_req);

        match resp {
            Ok(r) if r.status() == 200 => {
                println!("[SUCCESS] Cryptographic Trust-On-First-Use (TOFU) Pairing complete.");
                private_key_opt = Some(signing_key.to_bytes());
            }
            Ok(r) => {
                println!("[ERROR] Pairing rejected by server (HTTP {}). Container might be manually locked via API_TOKEN or already paired.", r.status());
                wait_for_enter();
                return Ok(());
            }
            Err(e) => {
                println!("[ERROR] Failed to connect for pairing: {}", e);
                wait_for_enter();
                return Ok(());
            }
        }
    }

    let config = ProxyConfig {
        base_url: final_url,
        token: final_token,
        private_key: private_key_opt,
    };

    println!("Saving configuration...");
    save_config(&config)?;

    println!("Registering System Link Handler...");
    if let Err(e) = install_handler() {
        println!("[WARNING] Failed to register handler: {}", e);
        println!("(You may need to run as Administrator/Root)");
        wait_for_enter();
    } else {
        println!("[SUCCESS] System Handler Registered.");
    }

    println!("\nSetup Complete!");
    println!("Launching Web Dashboard...");
    let _ = webbrowser::open(&config.browser_url());

    let fast_agent = get_fast_agent();
    poll_for_success(&config, &fast_agent);

    Ok(())
}

/// Send the given callback URL to the configured proxy server's /submit endpoint.
///
/// Loads the local ProxyConfig, posts a form with `callback_url` to `<base_url>/submit` using
/// the configured authentication (Bearer token or TOFU signing), and returns an error if the
/// server responds with a non-200 status or if loading/sending fails.
///
/// # Arguments
///
/// * `url` - The callback URL received from the OS protocol handler to forward to the server.
///
/// # Returns
///
/// `Ok(())` on success, otherwise an `anyhow::Error` describing the failure.
///
/// # Examples
///
/// ```rust,no_run
/// // Forward a protocol callback URL to the configured server.
/// handle_link("globalprotect://open?token=abc123").unwrap();
/// ```
fn handle_link(url: &str) -> Result<()> {
    let config = load_config()?;
    let target_endpoint = format!("{}/submit", config.base_url.trim_end_matches('/'));

    let agent = get_agent();
    let req = agent.post(&target_endpoint);

    let resp = with_auth(req, &config, "/submit").send_form([("callback_url", url)])?;

    if resp.status() != 200 {
        anyhow::bail!("Server Error: {}", resp.status());
    }
    Ok(())
}

fn wait_for_enter() {
    print!("Press Enter to continue...");
    io::stdout().flush().unwrap();
    let _ = io::stdin().read_line(&mut String::new());
}

fn try_discover() -> Result<DiscoveryResponse> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(1500)))?;

    socket.send_to(
        DISCOVERY_MSG.as_bytes(),
        format!("255.255.255.255:{}", UDP_PORT),
    )?;

    let mut buf = [0; 1024];
    let (amt, _src) = socket.recv_from(&mut buf)?;

    let response: DiscoveryResponse =
        serde_json::from_slice(&buf[..amt]).context("Invalid discovery response")?;

    Ok(response)
}

fn get_config_path() -> Result<PathBuf> {
    let proj_dirs = ProjectDirs::from("com", "gpproxy", "client").context("No config dir")?;
    let config_dir = proj_dirs.config_dir();
    if !config_dir.exists() {
        fs::create_dir_all(config_dir)?;
    }
    Ok(config_dir.join(CONFIG_FILE_NAME))
}

/// Loads the saved proxy configuration from the application's config file.
///
/// Expects the config file to contain:
/// 1) A base URL on the first line (required).
/// 2) An API token on the second line (may be empty).
/// 3) An optional base64-encoded 32-byte Ed25519 private key on the third line (may be empty).
///
/// # Returns
///
/// A `ProxyConfig` populated from the file: `base_url`, `token`, and `private_key` (as `Some([u8;32])` if present and valid, otherwise `None`).
///
/// # Errors
///
/// Returns an error if the config file is missing, unreadable, or the first line (base URL) is empty.
///
/// # Examples
///
/// ```no_run
/// // Write a config manually to the configured path (example only; avoid overwriting a real config).
/// use std::fs;
/// use std::io::Write;
/// let path = crate::get_config_path().unwrap();
/// let mut file = fs::File::create(&path).unwrap();
/// writeln!(file, "http://localhost:8001").unwrap();
/// writeln!(file, "my-token").unwrap();
/// // optional third line can be a base64 32-byte private key or empty
///
/// let cfg = crate::load_config().unwrap();
/// assert_eq!(cfg.base_url, "http://localhost:8001");
/// assert_eq!(cfg.token, "my-token");
/// ```
fn load_config() -> Result<ProxyConfig> {
    let path = get_config_path()?;
    if !path.exists() {
        anyhow::bail!("No config");
    }
    let content = fs::read_to_string(path)?;
    let mut lines = content.lines();

    let base_url = lines.next().unwrap_or("").trim().to_string();
    if base_url.is_empty() {
        anyhow::bail!("Invalid config: Missing URL");
    }

    let token = lines.next().unwrap_or("").trim().to_string();

    let mut private_key = None;
    if let Some(pk_str) = lines.next() {
        let pk_trim = pk_str.trim();
        if !pk_trim.is_empty() {
            if let Ok(decoded) = general_purpose::STANDARD.decode(pk_trim) {
                if decoded.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&decoded);
                    private_key = Some(arr);
                }
            }
        }
    }

    Ok(ProxyConfig {
        base_url,
        token,
        private_key,
    })
}

/// Persist the given ProxyConfig to the user's configuration file.
///
/// Writes the config as plain text where the first line is the base URL,
/// the second line is the token (may be empty), and the optional third line
/// is the base64-encoded 32-byte private key.
///
/// # Errors
///
/// Returns an error if the configuration path cannot be determined or if
/// writing the file fails.
///
/// # Examples
///
/// ```no_run
/// use std::error::Error;
///
/// // Construct a config and persist it
/// let cfg = ProxyConfig {
///     base_url: "http://127.0.0.1:8001".into(),
///     token: "mytoken".into(),
///     private_key: None,
/// };
/// save_config(&cfg).expect("failed to save config");
/// ```
fn save_config(config: &ProxyConfig) -> Result<()> {
    let mut content = format!("{}\n{}\n", config.base_url, config.token);
    if let Some(pk) = &config.private_key {
        content.push_str(&general_purpose::STANDARD.encode(pk));
        content.push('\n');
    }
    fs::write(get_config_path()?, content)?;
    Ok(())
}

fn remove_config() -> Result<()> {
    let path = get_config_path()?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn uninstall_process() -> Result<()> {
    println!("Removing...");
    if let Err(e) = uninstall_handler() {
        eprintln!("[WARNING] Handler removal failed: {}", e);
    }
    if let Err(e) = remove_config() {
        eprintln!("[WARNING] Config removal failed: {}", e);
    }
    println!("Done.");
    wait_for_enter();
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_handler() -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;
    let exe_path = env::current_exe()?;
    let exe_path_str = exe_path
        .to_str()
        .context("Executable path contains invalid UTF-8")?;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = std::path::Path::new("Software")
        .join("Classes")
        .join(PROTOCOL_SCHEME);
    let (key, _) = hkcu.create_subkey(&path)?;
    key.set_value("", &format!("URL:{} Protocol", APP_NAME))?;
    key.set_value("URL Protocol", &"")?;
    let cmd_key = key.create_subkey("shell\\open\\command")?.0;
    let cmd_val = format!("\"{}\" \"%1\"", exe_path_str);
    cmd_key.set_value("", &cmd_val)?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn uninstall_handler() -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = std::path::Path::new("Software")
        .join("Classes")
        .join(PROTOCOL_SCHEME);
    hkcu.delete_subkey_all(&path)
        .context("Failed to delete Registry key")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_handler() -> Result<()> {
    let exe_path = env::current_exe()?;
    let dirs = directories::BaseDirs::new().context("No home dir")?;

    let icon_dir = dirs.data_local_dir().join("icons/hicolor/512x512/apps");
    if !icon_dir.exists() {
        fs::create_dir_all(&icon_dir)?;
    }
    fs::write(icon_dir.join("gp-client-proxy.png"), ICON_PNG)?;

    let desktop_file = format!(
        "[Desktop Entry]\nType=Application\nName={}\nExec=\"{}\" %u\nIcon=gp-client-proxy\nStartupNotify=false\nMimeType=x-scheme-handler/{};\n",
        APP_NAME, exe_path.to_string_lossy(), PROTOCOL_SCHEME
    );
    let apps_dir = dirs.data_local_dir().join("applications");
    if !apps_dir.exists() {
        fs::create_dir_all(&apps_dir)?;
    }
    fs::write(
        apps_dir.join(format!("{}.desktop", BINARY_NAME)),
        desktop_file,
    )?;

    let status = Command::new("xdg-mime")
        .args([
            "default",
            &format!("{}.desktop", BINARY_NAME),
            &format!("x-scheme-handler/{}", PROTOCOL_SCHEME),
        ])
        .status()?;

    if !status.success() {
        anyhow::bail!("xdg-mime failed with exit code: {:?}", status.code());
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_handler() -> Result<()> {
    let dirs = directories::BaseDirs::new().context("No home dir")?;
    let apps_dir = dirs.data_local_dir().join("applications");
    let file = apps_dir.join(format!("{}.desktop", BINARY_NAME));
    if file.exists() {
        fs::remove_file(file)?;
    }
    let _ = Command::new("update-desktop-database")
        .arg(&apps_dir)
        .status();
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_handler() -> Result<()> {
    let exe_path = env::current_exe()?;
    let dirs = directories::UserDirs::new().context("No home dir")?;
    let app_path = dirs
        .home_dir()
        .join(format!("Applications/{}.app", APP_NAME));
    let contents = app_path.join("Contents");
    let macos = contents.join("MacOS");
    let res = contents.join("Resources");
    fs::create_dir_all(&macos)?;
    fs::create_dir_all(&res)?;
    fs::copy(&exe_path, macos.join(BINARY_NAME))?;
    fs::write(res.join("AppIcon.icns"), ICON_ICNS)?;

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>{}</string>
<key>CFBundleIdentifier</key><string>com.gpproxy.client</string>
<key>CFBundleName</key><string>{}</string>
<key>CFBundleDisplayName</key><string>{}</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>CFBundleURLTypes</key><array><dict><key>CFBundleURLName</key><string>VPN Login Link</string><key>CFBundleURLSchemes</key><array><string>globalprotect</string></array></dict></array>
</dict></plist>"#,
        BINARY_NAME, APP_NAME, APP_NAME
    );

    fs::write(contents.join("Info.plist"), plist)?;
    let status = Command::new(
        "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister",
    )
    .arg("-f")
    .arg(&app_path)
    .status()?;

    if !status.success() {
        anyhow::bail!("lsregister failed with exit code: {:?}", status.code());
    }
    Ok(())
}

/// Unregisters and removes the installed macOS app bundle at `~/Applications/GP Client Proxy.app`.
/// Strictly requires unregistration success before file deletion to prevent OS scheme handler corruption.
#[cfg(target_os = "macos")]
fn uninstall_handler() -> Result<()> {
    let dirs = directories::UserDirs::new().context("No home dir")?;
    let app_path = dirs
        .home_dir()
        .join(format!("Applications/{}.app", APP_NAME));

    if app_path.exists() {
        let status = Command::new(
            "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister",
        )
        .arg("-u")
        .arg(&app_path)
        .status()?;

        if !status.success() {
            anyhow::bail!("lsregister unregistration failed with exit code: {:?}. Aborting deletion to prevent orphaned handlers.", status.code());
        }

        fs::remove_dir_all(&app_path)?;
        println!("App removed successfully.");
    } else {
        println!("App not found, nothing to remove.");
    }
    Ok(())
}
