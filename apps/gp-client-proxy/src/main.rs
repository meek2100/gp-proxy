// File: apps/gp-client-proxy/src/main.rs
use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::Deserialize;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

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
}

#[derive(Deserialize, Debug)]
struct DiscoveryResponse {
    ip: String,
    port: u16,
    #[serde(default)]
    token: String, // Zero-touch session token for API authorization
}

#[derive(Clone, Debug)]
struct ProxyConfig {
    base_url: String,
    token: String,
}

impl ProxyConfig {
    /// Generates the authenticated browser URL to pass the zero-touch token to the frontend
    fn browser_url(&self) -> String {
        if self.token.is_empty() {
            self.base_url.clone()
        } else {
            format!("{}/?token={}", self.base_url, encode_token(&self.token))
        }
    }
}

/// Helper function to safely percent-encode the token without requiring additional dependencies
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

/// Helper function to uniformly inject the Authorization header if a token is present
fn with_auth<T>(req: ureq::RequestBuilder<T>, token: &str) -> ureq::RequestBuilder<T> {
    if token.is_empty() {
        req
    } else {
        req.header("Authorization", &format!("Bearer {}", token))
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
                        println!("SOCKS5 Proxy:  {}:1080 (No Auth)", host_ip);
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
                        if let Err(e) = with_auth(req, &config.token).send_empty() {
                            println!("Error disconnecting: {}", e);
                            thread::sleep(Duration::from_secs(2));
                        } else {
                            thread::sleep(Duration::from_secs(1));
                        }
                    } else {
                        println!("Initiating Connection...");
                        let req = agent.post(&format!("{}/connect", config.base_url));
                        if let Err(e) = with_auth(req, &config.token).send_empty() {
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

/// Fetches the proxy server's status using a fast-timeout HTTP agent.
fn fetch_status(config: &ProxyConfig, agent: &ureq::Agent) -> Result<ServerStatus> {
    let req = agent.get(&format!("{}/status.json", config.base_url));
    let resp: ServerStatus = with_auth(req, &config.token)
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

fn run_setup_wizard() -> Result<()> {
    clear_screen();
    print_header();
    println!("Scanning network for GP Proxy Server...");

    let mut found_url = String::new();
    let mut found_token = String::new();

    match try_discover() {
        Ok(resp) => {
            println!("[SUCCESS] FOUND SERVER: {}:{}", resp.ip, resp.port);
            found_url = format!("http://{}:{}", resp.ip, resp.port);
            found_token = resp.token;
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

    // If the user manually inputs an IP that differs, we discard the discovered token
    let final_token = if input.is_empty() {
        found_token
    } else {
        String::new()
    };

    let config = ProxyConfig {
        base_url: final_url,
        token: final_token,
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

fn handle_link(url: &str) -> Result<()> {
    let config = load_config()?;
    let target_endpoint = format!("{}/submit", config.base_url.trim_end_matches('/'));

    let agent = get_agent();
    let req = agent
        .post(&target_endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded");

    let resp = with_auth(req, &config.token).send_form([("callback_url", url)])?;

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

    Ok(ProxyConfig { base_url, token })
}

fn save_config(config: &ProxyConfig) -> Result<()> {
    let content = if config.token.is_empty() {
        config.base_url.clone()
    } else {
        format!("{}\n{}", config.base_url, config.token)
    };
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
