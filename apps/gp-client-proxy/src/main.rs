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
    #[allow(dead_code)]
    url: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize, Debug)]
struct DiscoveryResponse {
    ip: String,
    port: u16,
}

/// Program entry point that dispatches between the protocol handler, uninstaller, and interactive dashboard.
///
/// On startup it initializes logging and then selects one of three modes based on command-line arguments:
/// - If the first argument begins with the `globalprotect://` scheme, the link handler is invoked and the process exits.
/// - If the first argument equals `--uninstall`, the uninstall flow is executed and the program exits.
/// - Otherwise, the interactive dashboard/launcher is started.
///
/// # Returns
///
/// `Ok(())` on successful completion of the selected mode; an `Err` if an operation fails.
///
/// # Examples
///
/// ```
/// // Calling the application entry point; in real use this is invoked by the runtime.
/// // This example demonstrates invocation only and does not assert side effects.
/// let _ = crate::main();
/// ```
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

// --- HELPER: Configured HTTP Agent ---
/// Create a preconfigured HTTP agent with a 10-second global timeout.
///
/// This returns a `ureq::Agent` configured with a global request timeout of 10 seconds,
/// suitable for performing HTTP requests with a consistent timeout policy.
///
/// # Examples
///
/// ```
/// let agent = get_agent();
/// let resp = agent.get("[http://example.invalid/](http://example.invalid/)").call();
/// // `resp` will be an error if the request fails or times out.
/// assert!(resp.is_err());
/// ```
fn get_agent() -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .build();
    ureq::Agent::new_with_config(config)
}

// =============================================================================
// DASHBOARD LOGIC
// =============================================================================

/// Displays the interactive dashboard and launcher for the GP Client Proxy.
///
/// On first run (no saved configuration) this will start the setup wizard instead of entering the dashboard.
/// In the dashboard the user can view server and connection status and choose to open the web dashboard,
/// connect or disconnect the VPN, re-run setup/discovery, uninstall, or exit.
///
/// # Returns
///
/// `Ok(())` when the dashboard loop exits normally (for example, when the user selects Exit or after uninstall),
/// `Err` if an I/O or operational error occurs while running the dashboard.
///
/// # Examples
///
/// ```no_run
/// // Starts the interactive dashboard; this will block until the user exits or the process performs an uninstall.
/// let _ = run_dashboard();
/// ```
fn run_dashboard() -> Result<()> {
    // 1. First Run Check
    if load_config().is_err() {
        println!("No configuration found. Starting Setup...");
        return run_setup_wizard();
    }

    // 2. Main Loop
    loop {
        clear_screen();
        print_header();

        // Fetch Status
        let config_url = load_config().unwrap_or_default();
        let status = fetch_status(&config_url);

        // Display Status
        match &status {
            Ok(s) => {
                println!("SERVER:    Online ({})", config_url);
                println!("STATUS:    {}", s.state.to_uppercase());
                println!("MODE:      {}", s.vpn_mode.to_uppercase());

                // --- Connection Info Block ---
                if s.state == "connected" {
                    println!("\n[!] CONNECTION DETAILS");

                    // Extract IP from URL (http://1.2.3.4:8001 -> 1.2.3.4)
                    let host_ip = config_url
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
                println!("SERVER:    Unreachable ({})", config_url);
                println!("STATUS:    OFFLINE");
            }
        }
        println!("----------------------------------------");

        // Menu Options
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
                let _ = webbrowser::open(&config_url);
            }
            "2" => {
                if let Ok(s) = &status {
                    if s.state == "connected" {
                        // DISCONNECT ACTION
                        println!("Disconnecting...");
                        // Use get_agent() for timeout protection
                        if let Err(e) = get_agent()
                            .post(&format!("{}/disconnect", config_url))
                            .send_empty()
                        {
                            println!("Error disconnecting: {}", e);
                            thread::sleep(Duration::from_secs(2));
                        } else {
                            thread::sleep(Duration::from_secs(1));
                        }
                    } else {
                        // CONNECT ACTION
                        println!("Initiating Connection...");
                        if let Err(e) = get_agent()
                            .post(&format!("{}/connect", config_url))
                            .send_empty()
                        {
                            println!("Error initiating connection: {}", e);
                            thread::sleep(Duration::from_secs(2));
                        } else {
                            println!("Launching Browser for Auth...");
                            let _ = webbrowser::open(&config_url);
                            poll_for_success(&config_url);
                        }
                    }
                }
            }
            "3" => {
                run_setup_wizard()?;
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

/// Polls the proxy server's status endpoint until the VPN becomes connected, reports an error, or times out.
///
/// Repeatedly fetches the server status at `base_url` and prints progress to stdout. Stops when the server reports `connected`, when the server reports `error` (printing the error), or after 60 seconds (printing a timeout message). Prompts the user to press Enter when an error or timeout occurs.
///
/// # Parameters
///
/// - `base_url`: Base HTTP URL of the proxy server (for example `"http://127.0.0.1:8001"`).
///
/// # Examples
///
/// ```
/// // This will poll the status endpoint at the provided base URL until success, error, or timeout.
/// poll_for_success("[http://127.0.0.1:8001](http://127.0.0.1:8001)");
/// ```
fn poll_for_success(base_url: &str) {
    println!("\nWaiting for connection (Press Ctrl+C to cancel)...");
    let start = Instant::now();

    // Poll for 60 seconds max
    while start.elapsed().as_secs() < 60 {
        if let Ok(s) = fetch_status(base_url) {
            if s.state == "connected" {
                println!("\n✅ SUCCESS! VPN is Connected.");
                println!("You may close this window or return to menu.");
                thread::sleep(Duration::from_secs(2));
                return;
            }
            if s.state == "error" {
                println!("\n❌ Connection Failed: {:?}", s.error.unwrap_or_default());
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

/// Fetches the proxy server's status from its `/status.json` endpoint.
///
/// `base_url` is the base URL of the GP Proxy server (for example `http://192.168.1.10:8001`).
///
/// # Returns
///
/// The parsed `ServerStatus` returned by the server.
///
/// # Examples
///
/// ```no_run
/// let status = fetch_status("[http://127.0.0.1:8001](http://127.0.0.1:8001)").unwrap();
/// println!("state = {:?}", status.state);
/// ```
fn fetch_status(base_url: &str) -> Result<ServerStatus> {
    // Use configured agent with timeout
    let resp: ServerStatus = get_agent()
        .get(&format!("{}/status.json", base_url))
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

/// Runs the interactive setup wizard for the GP Client Proxy.
///
/// The wizard attempts to discover a local GP Proxy server on the network, prompts the user to
/// accept a discovered URL or enter one manually, saves the chosen proxy URL to the local
/// configuration, tries to register the OS URL handler for the `globalprotect://` scheme, and
/// launches the web dashboard while polling the server for a connection status.
///
/// # Errors
///
/// Returns an error if I/O, network discovery, configuration save, or other underlying operations
/// fail.
///
/// # Examples
///
/// ```no_run
/// use anyhow::Result;
///
/// fn main() -> Result<()> {
///     // Launch the interactive setup wizard (may prompt the user).
///     run_setup_wizard()?;
///     Ok(())
/// }
/// ```
fn run_setup_wizard() -> Result<()> {
    clear_screen();
    print_header();
    println!("Scanning network for GP Proxy Server...");

    let mut found_url = String::new();

    // 1. Auto-Discovery
    match try_discover() {
        Ok(resp) => {
            println!("✅ FOUND SERVER: {}:{}", resp.ip, resp.port);
            found_url = format!("http://{}:{}", resp.ip, resp.port);
        }
        Err(_) => {
            println!("❌ No server found automatically.");
        }
    }

    // 2. Confirm / Manual Entry
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
            println!("Error: IP required.");
            wait_for_enter();
            return Ok(());
        }
        found_url
    } else if input.contains("://") {
        input.to_string()
    } else {
        format!("http://{}:8001", input)
    };

    // 3. Save
    println!("Saving configuration...");
    save_config(&final_url)?;

    // 4. Register OS Handler
    println!("Registering System Link Handler...");
    if let Err(e) = install_handler() {
        println!("⚠️ Warning: Failed to register handler: {}", e);
        println!("(You may need to run as Administrator/Root)");
        wait_for_enter();
    } else {
        println!("✅ System Handler Registered.");
    }

    // 5. Test / First Launch
    println!("\nSetup Complete!");
    println!("Launching Web Dashboard...");
    let _ = webbrowser::open(&final_url);
    poll_for_success(&final_url);

    Ok(())
}

// =============================================================================
// LINK HANDLER LOGIC (Background Mode)
// =============================================================================

/// Submits a callback URL to the configured GP Client Proxy server's /submit endpoint.
///
/// Reads the proxy base URL from the saved configuration and posts a form with
/// `callback_url` set to the provided `url`. Returns success only if the server
/// responds with HTTP 200.
///
/// # Errors
///
/// Returns an error if the configuration cannot be loaded, the HTTP request
/// fails, or the server responds with a non-200 status.
///
/// # Examples
///
/// ```no_run
/// # use anyhow::Result;
/// # fn example() -> Result<()> {
/// handle_link("globalprotect://example/callback")?;
/// # Ok(())
/// # }
/// ```
fn handle_link(url: &str) -> Result<()> {
    let proxy_base = load_config()?;
    let target_endpoint = format!("{}/submit", proxy_base.trim_end_matches('/'));

    // Use get_agent() for timeout protection
    let resp = get_agent()
        .post(&target_endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send_form([("callback_url", url)])?;

    if resp.status() != 200 {
        anyhow::bail!("Server Error: {}", resp.status());
    }
    Ok(())
}

/// Prints a prompt and waits for the user to press Enter.
///
/// # Examples
///
/// ```no_run
/// // Displays a prompt and blocks until the user presses Enter.
/// wait_for_enter();
/// ```
fn wait_for_enter() {
    print!("Press Enter to continue...");
    io::stdout().flush().unwrap();
    let _ = io::stdin().read_line(&mut String::new());
}

// --- DISCOVERY ---
/// Discovers a GP Proxy server on the local network using a UDP broadcast.
///
/// Sends a discovery broadcast and parses the first valid JSON reply into a `DiscoveryResponse`.
///
/// # Examples
///
/// ```no_run
/// let resp = try_discover().expect("discovery failed");
/// println!("Found proxy at {}:{}", resp.ip, resp.port);
/// ```
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

// --- CONFIG ---
fn get_config_path() -> Result<PathBuf> {
    let proj_dirs = ProjectDirs::from("com", "gpproxy", "client").context("No config dir")?;
    let config_dir = proj_dirs.config_dir();
    if !config_dir.exists() {
        fs::create_dir_all(config_dir)?;
    }
    Ok(config_dir.join(CONFIG_FILE_NAME))
}
fn load_config() -> Result<String> {
    let path = get_config_path()?;
    if !path.exists() {
        anyhow::bail!("No config");
    }
    Ok(fs::read_to_string(path)?.trim().to_string())
}
fn save_config(url: &str) -> Result<()> {
    fs::write(get_config_path()?, url)?;
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
    let _ = uninstall_handler();
    let _ = remove_config();
    println!("Done.");
    wait_for_enter();
    Ok(())
}

// --- OS SPECIFIC INSTALLERS ---

/// Registers the application as the `globalprotect:` URL protocol handler in the current user's registry.
///
/// On success the registry key `HKCU\Software\Classes\globalprotect` is created/updated so that
/// opening `globalprotect://...` invokes the current executable with the URL as the first argument.
///
/// # Errors
///
/// Returns an error if the current executable path cannot be determined or if any registry operation fails.
///
/// # Examples
///
/// ```
/// # #[cfg(target_os = "windows")] {
/// let _ = gp_client_proxy::install_handler();
/// # }
/// ```
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

    // Icon
    let icon_dir = dirs.data_local_dir().join("icons/hicolor/512x512/apps");
    if !icon_dir.exists() {
        fs::create_dir_all(&icon_dir)?;
    }
    fs::write(icon_dir.join("gp-client-proxy.png"), ICON_PNG)?;

    // Desktop Entry
    let desktop_file = format!(
        "[Desktop Entry]\nType=Application\nName={}\nExec={} %u\nIcon=gp-client-proxy\nStartupNotify=false\nMimeType=x-scheme-handler/{};\n",
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

/// Installs a macOS app bundle for the application and registers it as a URL handler for the `globalprotect` scheme.
///
/// Creates an application bundle at `~/Applications/GP Client Proxy.app`, copies the current executable and bundled icon into the bundle, writes an `Info.plist` declaring the `globalprotect` URL type, and registers the bundle with LaunchServices so the system recognizes the URL scheme handler.
///
/// # Errors
///
/// Returns an error if the current executable or home directory cannot be determined, file operations fail, or LaunchServices registration (`lsregister`) exits with a non-zero status.
///
/// # Examples
///
/// ```no_run
/// # #[cfg(target_os = "macos")] {
/// let _ = gp_client_proxy::install_handler();
/// # }
/// ```
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

    // Fix: Propagate error instead of silent fail
    if !status.success() {
        anyhow::bail!("lsregister failed with exit code: {:?}", status.code());
    }
    Ok(())
}

/// Unregisters and removes the installed macOS app bundle at `~/Applications/GP Client Proxy.app`.
///
/// Attempts to unregister the app with LaunchServices before deleting the app bundle. If the
/// app bundle is not present, the function prints a message and returns `Ok(())`. Any filesystem
/// or process errors encountered during removal are returned as an error.
///
/// # Examples
///
/// ```rust,no_run
/// // On macOS, remove the installed app bundle (may require appropriate permissions).
/// uninstall_handler().expect("failed to uninstall app");
/// ```
#[cfg(target_os = "macos")]
fn uninstall_handler() -> Result<()> {
    let dirs = directories::UserDirs::new().context("No home dir")?;
    let app_path = dirs
        .home_dir()
        .join(format!("Applications/{}.app", APP_NAME));

    if app_path.exists() {
        // Fix: Explicitly unregister BEFORE deletion
        let status = Command::new(
            "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister",
        )
        .arg("-u")
        .arg(&app_path)
        .status();

        if let Err(e) = status {
            eprintln!("Warning: Failed to unregister app: {}", e);
        }

        fs::remove_dir_all(&app_path)?;
        println!("App removed successfully.");
    } else {
        println!("App not found, nothing to remove.");
    }
    Ok(())
}
