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

// FIX: Only import Command on non-Windows platforms
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

// FIX: Only define BINARY_NAME on non-Windows platforms to avoid "unused const" warnings
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

// =============================================================================
// DASHBOARD LOGIC
// =============================================================================

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
                        let _ = ureq::post(&format!("{}/disconnect", config_url)).send_empty();
                        thread::sleep(Duration::from_secs(1));
                    } else {
                        // CONNECT ACTION
                        println!("Initiating Connection...");
                        let _ = ureq::post(&format!("{}/connect", config_url)).send_empty();
                        println!("Launching Browser for Auth...");
                        let _ = webbrowser::open(&config_url);
                        poll_for_success(&config_url);
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

fn fetch_status(base_url: &str) -> Result<ServerStatus> {
    let resp: ServerStatus = ureq::get(&format!("{}/status.json", base_url))
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

    // 1. Auto-Discovery
    match try_discover() {
        Ok(ip) => {
            println!("✅ FOUND SERVER: {}", ip);
            found_url = format!("http://{}:8001", ip);
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

    // FIX: Collapsed else-if block
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

fn handle_link(url: &str) -> Result<()> {
    let proxy_base = load_config()?;
    let target_endpoint = format!("{}/submit", proxy_base.trim_end_matches('/'));

    let resp = ureq::post(&target_endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send_form([("callback_url", url)])?;

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

// --- DISCOVERY ---
fn try_discover() -> Result<String> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(1500)))?;

    socket.send_to(
        DISCOVERY_MSG.as_bytes(),
        format!("255.255.255.255:{}", UDP_PORT),
    )?;

    let mut buf = [0; 1024];
    let (amt, _src) = socket.recv_from(&mut buf)?;
    let response = String::from_utf8_lossy(&buf[..amt]);

    if let Some(start) = response.find("\"ip\": \"") {
        let rest = &response[start + 7..];
        if let Some(end) = rest.find("\"") {
            return Ok(rest[..end].to_string());
        }
    }
    anyhow::bail!("Invalid response");
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

#[cfg(target_os = "windows")]
fn install_handler() -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;
    let exe_path = env::current_exe()?;
    let exe_path_str = exe_path.to_str().unwrap();
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

    Command::new("xdg-mime")
        .args([
            "default",
            &format!("{}.desktop", BINARY_NAME),
            &format!("x-scheme-handler/{}", PROTOCOL_SCHEME),
        ])
        .status()?;
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
    Command::new(
        "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister",
    )
    .arg("-f")
    .arg(&app_path)
    .status()
    .ok();
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_handler() -> Result<()> {
    let dirs = directories::UserDirs::new().context("No home dir")?;
    let app_path = dirs
        .home_dir()
        .join(format!("Applications/{}.app", APP_NAME));
    if app_path.exists() {
        fs::remove_dir_all(&app_path)?;
    }
    Command::new(
        "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister",
    )
    .arg("-f")
    .arg(&app_path)
    .status()
    .ok();
    Ok(())
}
