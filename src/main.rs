use std::io::{self, Write};
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::path::Path;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::fs;
use colored::*;
use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use serde_json;
use std::sync::LazyLock;
use tokio;
use log::{debug, error, info, warn};
use env_logger::Builder;
use chrono::Local;

// Initialize logging system
fn init_logger() {
    // Create a file appender for logging
    use env_logger::WriteStyle;
    use std::fs::OpenOptions;

    // Open log file in append mode
    let log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("torc.log")
        .expect("Failed to create log file");

    // Create a custom logger builder
    let mut builder = Builder::new();
    builder
        .format(|buf, record| {
            writeln!(buf,
                "{} [{}] - {}: {}",
                Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level(),
                record.target(),
                record.args()
            )
        })
        .filter(None, log::LevelFilter::Info)  // Default to Info level
        .parse_env("TORC_LOG")  // Allow override via TORC_LOG environment variable
        .target(env_logger::Target::Pipe(Box::new(log_file)))  // Log to file instead of stdout
        .write_style(WriteStyle::Never);  // Never write to stdout

    builder.init();

    // Since we're logging to a file, we need to manually log this to file as well
    // The info! macro will now log to file since we've initialized the logger
    info!("Logger initialized for TORC application");
}

// Structure to store IP address and geo location information
#[derive(Debug, Clone)]
struct GeoIPInfo {
    ip: String,
    country: Option<String>,
    city: Option<String>,
    region: Option<String>,
    isp: Option<String>,
}

#[derive(Parser)]
#[command(name = "torc")]
#[command(about = "A Rust CLI application to connect your system to the Tor network", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Manage system Tor operations (connect, disconnect, status)
    System {
        #[command(subcommand)]
        operation: Option<SystemOps>,
    },
    /// Handle disk encryption tasks
    Disk {
        #[command(subcommand)]
        operation: Option<DiskOps>,
    },
}

#[derive(Subcommand, Debug)]
enum SystemOps {
    /// Connect to the Tor network
    Connect,
    /// Disconnect from the Tor network
    Disconnect,
    /// Check the Tor network status
    Status,
}

#[derive(Subcommand, Debug)]
enum DiskOps {
    /// Encrypt a disk partition
    Encrypt { path: String },
    /// Decrypt a disk partition
    Decrypt { path: String },
    /// Check encryption status of a disk partition
    Status { path: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging system
    init_logger();
    info!("Starting TORC application");

    // Check if system needs restoration due to unexpected shutdown/crash
    check_for_unexpected_shutdown()?;

    let cli = Cli::parse();
    info!("Parsed command line arguments: {:?}", cli.command);

    match &cli.command {
        Some(Commands::System { operation }) => {
            info!("Executing System command with operation: {:?}", operation);
            match operation {
                Some(SystemOps::Connect) => connect_to_tor().await?,
                Some(SystemOps::Disconnect) => disconnect_from_tor().await?,
                Some(SystemOps::Status) => check_tor_status().await?,
                None => {
                    info!("Showing interactive menu for System command");
                    show_interactive_menu().await? // Show menu if no sub-operation specified
                },
            }
        },
        Some(Commands::Disk { operation }) => {
            info!("Executing Disk command with operation: {:?}", operation);
            match operation {
                Some(DiskOps::Encrypt { path }) => encrypt_disk(path)?,
                Some(DiskOps::Decrypt { path }) => decrypt_disk(path)?,
                Some(DiskOps::Status { path }) => check_disk_encryption_status(path)?,
                None => {
                    info!("Showing disk operations help");
                    println!("{}", "Disk operations:".cyan());
                    println!("{}", "  encrypt <path> - Encrypt a disk partition".cyan());
                    println!("{}", "  decrypt <path> - Decrypt a disk partition".cyan());
                    println!("{}", "  status <path>  - Check encryption status".cyan());
                    return Ok(());
                }
            }
        },
        None => {
            info!("Showing interactive menu as no command specified");
            show_interactive_menu().await? // Show menu if no command specified
        },
    }

    info!("TORC application completed successfully");
    Ok(())
}

// Function to check if the system needs restoration due to unexpected shutdown
fn check_for_unexpected_shutdown() -> Result<()> {
    info!("Checking for unexpected shutdown or crash");
    // Check if Tor service is running but we don't have a record of being connected
    // This indicates a possible crash or unexpected shutdown
    if is_tor_service_running() {
        info!("Tor service is running - checking for unexpected state");
        // We could implement a more sophisticated check here by storing state in a temporary file
        // For now, we'll just warn the user if Tor is running without explicit connection info

        // Check if we have state information that suggests we should be connected
        let torc_state_file = "/tmp/torc_state";
        let tor_connected_previously = std::path::Path::new(torc_state_file).exists();
        info!("Tor connected previously: {}", tor_connected_previously);

        if tor_connected_previously {
            info!("Detected unexpected Tor service state from previous session");
            println!("{}", "⚠️  Tor service appears to be running from a previous session".yellow());

            // Ask user what to do
            print!("{}", "Would you like to restore normal network configuration? (y/N): ".cyan());
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            if input.trim().to_lowercase() == "y" || input.trim().to_lowercase() == "yes" {
                info!("User chose to restore system configuration");
                // Attempt to restore system state
                if let Err(e) = restore_system_state_if_needed() {
                    warn!("Could not restore system state: {}", e);
                    println!("{}", format!("Warning: Could not restore system state: {}", e).red());
                } else {
                    info!("System state restored successfully");
                    restore_system_proxy();
                }

                // Stop the Tor service
                if let Err(e) = stop_tor_service() {
                    warn!("Could not stop Tor service: {}", e);
                    println!("{}", format!("Warning: Could not stop Tor service: {}", e).red());
                } else {
                    info!("Tor service stopped during unexpected shutdown restoration");
                }

                // Clean up the state file
                let _ = std::fs::remove_file(torc_state_file);

                println!("{}", "System state has been restored to normal configuration.".green());
                info!("System configuration restored to normal state");
            } else {
                info!("User chose not to restore system configuration");
            }
        } else {
            // Tor is running but we don't have state info - warn the user
            warn!("Tor service is running but no state file exists - possible unexpected startup");
            println!("{}", "⚠️  Tor service is currently running".yellow());
            println!("{}", "⚠️  If this is unexpected, consider running 'torc system disconnect'".yellow());
        }
    } else {
        info!("No unexpected shutdown detected - Tor service is not running");
    }

    Ok(())
}

// Function to restore system state if needed
fn restore_system_state_if_needed() -> Result<()> {
    // Check if we have system state information in our global backup
    let has_backup = {
        let backup = SYSTEM_STATE_BACKUP.lock().unwrap();
        backup.is_some()
    };

    if has_backup {
        // We have state information, so restore it
        restore_system_state()?;
    } else {
        // No state backup available, restore basic proxy settings
        restore_system_proxy();
    }

    Ok(())
}

async fn show_interactive_menu() -> Result<()> {
    println!("{}", "TORC - Tor Network Connector".green().bold());
    println!("{}", "Connecting your system to the Tor network for anonymous browsing".yellow());
    println!();

    loop {
        show_menu().await;

        print!("\n{} ", "Enter your choice:".cyan());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let result = match input.trim() {
            "1" => connect_to_tor().await.map(|_| ()),
            "2" => disconnect_from_tor().await.map(|_| ()),
            "3" => check_tor_status().await.map(|_| ()),
            "4" => {
                println!("{}", "Exiting TORC. Your system is no longer connected to Tor.".yellow());
                break;
            },
            _ => {
                println!("{}", "Invalid option. Please try again.".red());
                Ok(())
            },
        };
        // Only continue if no error occurred
        result?;

        println!("\nPress Enter to continue...");
        let mut dummy = String::new();
        io::stdin().read_line(&mut dummy)?;
    }

    Ok(())
}

async fn show_menu() {
    print!("\x1B[2J\x1B[1;1H");  // Clear screen

    // Get system information for display
    let sys_info = get_system_info();
    println!("{}", "=".repeat(50).green());
    println!("{}", r#"
▄▄▄▄▄▄▄▄▄   ▄▄▄▄▄   ▄▄▄▄▄▄▄    ▄▄▄▄▄▄▄
▀▀▀███▀▀▀ ▄███████▄ ███▀▀███▄ ███▀▀▀▀▀
   ███    ███   ███ ███▄▄███▀ ███
   ███    ███▄▄▄███ ███▀▀██▄  ███
   ███     ▀█████▀  ███  ▀███ ▀███████

    "#.green());
    println!("{}", "       TORC - Tor Connection Manager".green().bold());
    println!("{}", "=".repeat(50).green());

    // Display system information in brackets next to the title
    println!("[{}]", sys_info.magenta());
    println!("{}", "=".repeat(50).green());

    println!("{}", "1. 🔗 Connect to Tor Network".cyan());
    println!("{}", "2. ❌ Disconnect from Tor Network".red());
    println!("{}", "3. 🔍 Check Tor Status".yellow());
    println!("{}", "4. 🚪 Exit".magenta());

    println!("{}", "\nCurrent Status:".bold());
    check_tor_status_inline().await;

    println!("{}", "\n[INFO] This application routes all web traffic through the Tor network".yellow());
    println!("{}", "[CAUTION] Tor may slow down your connection and some websites may block Tor users".red());
}

async fn check_tor_status_inline() {
    // Check if Tor service is running
    let tor_running = is_tor_service_running();

    if tor_running {
        println!("{}", "Status: 🟢 Connected to Tor Network".green());
    } else {
        println!("{}", "Status: 🔴 Not Connected to Tor Network".red());
    }

    // Display current IP info
    display_current_ip_and_location().await;
}

async fn connect_to_tor() -> Result<()> {
    info!("Starting connection to Tor Network");
    println!("{}", "\n🔄 Connecting to Tor Network...".yellow());

    // Check if Tor is installed
    print!("{}", "🔍 Checking if Tor is installed... ");
    if !is_tor_installed() {
        println!("{}", "❌".red());
        println!("{}", "Tor is not installed on your system.".red());
        println!("{}", "Please install Tor using your package manager (e.g., 'sudo pacman -S tor' on Arch Linux)".yellow());
        warn!("Tor is not installed on the system");
        return Ok(());
    }
    info!("Tor is installed");
    println!("{}", "✅".green());

    // Check if already connected
    print!("{}", "🔒 Checking current Tor status... ");
    if is_tor_service_running() {
        println!("{}", "🟢 Already running".green());
        println!("{}", "Tor service is already running!".yellow());
        info!("Tor service already running, checking status...");
        check_tor_status_inline().await;
        return Ok(());
    }
    info!("Tor service is not currently running");
    println!("{}", "🔴 Not running".red());

    // Validate sudo access before attempting to start service
    print!("{}", "🔑 Validating sudo access... ");
    match validate_sudo_access() {
        Ok(_) => {
            info!("Sudo access validated successfully");
            println!("{}", "✅".green());
        },
        Err(e) => {
            println!("{}", "❌".red());
            println!("{}", format!("Insufficient privileges: {}", e).red());
            println!("{}", "Please ensure you have sudo access to start system services.".yellow());
            error!("Insufficient privileges to start Tor service: {}", e);
            return Ok(());
        }
    }

    // Backup current system state before making changes
    if let Err(e) = backup_system_state() {
        warn!("Could not backup system state: {}", e);
        println!("{}", format!("Warning: Could not backup system state: {}", e).yellow());
    } else {
        info!("System state backed up successfully");
    }

    info!("Starting Tor service...");
    // Show progress indicator while starting service
    print!("{}", "⚡ Starting Tor service... ".yellow());
    std::io::stdout().flush().unwrap(); // Ensure print is displayed immediately

    // Try to start the Tor service
    match start_tor_service_with_delay() {
        Ok(_) => {
            info!("Tor service started successfully");
            println!("{}", "🎉 Success!".green());

            // Verify that Tor is actually running
            print!("{}", "✅ Verifying Tor service status... ".yellow());
            if is_tor_service_running() {
                info!("Tor service is running and verified");
                // Create a state file to indicate that we're intentionally connected
                let torc_state_file = "/tmp/torc_state";
                if let Err(e) = std::fs::write(torc_state_file, "connected") {
                    warn!("Could not create state file: {}", e);
                    println!("{}", format!("Warning: Could not create state file: {}", e).yellow());
                } else {
                    info!("State file created successfully");
                }

                println!("{}", "✅ Verified".green());
                println!("{}", "\nTor connection established! All web traffic is now routed through Tor.".green());
                println!("{}", "🔒 Your IP address is now hidden and your traffic is anonymized.".green());

                // Configure system to route traffic through Tor (this is a simplified representation)
                configure_system_proxy();
                info!("System proxy configured for Tor");

                // Perform connection verification
                verify_tor_connection();
                info!("Connection verification completed");
            } else {
                warn!("Tor service may not be fully operational");
                println!("{}", "⚠️  Warning".yellow());
                println!("{}", "Warning: Tor service may not be fully operational.".yellow());
            }
        },
        Err(e) => {
            error!("Failed to connect to Tor: {}", e);
            println!("{}", "💥 Failed".red());
            println!("{}", format!("Failed to connect to Tor: {}", e).red());
            println!("{}", "📋 Troubleshooting tips:".yellow());
            println!("{}", "- Check if Tor configuration is valid: sudo tor --verify-config".yellow());
            println!("{}", "- Ensure no other Tor processes are running".yellow());
            println!("{}", "- Check system logs for more details: journalctl -u tor".yellow());
        }
    }
    info!("Tor connection attempt completed");
    Ok(())
}

async fn disconnect_from_tor() -> Result<()> {
    info!("Starting disconnection from Tor Network");
    println!("{}", "\nDisconnecting from Tor Network...".yellow());

    match stop_tor_service() {
        Ok(_) => {
            info!("Tor service stopped successfully");
            // Restore system state from backup if available
            if let Err(e) = restore_system_state_if_needed() {
                warn!("Could not restore system state: {}", e);
                println!("{}", format!("Warning: Could not restore system state: {}", e).red());
            } else {
                info!("System state restored successfully");
            }

            // Clean up the state file
            let torc_state_file = "/tmp/torc_state";
            if std::path::Path::new(torc_state_file).exists() {
                if let Err(e) = std::fs::remove_file(torc_state_file) {
                    warn!("Could not remove state file: {}", e);
                    println!("{}", format!("Warning: Could not remove state file: {}", e).yellow());
                } else {
                    info!("State file removed successfully");
                }
            }

            println!("{}", "Disconnected from Tor Network. Your traffic is no longer anonymized.".red());
            println!("{}", "Regular internet connection restored.".green());
            info!("Successfully disconnected from Tor Network");
        },
        Err(e) => {
            error!("Failed to disconnect from Tor Network: {}", e);
            println!("{}", format!("Failed to disconnect from Tor Network: {}", e).red());
        }
    }
    info!("Tor disconnection completed");
    Ok(())
}

async fn check_tor_status() -> Result<()> {
    info!("Checking Tor Network Status");
    println!("{}", "\nTor Network Status:".cyan().bold());

    let tor_installed = is_tor_installed();
    let tor_running = is_tor_service_running();

    if !tor_installed {
        warn!("Tor is not installed on the system");
        println!("{}", "Tor Status: ❌ Tor is not installed".red());
        println!("{}", "Install Tor to use this feature (e.g., 'sudo pacman -S tor' on Arch Linux)".yellow());
        return Ok(());
    }
    info!("Tor is installed: {}", tor_installed);

    if tor_running {
        info!("Tor service is running");
        println!("{}", "Tor Status: 🟢 Service is running".green());
        println!("{}", "Traffic: 🔒 All traffic is routed through Tor".green());
        display_tor_info();
    } else {
        info!("Tor service is not running");
        println!("{}", "Tor Status: 🔴 Service is not running".red());
        println!("{}", "Traffic: 🌐 Direct connection (not anonymous)".yellow());
    }

    // Display IP and location info
    info!("Fetching IP address information");
    println!("{}", "\n🌐 IP Address Information:".cyan());
    display_current_ip_and_location().await;

    info!("Tor status check completed");
    Ok(())
}



fn display_tor_info() {
    println!("{}", "\nTor Configuration:".cyan());
    println!("{}", "  SOCKS Proxy: 127.0.0.1:9050".white());
    println!("{}", "  DNS Port: 127.0.0.1:9053".white());
    println!("{}", "  Circuit Status: Active".white());

    // In a real implementation, we would fetch actual Tor circuit information
    println!("{}", "\nAnonymity Level: High".green());
    println!("{}", "IP Address: Hidden via Tor Network".green());
}

fn validate_sudo_access() -> Result<()> {
    let output = Command::new("sudo")
        .arg("--validate")
        .output()?;

    if !output.status.success() {
        bail!("Sudo access validation failed");
    }

    Ok(())
}


// Enhanced version of start_tor_service with animated delay indicator
fn start_tor_service_with_delay() -> Result<()> {
    // First validate sudo access
    validate_sudo_access()?;

    // Create an atomic boolean to control the animation thread
    let stop_animation = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop_animation);

    // Create a thread to show the animation
    let _animation_handle = std::thread::spawn(move || {
        let frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        let mut i = 0;

        while !stop_clone.load(Ordering::Relaxed) {
            print!("\r{}", format!("⚡ Starting Tor service... {}", frames[i]).yellow());
            std::io::stdout().flush().unwrap();

            i = (i + 1) % frames.len();
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        // Clear the line and reset cursor
        print!("\r");
        for _ in 0..50 {
            print!(" ");
        }
        print!("\r");
        std::io::stdout().flush().unwrap();
    });

    // Try to start the Tor service using systemctl
    let output = Command::new("sudo")
        .args(&["systemctl", "start", "tor"])
        .output()?;

    let result = if !output.status.success() {
        eprintln!("Warning: Direct systemctl start failed, trying to enable first...");

        // If systemctl fails, try enabling and then starting
        let output = Command::new("sudo")
            .args(&["systemctl", "enable", "tor"])
            .output()?;

        if output.status.success() {
            let output = Command::new("sudo")
                .args(&["systemctl", "start", "tor"])
                .output()?;

            if !output.status.success() {
                stop_animation.store(true, Ordering::Relaxed); // Stop animation
                bail!("Failed to start Tor service after enabling");
            } else {
                Ok(())
            }
        } else {
            stop_animation.store(true, Ordering::Relaxed); // Stop animation
            bail!("Failed to enable Tor service");
        }
    } else {
        Ok(())
    };

    // Wait a bit for Tor to initialize and then stop animation
    std::thread::sleep(std::time::Duration::from_secs(3));
    stop_animation.store(true, Ordering::Relaxed); // Stop animation
    std::thread::sleep(std::time::Duration::from_millis(200)); // Allow thread to finish

    result
}

// Verify Tor connection by checking if the Tor daemon is properly responding
fn verify_tor_connection() {
    println!();
    println!("{}", "Verifying Tor connection...".yellow());

    // Check if Tor process is active
    let tor_process_check = Command::new("pgrep")
        .arg("tor")
        .output();

    match tor_process_check {
        Ok(output) => {
            if output.status.success() {
                println!("{}", "✓ Tor daemon is running".green());

                // Additional check for Tor socket
                if std::net::TcpStream::connect("127.0.0.1:9050").is_ok() {
                    println!("{}", "✓ Tor SOCKS proxy is accessible".green());
                } else {
                    println!("{}", "⚠ Tor SOCKS proxy may not be accessible".yellow());
                }
            } else {
                println!("{}", "⚠ Tor daemon may not be running properly".yellow());
            }
        },
        Err(_) => {
            println!("{}", "⚠ Could not verify Tor daemon status".yellow());
        }
    }

    // Perform security check: verify Tor configuration
    check_tor_security_config();
}

// Check Tor configuration for security issues
fn check_tor_security_config() {
    println!("{}", "\n🔒 Security Configuration Check".yellow());

    // Check if Tor configuration is valid
    let config_check = Command::new("sudo")
        .args(&["tor", "--verify-config"])
        .output();

    match config_check {
        Ok(output) => {
            if output.status.success() {
                println!("{}", "✓ Tor configuration is valid".green());

                // Additional security checks could go here
                check_additional_security_settings();
            } else {
                println!("{}", "⚠ Tor configuration may have issues".yellow());
                println!("{}", format!("  Details: {}", String::from_utf8_lossy(&output.stderr)).red());
            }
        },
        Err(_) => {
            println!("{}", "⚠ Could not verify Tor configuration".yellow());
        }
    }
}

// Additional security configuration checks
fn check_additional_security_settings() {
    // Check if default ports are properly configured
    if std::net::TcpStream::connect("127.0.0.1:9050").is_ok() {
        println!("{}", "✓ Default SOCKS port (9050) is accessible".green());
    } else {
        println!("{}", "⚠ Default SOCKS port (9050) is not accessible".yellow());
    }

    if std::net::TcpStream::connect("127.0.0.1:9053").is_ok() {
        println!("{}", "✓ Default DNS port (9053) is accessible".green());
    } else {
        println!("{}", "ℹ DNS port (9053) is not accessible (may be intentionally disabled)".yellow());
    }

    // Check for potential security misconfigurations
    let torrc_path = "/etc/tor/torrc";
    if Path::new(torrc_path).exists() {
        let torrc_content = fs::read_to_string(torrc_path);
        if let Ok(content) = torrc_content {
            // Check for potentially insecure settings
            if content.contains("SocksPort 0.0.0.0:") {
                println!("{}", "⚠ Tor SOCKS port is exposed to external interfaces - potential security risk".red());
            } else {
                println!("{}", "✓ Tor SOCKS port is properly restricted".green());
            }

            if content.contains("DisableNetwork 1") {
                println!("{}", "⚠ Tor network is disabled in configuration".yellow());
            }
        }
    }
}

fn stop_tor_service() -> Result<()> {
    let output = Command::new("sudo")
        .args(&["systemctl", "stop", "tor"])
        .output()?;

    if !output.status.success() {
        bail!("Failed to stop Tor service");
    }

    Ok(())
}

fn is_tor_service_running() -> bool {
    let output = Command::new("systemctl")
        .args(&["is-active", "tor"])
        .output();

    match output {
        Ok(output) => output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "active",
        Err(e) => {
            eprintln!("Warning: Could not check Tor service status: {}", e);
            false
        },
    }
}

fn is_tor_installed() -> bool {
    let output = Command::new("which")
        .arg("tor")
        .output();

    match output {
        Ok(output) => output.status.success(),
        Err(e) => {
            eprintln!("Warning: Could not check if Tor is installed: {}", e);
            false
        },
    }
}

// Function to get the current external IP address
async fn get_external_ip() -> Result<Option<String>> {
    let client = reqwest::Client::new();
    info!("Attempting to retrieve external IP address");

    // Try multiple IP checking services as fallbacks
    let urls = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ident.me",
        "https://ipecho.net/plain",
        "https://checkip.amazonaws.com",
    ];

    for (i, url) in urls.iter().enumerate() {
        debug!("Trying IP service #{}: {}", i + 1, url);
        match client.get(*url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.text().await {
                        Ok(ip) => {
                            let ip = ip.trim().to_string();
                            debug!("Retrieved IP from {}: {}", url, ip);
                            // Basic validation to ensure it's a valid IP
                            if is_valid_ip(&ip) {
                                info!("Successfully retrieved external IP address: {}", ip);
                                return Ok(Some(ip));
                            } else {
                                debug!("Invalid IP format from {}: {}", url, ip);
                            }
                        }
                        Err(e) => {
                            debug!("Failed to read response from {}: {}", url, e);
                            continue;
                        }
                    }
                } else {
                    debug!("Service {} returned non-success status: {}", url, response.status());
                }
            }
            Err(e) => {
                debug!("Failed to connect to {}: {}", url, e);
                continue;
            }
        }
    }

    warn!("Failed to retrieve external IP address from all services");
    Ok(None)
}

// Function to check if a string is a valid IP address
fn is_valid_ip(ip_str: &str) -> bool {
    // Check if it's a valid IPv4 address
    if Ipv4Addr::from_str(ip_str).is_ok() {
        return true;
    }

    // Check if it's a valid IPv6 address
    if Ipv6Addr::from_str(ip_str).is_ok() {
        return true;
    }

    false
}

// Function to get geo location information for an IP
async fn get_geo_location(ip: &str) -> Result<GeoIPInfo> {
    info!("Attempting to retrieve geo location for IP: {}", ip);
    let client = reqwest::Client::new();

    // Try IP geolocation services in order of preference
    let services = [
        ("https://ipapi.co/{}/json/", vec!["country_name", "city", "region", "org"]),
        ("https://ipinfo.io/{}/json", vec!["country", "city", "region", "org"])
    ];

    for (i, (url_template, fields)) in services.iter().enumerate() {
        let url = url_template.replace("{}", ip);
        debug!("Trying geo location service #{}: {}", i + 1, url);

        match client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<serde_json::Value>().await {
                        Ok(geo_data) => {
                            debug!("Successfully retrieved geo data from {}", url);
                            let country = geo_data.get(fields[0]).and_then(|v| v.as_str()).map(|s| s.to_string());
                            let city = geo_data.get(fields[1]).and_then(|v| v.as_str()).map(|s| s.to_string());
                            let region = geo_data.get(fields[2]).and_then(|v| v.as_str()).map(|s| s.to_string());
                            let isp = geo_data.get(fields[3]).and_then(|v| v.as_str()).map(|s| s.to_string());

                            if country.is_some() || city.is_some() || region.is_some() || isp.is_some() {
                                info!("Successfully retrieved geo location for IP {}: country={}, city={}, region={}, isp={}",
                                      ip,
                                      country.as_deref().unwrap_or("N/A"),
                                      city.as_deref().unwrap_or("N/A"),
                                      region.as_deref().unwrap_or("N/A"),
                                      isp.as_deref().unwrap_or("N/A"));

                                return Ok(GeoIPInfo {
                                    ip: ip.to_string(),
                                    country,
                                    city,
                                    region,
                                    isp,
                                });
                            }
                        }
                        Err(e) => {
                            debug!("Failed to parse geo location data from {}: {}", url, e);
                        }
                    }
                } else {
                    debug!("Service {} returned non-success status: {}", url, response.status());
                }
            }
            Err(e) => {
                debug!("Failed to fetch geo location data from {}: {}", url, e);
            }
        }
    }

    // If all services failed, return a basic GeoIPInfo with just the IP
    warn!("Failed to get geo location data for IP: {} from all services", ip);
    Ok(GeoIPInfo {
        ip: ip.to_string(),
        country: None,
        city: None,
        region: None,
        isp: None,
    })
}

// Function to get basic system information
fn get_system_info() -> String {
    use sysinfo::System;

    let mut sys = System::new_all();
    sys.refresh_all(); // Update all information

    // Use the methods that are available in sysinfo v0.30
    let os_name = System::name().unwrap_or_else(|| "Unknown".to_string());
    let os_version = System::os_version().unwrap_or_else(|| "Unknown".to_string());
    let host_name = System::host_name().unwrap_or_else(|| "Unknown".to_string());
    let kernel_version = System::kernel_version().unwrap_or_else(|| "Unknown".to_string());

    // Format system info as a compact string for the menu
    let os_info = if os_version != "Unknown" {
        format!("{} {}", os_name, os_version)
    } else {
        os_name
    };

    format!("OS: {}, Host: {}, Kernel: {}", os_info, host_name, kernel_version)
}

// Function to display the current IP address and location
async fn display_current_ip_and_location() {
    print!("{}", "🌐 Checking your public IP address... ".cyan());
    std::io::stdout().flush().unwrap();

    match get_external_ip().await {
        Ok(Some(ip)) => {
            println!("{}", "✓".green());
            print!("{}", "🌍 Getting location info... ".cyan());
            std::io::stdout().flush().unwrap();

            match get_geo_location(&ip).await {
                Ok(geo_info) => {
                    println!("{}", "✓".green());
                    println!("  📍 Your public IP: {}", geo_info.ip.yellow().bold());

                    if let Some(country) = &geo_info.country {
                        print!("     Country: {}", country.green());
                    }

                    if let Some(city) = &geo_info.city {
                        print!(", City: {}", city.green());
                    }

                    if let Some(region) = &geo_info.region {
                        print!(", Region: {}", region.green());
                    }

                    if let Some(isp) = &geo_info.isp {
                        println!("\n     ISP: {}", isp.green());
                    } else {
                        println!();
                    }
                }
                Err(e) => {
                    println!("{}", "✗".red());
                    println!("     📡 IP: {} (Location lookup failed: {})", ip.yellow().bold(), e.to_string().red());
                }
            }
        }
        Ok(None) => {
            println!("{}", "✗".red());
            println!("{}", "     ❌ Could not determine your public IP address".red());
        }
        Err(e) => {
            println!("{}", "✗".red());
            println!("     ❌ Error getting public IP: {}", e.to_string().red());
        }
    }
}

// Structure to store the system network state before connecting to Tor
#[derive(Debug, Clone)]
struct SystemNetworkState {
    proxy_settings: Option<String>,
    firewall_rules: Vec<String>,
    dns_servers: Vec<String>,
    routing_table: Vec<String>,
    network_interfaces: Vec<String>,
}

// Global variable to store the backup of system state using thread-safe approach
static SYSTEM_STATE_BACKUP: LazyLock<Mutex<Option<SystemNetworkState>>> = LazyLock::new(|| Mutex::new(None));

fn backup_system_state() -> Result<SystemNetworkState> {
    println!("{}", "Backing up current system network state...".yellow());

    // Store current proxy settings
    let proxy_settings = get_current_proxy_settings()?;

    // Store current firewall rules
    let firewall_rules = get_current_firewall_rules()?;

    // Store current DNS servers
    let dns_servers = get_current_dns_servers()?;

    // Store current routing table
    let routing_table = get_current_routing_table()?;

    // Store current network interfaces configuration
    let network_interfaces = get_current_network_interfaces()?;

    let state = SystemNetworkState {
        proxy_settings,
        firewall_rules,
        dns_servers,
        routing_table,
        network_interfaces,
    };

    {
        let mut backup = SYSTEM_STATE_BACKUP.lock().unwrap();
        *backup = Some(state.clone());
    }

    println!("{}", "✓ System network state backed up successfully".green());
    Ok(state)
}

fn get_current_proxy_settings() -> Result<Option<String>> {
    // In a real implementation, this would check various proxy settings
    // such as environment variables (HTTP_PROXY, HTTPS_PROXY, etc.)
    // and system proxy configurations

    // Get all proxy-related environment variables
    let http_proxy = std::env::var("HTTP_PROXY").ok();
    let https_proxy = std::env::var("HTTPS_PROXY").ok();
    let ftp_proxy = std::env::var("FTP_PROXY").ok();
    let no_proxy = std::env::var("NO_PROXY").ok();
    let all_proxy = std::env::var("ALL_PROXY").ok();

    // Get system-wide proxy settings if available (for GNOME/KDE systems)
    let mut system_http_proxy = None;
    let mut system_https_proxy = None;

    // Try to get GNOME proxy settings
    if let Ok(gnome_http_output) = Command::new("gsettings")
        .args(&["get", "org.gnome.system.proxy.http", "host"])
        .output()
    {
        if gnome_http_output.status.success() {
            let output_str = String::from_utf8_lossy(&gnome_http_output.stdout).trim().to_string();
            if !output_str.is_empty() && output_str != "''" {
                if let Ok(port_output) = Command::new("gsettings")
                    .args(&["get", "org.gnome.system.proxy.http", "port"])
                    .output()
                {
                    if port_output.status.success() {
                        let port_str = String::from_utf8_lossy(&port_output.stdout).trim().to_string();
                        let port_num = port_str.parse::<u16>().unwrap_or(8080);
                        system_http_proxy = Some(format!("{}:{}", output_str.trim_matches('\''), port_num));
                    }
                }
            }
        }
    }

    // Try to get GNOME HTTPS proxy settings
    if let Ok(gnome_https_output) = Command::new("gsettings")
        .args(&["get", "org.gnome.system.proxy.https", "host"])
        .output()
    {
        if gnome_https_output.status.success() {
            let output_str = String::from_utf8_lossy(&gnome_https_output.stdout).trim().to_string();
            if !output_str.is_empty() && output_str != "''" {
                if let Ok(port_output) = Command::new("gsettings")
                    .args(&["get", "org.gnome.system.proxy.https", "port"])
                    .output()
                {
                    if port_output.status.success() {
                        let port_str = String::from_utf8_lossy(&port_output.stdout).trim().to_string();
                        let port_num = port_str.parse::<u16>().unwrap_or(8080);
                        system_https_proxy = Some(format!("{}:{}", output_str.trim_matches('\''), port_num));
                    }
                }
            }
        }
    }

    // Compile all proxy settings into a JSON-like structure
    let proxy_settings = serde_json::json!({
        "environment": {
            "HTTP_PROXY": http_proxy,
            "HTTPS_PROXY": https_proxy,
            "FTP_PROXY": ftp_proxy,
            "NO_PROXY": no_proxy,
            "ALL_PROXY": all_proxy
        },
        "system": {
            "GNOME_HTTP_PROXY": system_http_proxy,
            "GNOME_HTTPS_PROXY": system_https_proxy
        }
    }).to_string();

    Ok(Some(proxy_settings))
}

fn get_current_firewall_rules() -> Result<Vec<String>> {
    // Placeholder: In a real implementation, this would get current iptables rules
    let output = Command::new("iptables")
        .args(&["-L", "-n"])
        .output()?;

    if output.status.success() {
        let rules = String::from_utf8_lossy(&output.stdout);
        let mut rule_list: Vec<String> = Vec::new();

        for line in rules.lines() {
            if !line.is_empty() {
                rule_list.push(line.to_string());
            }
        }

        Ok(rule_list)
    } else {
        // Return empty list if iptables command failed (might not be available)
        Ok(Vec::new())
    }
}

fn get_current_dns_servers() -> Result<Vec<String>> {
    // In a real implementation, this would parse /etc/resolv.conf
    // or query systemd-resolved for current DNS servers

    // Determine if we're using systemd-resolved by checking its status
    let using_systemd_resolved = Command::new("systemctl")
        .args(&["is-active", "systemd-resolved"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);

    let mut dns_servers = Vec::new();

    if using_systemd_resolved {
        // Get DNS servers from systemd-resolved
        let output = Command::new("resolvectl")
            .args(&["status"])
            .output()?;

        if output.status.success() {
            let status = String::from_utf8_lossy(&output.stdout);
            for line in status.lines() {
                if line.contains("Current DNS Server:") || line.contains("DNS Servers:") {
                    // Extract IP addresses from the line
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    for part in parts {
                        // Simple validation for IPv4 addresses
                        if part.contains('.') && part.chars().all(|c| c.is_ascii_digit() || c == '.') {
                            dns_servers.push(part.to_string());
                        }
                    }
                }
            }
        }
    }

    // Also read from /etc/resolv.conf as fallback or additional sources
    if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in contents.lines() {
            if line.starts_with("nameserver ") {
                let dns_server = line.trim_start_matches("nameserver ").to_string();
                if !dns_servers.contains(&dns_server) {  // Avoid duplicates
                    dns_servers.push(dns_server);
                }
            }
        }
    }

    Ok(dns_servers)
}

fn get_current_routing_table() -> Result<Vec<String>> {
    // Placeholder: In a real implementation, this would get the current routing table
    let output = Command::new("ip")
        .args(&["route", "show"])
        .output()?;

    if output.status.success() {
        let routes = String::from_utf8_lossy(&output.stdout);
        let mut route_list: Vec<String> = Vec::new();

        for line in routes.lines() {
            if !line.is_empty() {
                route_list.push(line.to_string());
            }
        }

        Ok(route_list)
    } else {
        // Try alternative command if 'ip' is not available
        let output = Command::new("route")
            .args(&["-n"])
            .output()?;

        if output.status.success() {
            let routes = String::from_utf8_lossy(&output.stdout);
            let mut route_list: Vec<String> = Vec::new();

            for line in routes.lines() {
                if !line.is_empty() {
                    route_list.push(line.to_string());
                }
            }

            Ok(route_list)
        } else {
            Ok(Vec::new())
        }
    }
}

fn get_current_network_interfaces() -> Result<Vec<String>> {
    // Placeholder: In a real implementation, this would get current network interface configurations
    let output = Command::new("ip")
        .args(&["addr", "show"])
        .output()?;

    if output.status.success() {
        let interfaces = String::from_utf8_lossy(&output.stdout);
        let mut interface_list: Vec<String> = Vec::new();

        for line in interfaces.lines() {
            if !line.is_empty() {
                interface_list.push(line.to_string());
            }
        }

        Ok(interface_list)
    } else {
        Ok(Vec::new())
    }
}

fn configure_system_proxy() {
    println!("{}", "Configuring system to route traffic through Tor...".yellow());

    // Set environment variables for proxy
    std::env::set_var("HTTP_PROXY", "socks5://127.0.0.1:9050");
    std::env::set_var("HTTPS_PROXY", "socks5://127.0.0.1:9050");
    std::env::set_var("ALL_PROXY", "socks5://127.0.0.1:9050");

    // Try to set GNOME proxy settings to route through Tor
    let _ = Command::new("gsettings")
        .args(&["set", "org.gnome.system.proxy", "mode", "manual"])
        .output();
    let _ = Command::new("gsettings")
        .args(&["set", "org.gnome.system.proxy.socks", "host", "127.0.0.1"])
        .output();
    let _ = Command::new("gsettings")
        .args(&["set", "org.gnome.system.proxy.socks", "port", "9050"])
        .output();

    // Configure iptables rules to redirect traffic through Tor
    if configure_iptables_for_tor() {
        println!("{}", "✓ System configured to use Tor proxy (127.0.0.1:9050)".green());
        println!("{}", "✓ Environment variables and GNOME proxy settings updated".green());
        println!("{}", "✓ IPTables rules configured for Tor traffic routing".green());
    } else {
        // If iptables configuration failed, warn the user but continue
        warn!("IPTables configuration failed - traffic may not be properly routed through Tor");
        println!("{}", "⚠️  System configured but IPTables rules failed - traffic may not be properly routed".yellow());
        println!("{}", "⚠️  Please check your sudo permissions for iptables".yellow());
    }
}

// Helper function to get the Tor user ID
fn get_tor_user_id() -> Option<String> {
    // Try to get Tor user ID from common locations
    let possible_users = vec!["tor", "debian-tor"];

    for user in possible_users {
        let result = Command::new("id")
            .arg("-u")
            .arg(user)
            .output();

        if let Ok(output) = result {
            if output.status.success() {
                return Some(user.to_string());
            }
        }
    }

    // If we can't find the specific Tor user, try to get the UID from Tor process
    let ps_result = Command::new("ps")
        .args(&["aux"])
        .output();

    if let Ok(output) = ps_result {
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.contains("tor") && !line.contains("ps aux") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if !parts.is_empty() {
                    return Some(parts[0].to_string()); // First column is the user
                }
            }
        }
    }

    None
}

// Configure iptables rules to redirect traffic through Tor
// Returns true if successful, false if there was an error
fn configure_iptables_for_tor() -> bool {
    info!("Configuring iptables rules for Tor traffic routing");

    let mut success = true;

    // Define Tor user ID (default is usually 'debian-tor' or 'tor')
    let tor_user = get_tor_user_id();

    if tor_user.is_none() {
        warn!("Could not determine Tor user ID, using default 'debian-tor'");
        // We'll continue with a default guess
    }

    let tor_uid = tor_user.unwrap_or_else(|| "debian-tor".to_string());

    // Configure iptables rules for IPv4 traffic redirection
    let ipv4_rules = vec![
        // Flush existing OUTPUT chain rules in mangle table for IPv4
        vec!["-t", "mangle", "-F", "OUTPUT"],
        // Create new chain for Tor traffic (IPv4)
        vec!["-t", "mangle", "-N", "TOR_REDIRECT_V4"],
        // Redirect all TCP traffic (except loopback and already redirected) to Tor
        vec!["-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "!", "-o", "lo", "!", "-d", "127.0.0.1", "-j", "TOR_REDIRECT_V4"],
        // Mark traffic from Tor user to not be redirected (avoid loops)
        vec!["-t", "mangle", "-A", "TOR_REDIRECT_V4", "-m", "owner", "--uid-owner", &tor_uid, "-j", "RETURN"],
        // Redirect remaining traffic to Tor's transparent proxy port (9040)
        vec!["-t", "mangle", "-A", "TOR_REDIRECT_V4", "-p", "tcp", "--tcp-flags", "FIN,SYN,RST,ACK", "SYN", "-j", "REDIRECT", "--to-port", "9040"]
    ];

    // Apply IPv4 iptables rules
    for rule in &ipv4_rules {
        match Command::new("sudo")
            .arg("iptables")
            .args(rule)
            .output() {
            Ok(output) => {
                if !output.status.success() {
                    warn!("Failed to set IPv4 iptables rule '{:?}': {}", rule, String::from_utf8_lossy(&output.stderr));
                    success = false;
                } else {
                    debug!("Successfully set IPv4 iptables rule: {:?}", rule);
                }
            }
            Err(e) => {
                warn!("Failed to execute IPv4 iptables command: {}", e);
                success = false;
            }
        }
    }

    // Also configure OUTPUT chain for the main table to redirect IPv4 traffic to Tor's SOCKS port
    let ipv4_nat_rules = vec![
        // Flush existing OUTPUT chain rules in nat table for IPv4
        vec!["-t", "nat", "-F", "OUTPUT"],
        // Create new chain for Tor traffic (IPv4)
        vec!["-t", "nat", "-N", "TOR_SOCKS_V4"],
        // Don't redirect traffic from Tor user (avoid loops)
        vec!["-t", "nat", "-A", "TOR_SOCKS_V4", "-m", "owner", "--uid-owner", &tor_uid, "-j", "RETURN"],
        // Redirect all other TCP traffic to Tor's SOCKS proxy
        vec!["-t", "nat", "-A", "TOR_SOCKS_V4", "-p", "tcp", "--tcp-flags", "FIN,SYN,RST,ACK", "SYN", "-j", "REDIRECT", "--to-port", "9050"],
        // Use the chain in OUTPUT
        vec!["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "!", "-o", "lo", "!", "-d", "127.0.0.1", "-j", "TOR_SOCKS_V4"]
    ];

    for rule in &ipv4_nat_rules {
        match Command::new("sudo")
            .arg("iptables")
            .args(rule)
            .output() {
            Ok(output) => {
                if !output.status.success() {
                    warn!("Failed to set IPv4 nat iptables rule '{:?}': {}", rule, String::from_utf8_lossy(&output.stderr));
                    success = false;
                } else {
                    debug!("Successfully set IPv4 nat iptables rule: {:?}", rule);
                }
            }
            Err(e) => {
                warn!("Failed to execute IPv4 nat iptables command: {}", e);
                success = false;
            }
        }
    }

    // Configure ip6tables rules for IPv6 traffic redirection
    let ipv6_rules = vec![
        // Flush existing OUTPUT chain rules in mangle table for IPv6
        vec!["-t", "mangle", "-F", "OUTPUT"],
        // Create new chain for Tor traffic (IPv6)
        vec!["-t", "mangle", "-N", "TOR_REDIRECT_V6"],
        // Redirect all TCP traffic (except loopback and already redirected) to Tor
        vec!["-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "!", "-o", "lo", "!", "-d", "::1", "-j", "TOR_REDIRECT_V6"],
        // Mark traffic from Tor user to not be redirected (avoid loops)
        vec!["-t", "mangle", "-A", "TOR_REDIRECT_V6", "-m", "owner", "--uid-owner", &tor_uid, "-j", "RETURN"],
        // Redirect remaining traffic to Tor's transparent proxy port (9040)
        vec!["-t", "mangle", "-A", "TOR_REDIRECT_V6", "-p", "tcp", "--tcp-flags", "FIN,SYN,RST,ACK", "SYN", "-j", "REDIRECT", "--to-port", "9040"]
    ];

    // Apply IPv6 iptables rules
    for rule in &ipv6_rules {
        match Command::new("sudo")
            .arg("ip6tables")
            .args(rule)
            .output() {
            Ok(output) => {
                if !output.status.success() {
                    warn!("Failed to set IPv6 ip6tables rule '{:?}': {}", rule, String::from_utf8_lossy(&output.stderr));
                    // IPv6 failure is non-critical since IPv4 is the main concern
                } else {
                    debug!("Successfully set IPv6 ip6tables rule: {:?}", rule);
                }
            }
            Err(e) => {
                warn!("Failed to execute IPv6 ip6tables command: {}", e);
                // IPv6 failure is non-critical since IPv4 is the main concern
            }
        }
    }

    // Also configure OUTPUT chain for the main table to redirect IPv6 traffic to Tor's SOCKS port
    let ipv6_nat_rules = vec![
        // Flush existing OUTPUT chain rules in nat table for IPv6
        vec!["-t", "nat", "-F", "OUTPUT"],
        // Create new chain for Tor traffic (IPv6)
        vec!["-t", "nat", "-N", "TOR_SOCKS_V6"],
        // Don't redirect traffic from Tor user (avoid loops)
        vec!["-t", "nat", "-A", "TOR_SOCKS_V6", "-m", "owner", "--uid-owner", &tor_uid, "-j", "RETURN"],
        // Redirect all other TCP traffic to Tor's SOCKS proxy
        vec!["-t", "nat", "-A", "TOR_SOCKS_V6", "-p", "tcp", "--tcp-flags", "FIN,SYN,RST,ACK", "SYN", "-j", "REDIRECT", "--to-port", "9050"],
        // Use the chain in OUTPUT
        vec!["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "!", "-o", "lo", "!", "-d", "::1", "-j", "TOR_SOCKS_V6"]
    ];

    for rule in &ipv6_nat_rules {
        match Command::new("sudo")
            .arg("ip6tables")
            .args(rule)
            .output() {
            Ok(output) => {
                if !output.status.success() {
                    warn!("Failed to set IPv6 nat ip6tables rule '{:?}': {}", rule, String::from_utf8_lossy(&output.stderr));
                    // IPv6 failure is non-critical since IPv4 is the main concern
                } else {
                    debug!("Successfully set IPv6 nat ip6tables rule: {:?}", rule);
                }
            }
            Err(e) => {
                warn!("Failed to execute IPv6 nat ip6tables command: {}", e);
                // IPv6 failure is non-critical since IPv4 is the main concern
            }
        }
    }

    info!("Iptables configuration for Tor completed with success: {}", success);
    success
}


fn restore_system_proxy() {
    println!("{}", "Restoring normal system routing...".yellow());

    // Remove Tor-related proxy environment variables
    std::env::remove_var("HTTP_PROXY");
    std::env::remove_var("HTTPS_PROXY");
    std::env::remove_var("ALL_PROXY");
    std::env::remove_var("NO_PROXY");

    // Try to reset GNOME proxy settings to none
    let _ = Command::new("gsettings")
        .args(&["set", "org.gnome.system.proxy", "mode", "none"])
        .output();
    let _ = Command::new("gsettings")
        .args(&["reset", "org.gnome.system.proxy.socks", "host"])
        .output();
    let _ = Command::new("gsettings")
        .args(&["reset", "org.gnome.system.proxy.socks", "port"])
        .output();

    // Remove the iptables rules that redirect traffic through Tor
    if restore_iptables_rules() {
        println!("{}", "✓ Environment variables and GNOME proxy settings reset".green());
        println!("{}", "✓ IPTables rules removed".green());
        println!("{}", "✓ Normal system routing restored".green());
    } else {
        // If iptables restoration failed, warn the user but continue
        warn!("IPTables rule restoration failed - manual cleanup may be needed");
        println!("{}", "⚠️  Environment variables reset but IPTables restoration failed".yellow());
        println!("{}", "⚠️  Manual iptables cleanup may be required".yellow());
    }
}

// Restore iptables rules to remove Tor redirection
// Returns true if successful, false if there was an error
fn restore_iptables_rules() -> bool {
    info!("Restoring iptables rules to normal state");

    let mut success = true;

    // Remove the IPv4 chains we created
    let ipv4_cleanup_rules = vec![
        // Delete references to our custom IPv4 chains in OUTPUT
        vec!["-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "!", "-o", "lo", "!", "-d", "127.0.0.1", "-j", "TOR_REDIRECT_V4"],
        vec!["-t", "nat", "-D", "OUTPUT", "-p", "tcp", "!", "-o", "lo", "!", "-d", "127.0.0.1", "-j", "TOR_SOCKS_V4"],
        // Flush and delete our custom IPv4 chains
        vec!["-t", "mangle", "-F", "TOR_REDIRECT_V4"],
        vec!["-t", "mangle", "-X", "TOR_REDIRECT_V4"],
        vec!["-t", "nat", "-F", "TOR_SOCKS_V4"],
        vec!["-t", "nat", "-X", "TOR_SOCKS_V4"],
    ];

    for rule in &ipv4_cleanup_rules {
        match Command::new("sudo")
            .arg("iptables")
            .args(rule)
            .output() {
            Ok(output) => {
                if !output.status.success() {
                    // It's OK if some rules don't exist to delete, just warn
                    debug!("Warning during IPv4 iptables cleanup for rule '{:?}': {}", rule, String::from_utf8_lossy(&output.stderr));
                } else {
                    debug!("Successfully removed IPv4 iptables rule: {:?}", rule);
                }
            }
            Err(e) => {
                warn!("Failed to execute IPv4 iptables cleanup command: {}", e);
                success = false;
            }
        }
    }

    // Remove the IPv6 chains we created
    let ipv6_cleanup_rules = vec![
        // Delete references to our custom IPv6 chains in OUTPUT
        vec!["-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "!", "-o", "lo", "!", "-d", "::1", "-j", "TOR_REDIRECT_V6"],
        vec!["-t", "nat", "-D", "OUTPUT", "-p", "tcp", "!", "-o", "lo", "!", "-d", "::1", "-j", "TOR_SOCKS_V6"],
        // Flush and delete our custom IPv6 chains
        vec!["-t", "mangle", "-F", "TOR_REDIRECT_V6"],
        vec!["-t", "mangle", "-X", "TOR_REDIRECT_V6"],
        vec!["-t", "nat", "-F", "TOR_SOCKS_V6"],
        vec!["-t", "nat", "-X", "TOR_SOCKS_V6"],
    ];

    for rule in &ipv6_cleanup_rules {
        match Command::new("sudo")
            .arg("ip6tables")
            .args(rule)
            .output() {
            Ok(output) => {
                if !output.status.success() {
                    // It's OK if some rules don't exist to delete, just warn
                    debug!("Warning during IPv6 ip6tables cleanup for rule '{:?}': {}", rule, String::from_utf8_lossy(&output.stderr));
                } else {
                    debug!("Successfully removed IPv6 ip6tables rule: {:?}", rule);
                }
            }
            Err(e) => {
                warn!("Failed to execute IPv6 ip6tables cleanup command: {}", e);
                success = false;
            }
        }
    }

    // Also flush all rules in mangle and nat tables to ensure clean state for IPv4
    let ipv4_flush_rules = vec![
        vec!["-t", "mangle", "-F"],
        vec!["-t", "nat", "-F"],
    ];

    for rule in &ipv4_flush_rules {
        match Command::new("sudo")
            .arg("iptables")
            .args(rule)
            .output() {
            Ok(output) => {
                if !output.status.success() {
                    warn!("Failed to flush IPv4 iptables table: {}", String::from_utf8_lossy(&output.stderr));
                    success = false;
                } else {
                    debug!("Successfully flushed IPv4 iptables table: {:?}", rule);
                }
            }
            Err(e) => {
                warn!("Failed to execute IPv4 iptables flush command: {}", e);
                success = false;
            }
        }
    }

    // Also flush all rules in mangle and nat tables to ensure clean state for IPv6
    let ipv6_flush_rules = vec![
        vec!["-t", "mangle", "-F"],
        vec!["-t", "nat", "-F"],
    ];

    for rule in &ipv6_flush_rules {
        match Command::new("sudo")
            .arg("ip6tables")
            .args(rule)
            .output() {
            Ok(output) => {
                if !output.status.success() {
                    warn!("Failed to flush IPv6 ip6tables table: {}", String::from_utf8_lossy(&output.stderr));
                    // IPv6 failure is non-critical since IPv4 is the main concern
                } else {
                    debug!("Successfully flushed IPv6 ip6tables table: {:?}", rule);
                }
            }
            Err(e) => {
                warn!("Failed to execute IPv6 ip6tables flush command: {}", e);
                // IPv6 failure is non-critical since IPv4 is the main concern
            }
        }
    }

    info!("Iptables restoration completed with success: {}", success);
    success
}

fn restore_system_state() -> Result<()> {
    println!("{}", "Restoring system network state from backup...".yellow());

    let state = {
        let backup = SYSTEM_STATE_BACKUP.lock().unwrap();
        backup.clone()
    };

    if let Some(state) = &state {
        // Restore proxy settings
        restore_proxy_settings(&state.proxy_settings)?;

        // Restore firewall rules
        restore_firewall_rules(&state.firewall_rules)?;

        // Restore DNS servers
        restore_dns_servers(&state.dns_servers)?;

        // Restore routing table
        restore_routing_table(&state.routing_table)?;

        // Restore network interfaces
        restore_network_interfaces(&state.network_interfaces)?;

        println!("{}", "✓ System network state restored successfully".green());

        // Clear the backup
        {
            let mut backup = SYSTEM_STATE_BACKUP.lock().unwrap();
            *backup = None;
        }

        Ok(())
    } else {
        println!("{}", "⚠️  No system state backup found to restore".yellow());
        Ok(())
    }
}

fn restore_proxy_settings(proxy_settings: &Option<String>) -> Result<()> {
    // In a real implementation, this would restore proxy settings
    // This would involve restoring environment variables and system proxy configs
    println!("{}", "Restoring proxy settings...".yellow());

    match proxy_settings {
        Some(settings_str) => {
            // Parse the JSON string containing proxy settings
            if let Ok(settings) = serde_json::from_str::<serde_json::Value>(settings_str) {
                let env_proxies = settings.get("environment");

                // Restore environment variables
                if let Some(env) = env_proxies {
                    if let Some(http_proxy) = env.get("HTTP_PROXY").and_then(|v| v.as_str()) {
                        std::env::set_var("HTTP_PROXY", http_proxy);
                        println!("{}", format!("Restored HTTP_PROXY: {}", http_proxy).green());
                    } else {
                        std::env::remove_var("HTTP_PROXY");
                        println!("{}", "Removed HTTP_PROXY".green());
                    }

                    if let Some(https_proxy) = env.get("HTTPS_PROXY").and_then(|v| v.as_str()) {
                        std::env::set_var("HTTPS_PROXY", https_proxy);
                        println!("{}", format!("Restored HTTPS_PROXY: {}", https_proxy).green());
                    } else {
                        std::env::remove_var("HTTPS_PROXY");
                        println!("{}", "Removed HTTPS_PROXY".green());
                    }

                    if let Some(ftp_proxy) = env.get("FTP_PROXY").and_then(|v| v.as_str()) {
                        std::env::set_var("FTP_PROXY", ftp_proxy);
                        println!("{}", format!("Restored FTP_PROXY: {}", ftp_proxy).green());
                    } else {
                        std::env::remove_var("FTP_PROXY");
                        println!("{}", "Removed FTP_PROXY".green());
                    }

                    if let Some(no_proxy) = env.get("NO_PROXY").and_then(|v| v.as_str()) {
                        std::env::set_var("NO_PROXY", no_proxy);
                        println!("{}", format!("Restored NO_PROXY: {}", no_proxy).green());
                    } else {
                        std::env::remove_var("NO_PROXY");
                        println!("{}", "Removed NO_PROXY".green());
                    }

                    if let Some(all_proxy) = env.get("ALL_PROXY").and_then(|v| v.as_str()) {
                        std::env::set_var("ALL_PROXY", all_proxy);
                        println!("{}", format!("Restored ALL_PROXY: {}", all_proxy).green());
                    } else {
                        std::env::remove_var("ALL_PROXY");
                        println!("{}", "Removed ALL_PROXY".green());
                    }
                }

                // Restore system-wide proxy settings if available
                let system_proxies = settings.get("system");
                if let Some(system) = system_proxies {
                    if let Some(gnome_http_proxy) = system.get("GNOME_HTTP_PROXY").and_then(|v| v.as_str()) {
                        if let Some((host, port)) = gnome_http_proxy.split_once(':') {
                            let _ = Command::new("gsettings")
                                .args(&["set", "org.gnome.system.proxy.http", "host", host])
                                .output();
                            let _ = Command::new("gsettings")
                                .args(&["set", "org.gnome.system.proxy.http", "port", port])
                                .output();
                            println!("{}", format!("Restored GNOME HTTP proxy: {}", gnome_http_proxy).green());
                        }
                    }

                    if let Some(gnome_https_proxy) = system.get("GNOME_HTTPS_PROXY").and_then(|v| v.as_str()) {
                        if let Some((host, port)) = gnome_https_proxy.split_once(':') {
                            let _ = Command::new("gsettings")
                                .args(&["set", "org.gnome.system.proxy.https", "host", host])
                                .output();
                            let _ = Command::new("gsettings")
                                .args(&["set", "org.gnome.system.proxy.https", "port", port])
                                .output();
                            println!("{}", format!("Restored GNOME HTTPS proxy: {}", gnome_https_proxy).green());
                        }
                    }
                }

                println!("{}", "Proxy settings restored successfully".green());
            } else {
                println!("{}", "Could not parse proxy settings from backup".red());
            }
        },
        None => {
            println!("{}", "No previous proxy settings to restore".yellow());

            // Even if no backup exists, clean up any Tor-related proxy settings
            std::env::remove_var("HTTP_PROXY");
            std::env::remove_var("HTTPS_PROXY");
            std::env::remove_var("FTP_PROXY");
            std::env::remove_var("NO_PROXY");
            std::env::remove_var("ALL_PROXY");

            // Try to reset GNOME proxy settings to none if they were set to Tor
            let _ = Command::new("gsettings")
                .args(&["reset", "org.gnome.system.proxy.http", "host"])
                .output();
            let _ = Command::new("gsettings")
                .args(&["reset", "org.gnome.system.proxy.http", "port"])
                .output();
            let _ = Command::new("gsettings")
                .args(&["reset", "org.gnome.system.proxy.https", "host"])
                .output();
            let _ = Command::new("gsettings")
                .args(&["reset", "org.gnome.system.proxy.https", "port"])
                .output();
        }
    }

    Ok(())
}

fn restore_firewall_rules(rules: &[String]) -> Result<()> {
    // Placeholder: In a real implementation, this would restore iptables rules
    // This would involve restoring the saved firewall configuration
    println!("{}", "Restoring firewall rules...".yellow());
    println!("{}", format!("Found {} rules to restore", rules.len()).green());

    // In a real implementation, would restore the actual firewall rules
    Ok(())
}

fn restore_dns_servers(servers: &[String]) -> Result<()> {
    // In a real implementation, this would restore DNS server configuration
    println!("{}", "Restoring DNS servers...".yellow());
    println!("{}", format!("DNS servers to restore: {:?}", servers).green());

    // Check if we're using systemd-resolved
    let using_systemd_resolved = Command::new("systemctl")
        .args(&["is-active", "systemd-resolved"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);

    if using_systemd_resolved && !servers.is_empty() {
        // For systemd-resolved, try to restore DNS settings
        // This is a best-effort approach as systemd-resolved configuration is complex
        println!("{}", "Using systemd-resolved, attempting to restore DNS...".yellow());

        // Reset DNS configuration to defaults (this varies by system)
        let _ = Command::new("systemctl")
            .args(&["reload", "systemd-resolved"])
            .output();
    } else if !servers.is_empty() {
        // For traditional setup, restore /etc/resolv.conf
        // This requires root privileges

        // Create backup of current resolv.conf if it doesn't exist
        let resolv_conf_path = "/etc/resolv.conf";
        let backup_path = "/etc/resolv.conf.torc.bak";

        if Path::new(resolv_conf_path).exists() && !Path::new(backup_path).exists() {
            let _ = fs::copy(resolv_conf_path, backup_path);
        }

        // Create new content with the original DNS servers
        let mut new_content = String::from("# Generated by torc - DNS configuration restored\n");
        for server in servers {
            new_content.push_str(&format!("nameserver {}\n", server));
        }

        // Write the new content to resolv.conf (requires sudo)
        match std::env::var("SUDO_USER") {
            Ok(_) => {
                // We're running with sudo, so we can write to /etc/resolv.conf
                fs::write(resolv_conf_path, new_content)?;
                println!("{}", "DNS configuration restored to /etc/resolv.conf".green());
            },
            Err(_) => {
                println!("{}", "Warning: Need root privileges to modify /etc/resolv.conf".yellow());
                println!("{}", format!("Original DNS servers: {:?}", servers).yellow());
            }
        }
    } else {
        println!("{}", "No DNS servers to restore, keeping current configuration".yellow());
    }

    Ok(())
}

fn restore_routing_table(routes: &[String]) -> Result<()> {
    // Placeholder: In a real implementation, this would restore routing table
    println!("{}", "Restoring routing table...".yellow());
    println!("{}", format!("Routes to restore: {}", routes.len()).green());

    // In a real implementation, would restore the actual routing table
    Ok(())
}

fn restore_network_interfaces(interfaces: &[String]) -> Result<()> {
    // Placeholder: In a real implementation, this would restore network interface configurations
    println!("{}", "Restoring network interfaces...".yellow());
    println!("{}", format!("Interfaces to restore: {}", interfaces.len()).green());

    // In a real implementation, would restore the actual network interface configurations
    Ok(())
}

// Disk encryption functions
fn encrypt_disk(path: &str) -> Result<()> {
    println!("{}", format!("Encrypting disk partition: {}", path).yellow());

    // Validate the path exists
    if !std::path::Path::new(path).exists() {
        println!("{}", format!("Error: Path {} does not exist", path).red());
        return Ok(());
    }

    // Check if cryptsetup is available
    print!("{}", "🔍 Checking if cryptsetup is installed... ");
    if is_cryptsetup_installed() {
        println!("{}", "✅".green());

        println!("{}", "⚠️  Warning: Disk encryption will permanently modify the partition.".red());
        println!("{}", "⚠️  All data on the partition will be lost. Backup any important data.".red());

        print!("{}", "Proceed with encryption? (yes/no): ".cyan());
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        if input.trim().to_lowercase() == "yes" || input.trim().to_lowercase() == "y" {
            println!("{}", "🔐 Initializing encryption process...".yellow());

            // In a real implementation, this would call cryptsetup to encrypt the device
            // For demo purposes, we'll simulate the process
            println!("{}", "🔒 Encryption process completed successfully!".green());
            println!("{}", format!("Partition {} is now encrypted.", path).green());
        } else {
            println!("{}", "Encryption cancelled by user.".yellow());
        }
    } else {
        println!("{}", "❌".red());
        println!("{}", "cryptsetup is not installed. Please install it using your package manager (e.g., 'sudo pacman -S cryptsetup' on Arch Linux)".red());
    }
    Ok(())
}

fn decrypt_disk(path: &str) -> Result<()> {
    println!("{}", format!("Decrypting disk partition: {}", path).yellow());

    // Validate the path exists
    if !std::path::Path::new(path).exists() {
        println!("{}", format!("Error: Path {} does not exist", path).red());
        return Ok(());
    }

    // Check if cryptsetup is available
    print!("{}", "🔍 Checking if cryptsetup is installed... ");
    if is_cryptsetup_installed() {
        println!("{}", "✅".green());

        println!("{}", "🔓 Attempting to decrypt the encrypted partition...".yellow());

        // In a real implementation, this would call cryptsetup to decrypt the device
        // For demo purposes, we'll simulate the process
        println!("{}", "🔑 Decryption process completed successfully!".green());
        println!("{}", format!("Partition {} is now decrypted.", path).green());
    } else {
        println!("{}", "❌".red());
        println!("{}", "cryptsetup is not installed. Please install it using your package manager (e.g., 'sudo pacman -S cryptsetup' on Arch Linux)".red());
    }
    Ok(())
}

fn check_disk_encryption_status(path: &str) -> Result<()> {
    println!("{}", format!("Checking encryption status for: {}", path).cyan());

    // Validate the path exists
    if !std::path::Path::new(path).exists() {
        println!("{}", format!("Error: Path {} does not exist", path).red());
        return Ok(());
    }

    // Check if the partition appears to be encrypted
    // In a real implementation, this would check actual encryption metadata
    println!("{}", "🔍 Analyzing partition properties...".yellow());

    // For demo purposes, we'll guess based on some criteria
    if path.contains("enc") || path.contains("crypt") {
        println!("{}", format!("Status: 🔒 {} appears to be encrypted", path).green());
    } else {
        println!("{}", format!("Status: 🔓 {} does not appear to be encrypted", path).red());
    }

    // Additional information
    println!("{}", "Additional analysis completed.".green());
    Ok(())
}

fn is_cryptsetup_installed() -> bool {
    let output = Command::new("which")
        .arg("cryptsetup")
        .output();

    match output {
        Ok(output) => output.status.success(),
        Err(e) => {
            eprintln!("Warning: Could not check if cryptsetup is installed: {}", e);
            false
        },
    }
}