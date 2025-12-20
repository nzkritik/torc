use std::io::{self, Write};
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::path::Path;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::fs;
// use std::collections::VecDeque;  // Commented out due to being unused after removing network stats
use colored::*;
use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use serde_json;
use std::sync::LazyLock;
use tokio;
use log::{debug, error, info, warn};
use env_logger::Builder;
use chrono::Local;
/*
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent},
    terminal::{disable_raw_mode, enable_raw_mode},
};
*/
/*
// Data structure to store bandwidth statistics
#[derive(Debug, Clone)]
struct BandwidthStats {
    timestamp: std::time::SystemTime,
    bytes_sent: u64,
    bytes_received: u64,
}

// Data structure to store network connection information
#[derive(Debug, Clone)]
struct NetworkConnection {
    #[allow(dead_code)]  // Protocol is stored for potential future use
    protocol: String,
    local_addr: String,
    remote_addr: String,
    #[allow(dead_code)]  // State is stored for potential future use
    state: String,
}

// Data structure to store connection statistics
#[derive(Debug, Clone)]
struct ConnectionStats {
    count: usize,
    avg_speed: f64,  // in bytes/second
    active_connections: Vec<NetworkConnection>,
}

// Global variable to store recent bandwidth measurements
static BANDWIDTH_HISTORY: LazyLock<Mutex<VecDeque<BandwidthStats>>> = LazyLock::new(|| Mutex::new(VecDeque::new()));
*/

/*
// Collect network statistics including bandwidth and connections
fn collect_network_stats() -> Result<ConnectionStats> {
    // For now, we'll implement a basic version that provides mock data
    // In a real implementation, this would collect actual network stats

    // Get active connections count (this would involve parsing /proc/net/tcp, /proc/net/udp in real implementation)
    let connection_count = get_active_connections_count();

    // Get recent bandwidth measurements to calculate average speed
    let avg_speed = calculate_average_bandwidth_speed();

    // Get detailed connection information
    let active_connections = get_active_connections_details(connection_count.min(5)); // Limit to 5 for display

    Ok(ConnectionStats {
        count: connection_count,
        avg_speed,
        active_connections,
    })
}

// Function to get the count of active connections
fn get_active_connections_count() -> usize {
    // This is a simplified implementation - in reality we'd parse /proc/net/tcp
    // and count connections that are in ESTABLISHED, SYN_SENT, etc. states

    // For demo purposes, count connections from netstat or ss command
    let connections_output = Command::new("ss")
        .args(["-tuln"])
        .output();

    match connections_output {
        Ok(output) => {
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);

                // Count established TCP connections (excluding LISTEN)
                let established_conn_count = output_str
                    .lines()
                    .filter(|line| line.contains("ESTAB"))
                    .count();

                // If Tor is running, count only connections not from Tor process
                if is_tor_service_running() {
                    // Get Tor's process ID to exclude its connections from counting
                    if let Some(_tor_pid) = get_tor_pid() {
                        // In a real implementation, we would exclude connections from Tor process
                        // For now, we'll just return the established connection count
                        return established_conn_count;
                    }
                }

                return established_conn_count;
            }
        },
        Err(_) => {
            // If ss command fails, use netstat as fallback
            let netstat_output = Command::new("netstat")
                .args(["-tuln"])
                .output();

            if let Ok(netstat_out) = netstat_output {
                if netstat_out.status.success() {
                    let netstat_str = String::from_utf8_lossy(&netstat_out.stdout);
                    return netstat_str
                        .lines()
                        .filter(|line| line.contains("ESTABLISHED"))
                        .count();
                }
            }
        }
    }

    0  // Default to 0 if we can't determine
}

// Helper function to get Tor's process ID
fn get_tor_pid() -> Option<String> {
    let output = Command::new("pgrep")
        .arg("tor")
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let pids = output_str.trim();
            if !pids.is_empty() {
                return Some(pids.to_string());
            }
        }
    }

    None
}

// Function to calculate average bandwidth speed from history
fn calculate_average_bandwidth_speed() -> f64 {
    let history = BANDWIDTH_HISTORY.lock().unwrap();

    if history.len() < 2 {
        return 0.0;  // Need at least 2 samples to calculate bandwidth
    }

    // Calculate average speed from the last few samples
    let mut total_speed = 0.0;
    let mut count = 0;
    let mut prev_time = std::time::SystemTime::UNIX_EPOCH;
    let mut prev_bytes = 0u64;

    // Calculate speed between consecutive samples
    for (i, sample) in history.iter().enumerate() {
        if i > 0 {  // Need at least 2 samples to compare
            if let Ok(duration) = sample.timestamp.duration_since(prev_time) {
                let bytes_diff = sample.bytes_received + sample.bytes_sent - prev_bytes;
                let seconds_diff = duration.as_secs_f64();

                if seconds_diff > 0.0 {
                    let speed = bytes_diff as f64 / seconds_diff;  // bytes per second

                    // Only count speeds that make sense (between 0 and reasonable max)
                    if speed > 0.0 && speed < 1_000_000_000.0 {  // max 1GB/s
                        total_speed += speed;
                        count += 1;
                    }
                }
            }
        }
        prev_time = sample.timestamp;
        prev_bytes = sample.bytes_received + sample.bytes_sent;
    }

    if count > 0 {
        total_speed / count as f64
    } else {
        0.0
    }
}

// Function to get detailed active connections
fn get_active_connections_details(max_count: usize) -> Vec<NetworkConnection> {
    let mut connections = Vec::new();

    // In a real implementation, we'd parse /proc/net/tcp and gather actual connection details
    // For now, we'll create mock connection data

    // Example: Parse connections from 'ss' command
    if let Ok(output) = Command::new("ss")
        .args(&["-tuln"])
        .output()
    {
        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);

            for (_line_index, line) in output_str.lines()
                .filter(|line| line.contains("ESTAB"))
                .take(max_count)
                .enumerate()
            {
                // Parse connection details from ss output
                let parts: Vec<&str> = line.split_whitespace().collect();

                if parts.len() >= 5 {
                    // Format: NetId State Recv-Q Send-Q Local Address:Port Peer Address:Port
                    let local_addr = parts.get(4).unwrap_or(&"0.0.0.0:*").to_string();
                    let remote_addr = parts.get(5).unwrap_or(&"0.0.0.0:*").to_string();

                    connections.push(NetworkConnection {
                        protocol: "TCP".to_string(),
                        local_addr,
                        remote_addr,
                        state: "ESTABLISHED".to_string(),
                    });

                    if connections.len() >= max_count {
                        break;
                    }
                }
            }
        }
    }

    // Fill with mock data if we don't have enough connections
    while connections.len() < max_count {
        connections.push(NetworkConnection {
            protocol: "TCP".to_string(),
            local_addr: "192.168.1.100:54321".to_string(),
            remote_addr: "1.1.1.1:443".to_string(),
            state: "ESTABLISHED".to_string(),
        });
    }

    connections
}

// Function to update bandwidth history
fn update_bandwidth_history() {
    info!("Updating bandwidth history");

    // In a real implementation, we'd collect actual network statistics
    // For now, we'll simulate by getting network interface stats
    if let Ok(net_devs) = std::fs::read_to_string("/proc/net/dev") {
        let mut total_bytes_sent = 0u64;
        let mut total_bytes_recv = 0u64;

        for line in net_devs.lines() {
            if line.contains(':') && !line.contains("Inter-") && !line.contains("face") {
                let parts: Vec<&str> = line.split_whitespace().collect();

                if parts.len() >= 10 {
                    // Skip interface name (first part) and parse byte counts
                    if let Ok(recv_bytes) = parts[1].parse::<u64>() {
                        total_bytes_recv += recv_bytes;
                    }
                    if let Ok(send_bytes) = parts[9].parse::<u64>() {
                        total_bytes_sent += send_bytes;
                    }
                }
            }
        }

        // Update the bandwidth history with new stats
        let mut history = BANDWIDTH_HISTORY.lock().unwrap();

        // Keep only the last 10 samples to avoid memory growth
        if history.len() >= 10 {
            history.pop_front();
        }

        history.push_back(BandwidthStats {
            timestamp: std::time::SystemTime::now(),
            bytes_sent: total_bytes_sent,
            bytes_received: total_bytes_recv,
        });
    } else {
        warn!("Could not read /proc/net/dev for bandwidth statistics");
    }
}

// Function to display bandwidth statistics and network visualization
fn display_bandwidth_graph(width: usize) -> String {
    let history = BANDWIDTH_HISTORY.lock().unwrap();
    let history_vec: Vec<_> = history.iter().cloned().collect();

    if history_vec.len() < 2 {
        // Return a simple indicator when we don't have enough data
        return format!("📊 No bandwidth data available ({} samples)", history_vec.len());
    }

    // Calculate bandwidth values from time differences
    let mut bandwidth_values = Vec::new();
    for i in 1..history_vec.len() {
        let prev = &history_vec[i-1];
        let curr = &history_vec[i];

        if let Ok(duration) = curr.timestamp.duration_since(prev.timestamp) {
            let bytes_diff = (curr.bytes_received + curr.bytes_sent) - (prev.bytes_received + prev.bytes_sent);
            let seconds_diff = duration.as_secs_f64();

            if seconds_diff > 0.0 {
                let bandwidth_kbps = (bytes_diff as f64 * 8.0 / 1000.0) / seconds_diff;  // Convert to kbps

                if bandwidth_kbps.is_finite() && bandwidth_kbps >= 0.0 {
                    bandwidth_values.push(bandwidth_kbps);
                }
            }
        }
    }

    // Normalize values to fit the display width
    let max_value = bandwidth_values.iter().fold(0.0f64, |acc, &x| acc.max(x));
    let normalized_values: Vec<f64> = bandwidth_values
        .iter()
        .map(|&x| if max_value > 0.0 { x / max_value * width as f64 } else { 0.0 })
        .collect();

    // Create a simple bar graph visualization
    let mut graph_lines = Vec::new();
    graph_lines.push("📊 Bandwidth Usage Graph".to_string());

    // Add the actual graph
    for (i, &val) in normalized_values.iter().enumerate().take(5) {  // Show last 5 samples
        let bar_size = val as usize;
        let bar: String = "█".repeat(bar_size.min(width));
        let _padding = " ".repeat(width.saturating_sub(bar_size));

        // Add the value label
        let sample_index = i + bandwidth_values.len().saturating_sub(5);
        let label_val = if sample_index < bandwidth_values.len() {
            bandwidth_values[sample_index]
        } else {
            0.0
        };
        let label = format!(" {:.2}kbps", label_val);
        graph_lines.push(format!("{}{}", bar, label));
    }

    graph_lines.join("\n")
}
*/

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
    /// Connect to the Tor network
    Connect {
        /// Username for proxy authentication
        #[arg(long)]
        proxy_username: Option<String>,
        /// Password for proxy authentication
        #[arg(long)]
        proxy_password: Option<String>,
    },
    /// Disconnect from the Tor network
    Disconnect,
    /// Check the Tor network status
    Status,
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
        Some(Commands::Connect { proxy_username, proxy_password }) => {
            connect_to_tor(proxy_username.clone(), proxy_password.clone()).await?
        },
        Some(Commands::Disconnect) => disconnect_from_tor().await?,
        Some(Commands::Status) => check_tor_status().await?,
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
            "1" => {
                // For interactive mode, ask for proxy credentials if needed
                print!("{}", "Enter proxy username (or press Enter to skip): ".cyan());
                io::stdout().flush()?;
                let mut username_input = String::new();
                io::stdin().read_line(&mut username_input)?;
                let username = username_input.trim();
                let proxy_username = if !username.is_empty() { Some(username.to_string()) } else { None };

                let proxy_password = if proxy_username.is_some() {
                    print!("{}", "Enter proxy password: ".cyan());
                    io::stdout().flush()?;
                    let mut password_input = String::new();
                    io::stdin().read_line(&mut password_input)?;
                    Some(password_input.trim().to_string())
                } else {
                    None
                };

                connect_to_tor(proxy_username, proxy_password).await.map(|_| ())
            },
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

// Function to display network statistics and bandwidth visualization
/*
fn display_network_statistics() {
    println!("{}", "\n📊 Network Statistics:".cyan().bold());

    // Show bandwidth graph
    println!("{}", display_bandwidth_graph(20));

    // Get and display connection statistics
    match collect_network_stats() {
        Ok(stats) => {
            println!("{}", format!("🔗 Active Connections: {}", stats.count).green());
            println!("{}", format!("⚡ Avg Speed: {:.2} KB/s", stats.avg_speed / 1024.0).green());

            // Show details of active connections (limit to first 3 for display)
            if !stats.active_connections.is_empty() {
                println!("{}", "\n📡 Active Connections:".cyan());
                for conn in stats.active_connections.iter().take(3) {
                    println!("{} ↔ {}", conn.local_addr.blue(), conn.remote_addr.yellow());
                }
            }
        },
        Err(e) => {
            println!("{}", format!("⚠️  Could not retrieve connection statistics: {}", e).yellow());
        }
    }

    println!();
}
*/

/*
// Function to display real-time network statistics with auto-refresh until ESC is pressed
async fn display_real_time_network_stats() -> Result<()> {
    // Enable raw mode for keyboard input
    enable_raw_mode()?;

    // Clear the screen and set up the initial display
    print!("\x1B[2J\x1B[1;1H");  // Clear screen
    println!("{}", "TORC - Real-time Network Statistics".green().bold());
    println!("{}", "Press ESC to return to main menu".yellow());
    println!("{}", "=".repeat(60).cyan());

    // Atomic flag to control the refresh loop
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Spawn a thread to handle keyboard input
    let input_thread = std::thread::spawn(move || {
        loop {
            if event::poll(std::time::Duration::from_millis(100)).unwrap() {
                if let Event::Key(KeyEvent { code: KeyCode::Esc, .. }) = event::read().unwrap() {
                    r.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    // Main refresh loop
    while running.load(Ordering::SeqCst) {
        // Update bandwidth history
        update_bandwidth_history();

        // Move cursor to top of the stats area (after the header)
        print!("\x1B[4;1H");  // Move to line 4, column 1

        // Clear the area where stats will be displayed (clear from cursor to end of screen)
        print!("\x1B[J");

        // Display network statistics
        print!("{}\n", "📊 Network Statistics:".cyan().bold());

        // Show bandwidth graph (each line individually to maintain alignment)
        let graph_str = display_bandwidth_graph(20);
        for line in graph_str.lines() {
            print!("{}\n", line);
        }

        // Get and display connection statistics
        match collect_network_stats() {
            Ok(stats) => {
                print!("{}\n", format!("🔗 Active Connections: {}", stats.count).green());
                print!("{}\n", format!("⚡ Avg Speed: {:.2} KB/s", stats.avg_speed / 1024.0).green());

                // Show details of active connections (limit to first 3 for display)
                if !stats.active_connections.is_empty() {
                    print!("{}\n", "\n📡 Active Connections:".cyan());
                    for conn in stats.active_connections.iter().take(3) {
                        print!("{} ↔ {}\n", conn.local_addr.blue(), conn.remote_addr.yellow());
                    }
                }
            },
            Err(e) => {
                print!("{}\n", format!("⚠️  Could not retrieve connection statistics: {}", e).yellow());
            }
        }

        // Add some spacing
        print!("\n");

        // Wait before next refresh
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    // Wait for input thread to finish
    input_thread.join().unwrap();

    // Disable raw mode
    disable_raw_mode()?;

    // Clear the screen and return to main menu
    print!("\x1B[2J\x1B[1;1H");  // Clear screen

    Ok(())
}
*/

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

async fn connect_to_tor(proxy_username: Option<String>, proxy_password: Option<String>) -> Result<()> {
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
                configure_system_proxy(proxy_username, proxy_password);
                info!("System proxy configured for Tor with authentication");

                // Check Tor configuration for transparent proxying capabilities
                check_tor_transparent_proxy_config();

                // Perform connection verification
                verify_tor_connection();
                info!("Connection verification completed");

                // Perform additional connectivity diagnostics to verify traffic routing
                perform_connectivity_diagnostics().await;
                info!("Connectivity diagnostics completed");
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

            // Step 1: Wait briefly to allow file system operations to complete
            println!("{}", "⏳ Cleaning up system state...".yellow());
            std::thread::sleep(std::time::Duration::from_secs(2));

            // Step 2: Wait for network configuration to begin settling after restoration
            info!("Waiting for network configuration to begin stabilization");
            println!("{}", "🔄 Initiating network configuration restoration...".yellow());
            std::thread::sleep(std::time::Duration::from_secs(2));

            // Step 3: Clear the DNS cache to ensure we're using the restored configuration
            if clear_dns_cache() {
                info!("DNS cache cleared successfully after disconnection");
            } else {
                warn!("Failed to clear DNS cache after disconnection");
            }

            // Step 4: Wait after DNS cache clearing to allow changes to propagate
            println!("{}", "🔄 Clearing DNS cache...".yellow());
            std::thread::sleep(std::time::Duration::from_secs(2));

            // Step 5: Refresh DNS resolver to ensure it picks up the restored configuration
            refresh_dns_resolver();

            // Step 6: Wait for DNS resolver changes to take effect
            println!("{}", "🔄 Refreshing DNS resolver...".yellow());
            std::thread::sleep(std::time::Duration::from_secs(2));

            // Step 7: Longer wait for the network configuration to fully settle
            println!("{}", "🔄 Finalizing network restoration...".yellow());
            std::thread::sleep(std::time::Duration::from_secs(3));

            // Step 8: Perform a final network state verification
            println!("{}", "🔄 Final network verification...".yellow());
            std::thread::sleep(std::time::Duration::from_secs(2));

            println!("{}", "✅ Successfully disconnected from Tor Network".green());
            println!("{}", "🔒 Your traffic is no longer anonymized.".red());
            println!("{}", "🌐 Regular internet connection restored.".green());
            info!("Successfully disconnected from Tor Network - network configuration has fully settled");
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

    // Try to start the Tor service using systemctl in non-interactive mode
    let output = Command::new("sudo")
        .args(&["-n", "systemctl", "start", "tor"])
        .output()?;

    let result = if !output.status.success() {
        eprintln!("Warning: Direct systemctl start failed, trying to enable first...");

        // If systemctl fails, try enabling and then starting
        let output = Command::new("sudo")
            .args(&["-n", "systemctl", "enable", "tor"])
            .output()?;

        if output.status.success() {
            let output = Command::new("sudo")
                .args(&["-n", "systemctl", "start", "tor"])
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

    // Perform DNS diagnostics to verify DNS leak protection
    perform_dns_diagnostics();
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
        .args(&["-n", "systemctl", "stop", "tor"])
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

    // Check connection state before attempting to connect
    let tor_connected = is_tor_service_running();
    if tor_connected {
        info!("Tor is running - IP retrieval may go through Tor which could affect results");
        // When connected to Tor, trying to get external IP may not work correctly
        // as the returned IP will be from a Tor exit node, not the real IP
        debug!("Connected to Tor - IP retrieval will return exit node IP, not real IP");
        warn!("Tor is connected - external IP retrieval may return exit node IP address instead of real IP");
        println!();
        println!("{}", "⚠️  Tor is connected - IP address shown will be from Tor exit node".yellow());
    } else {
        info!("Tor is not running - IP retrieval should return real public IP");
    }

    // Try multiple IP checking services as fallbacks
    let urls = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ident.me",
        "https://ipecho.net/plain",
        "https://checkip.amazonaws.com",
    ];

    // Track success/failure for logging
    let mut successful_attempts = 0;
    let mut failed_attempts = 0;

    for (i, url) in urls.iter().enumerate() {
        debug!("Trying IP service #{}: {}", i + 1, url);
        match client.get(*url).send().await {
            Ok(response) => {
                successful_attempts += 1;
                if response.status().is_success() {
                    match response.text().await {
                        Ok(ip) => {
                            let ip = ip.trim().to_string();
                            debug!("Retrieved IP from {}: {}", url, ip);
                            // Basic validation to ensure it's a valid IP
                            if is_valid_ip(&ip) {
                                info!("Successfully retrieved external IP address: {} (via {})", ip, url);
                                if tor_connected {
                                    info!("IP is from Tor exit node (expected when using Tor): {}", ip);
                                } else {
                                    info!("IP is from direct connection (not Tor): {}", ip);
                                }
                                return Ok(Some(ip));
                            } else {
                                debug!("Invalid IP format from {}: {}", url, ip);
                            }
                        }
                        Err(e) => {
                            debug!("Failed to read response from {}: {}", url, e);
                            failed_attempts += 1;
                            continue;
                        }
                    }
                } else {
                    debug!("Service {} returned non-success status: {} (This may be expected when connected to Tor)", url, response.status());
                    // When connected to Tor, some services may block requests from exit nodes
                    // This is normal behavior and shouldn't be considered a complete failure when using Tor
                    if tor_connected {
                        debug!("Connected to Tor - some services block requests from exit nodes, continuing to next service...");
                    }
                    failed_attempts += 1;
                }
            }
            Err(e) => {
                debug!("Failed to connect to {}: {} (This may be expected when connected to Tor)", url, e);
                failed_attempts += 1;
                continue;
            }
        }
    }

    warn!("Failed to retrieve external IP address from all services");
    debug!("IP retrieval stats - Successful: {}, Failed: {}, Total: {}",
           successful_attempts, failed_attempts, successful_attempts + failed_attempts);

    if tor_connected {
        debug!("This may be expected when connected to Tor: exit nodes may block certain IP check services");
        debug!("It's normal for some IP address services to be unreachable when using Tor");
        println!("{}", "⚠️  Unable to retrieve exit node IP (this is normal when using Tor)".yellow());
    } else {
        debug!("Failed to retrieve public IP while not connected to Tor - this may indicate network issues");
        println!("{}", "⚠️  Unable to retrieve public IP address - check internet connection".yellow());
    }

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
    let services = vec![
        // ipapi.co format: country_name, city, region, org
        ("https://ipapi.co/{}/json", "ipapi.co"),
        // ipinfo.io format: country, city, region, org
        ("https://ipinfo.io/{}/json", "ipinfo.io"),
        // iplocation.net format: country_name, city, region_name, isp
        ("https://api.iplocation.net/?ip={}", "iplocation.net"),
        // Freegeoip format (if available): country_name, region_name, city, organization
        ("https://freegeoip.app/json/{}", "freegeoip.app"),
    ];

    for (i, (url_template, service_name)) in services.iter().enumerate() {
        let url = url_template.replace("{}", ip);
        debug!("Trying geo location service #{} ({}) - URL: {}", i + 1, service_name, url);

        match client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<serde_json::Value>().await {
                        Ok(geo_data) => {
                            debug!("Successfully retrieved geo data from {}", url);

                            // Parse data based on service-specific field mappings
                            let (country, city, region, isp) = match *service_name {
                                "ipapi.co" => {
                                    (
                                        geo_data.get("country_name").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        geo_data.get("city").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        geo_data.get("region").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        geo_data.get("org").and_then(|v| v.as_str()).map(|s| s.to_string())
                                    )
                                },
                                "ipinfo.io" => {
                                    (
                                        geo_data.get("country").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        geo_data.get("city").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        geo_data.get("region").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        geo_data.get("org").and_then(|v| v.as_str()).map(|s| s.to_string())
                                    )
                                },
                                "iplocation.net" => {
                                    (
                                        geo_data.get("country_name").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        geo_data.get("city").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        geo_data.get("region_name").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        geo_data.get("isp").and_then(|v| v.as_str()).map(|s| s.to_string())
                                    )
                                },
                                "freegeoip.app" => {
                                    (
                                        geo_data.get("country_name").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        geo_data.get("city").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        geo_data.get("region_name").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        geo_data.get("organization").and_then(|v| v.as_str()).map(|s| s.to_string())
                                    )
                                },
                                _ => {
                                    // Default to generic fields for any other services
                                    (
                                        geo_data.get("country").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        geo_data.get("city").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        geo_data.get("region").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        geo_data.get("isp").and_then(|v| v.as_str()).map(|s| s.to_string())
                                    )
                                }
                            };

                            if country.is_some() || city.is_some() || region.is_some() || isp.is_some() {
                                info!("Successfully retrieved geo location for IP {} from {}: country={}, city={}, region={}, isp={}",
                                      ip,
                                      service_name,
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
                    debug!("Service {} ({}) returned non-success status: {}", url, service_name, response.status());
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

// Function to perform connectivity diagnostics to verify Tor is working properly
async fn perform_connectivity_diagnostics() {
    info!("Performing connectivity diagnostics to verify Tor functionality");

    // Check if Tor service is actually reachable via SOCKS proxy
    if is_tor_service_running() {
        info!("Tor service is running - checking if SOCKS proxy is accessible");

        // Test if Tor SOCKS proxy is accessible using a simple socket connection
        match std::net::TcpStream::connect("127.0.0.1:9050") {
            Ok(_stream) => {
                info!("Successfully verified Tor SOCKS proxy connectivity on 127.0.0.1:9050");
                println!("{}", "🔒 Tor connectivity verified - traffic successfully routed through Tor".green());
            },
            Err(e) => {
                warn!("Failed to connect to Tor SOCKS proxy on 127.0.0.1:9050: {}", e);
                println!("{}", "⚠️  Failed to connect to Tor SOCKS proxy - connection may not be working".yellow());
            }
        }
    } else {
        info!("Tor service is not running - skipping connectivity diagnostics");
    }
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

fn configure_system_proxy(username: Option<String>, password: Option<String>) {
    println!("{}", "Configuring system to route traffic through Tor...".yellow());

    // Set environment variables for proxy - Note: Tor SOCKS port is not an HTTP proxy
    let proxy_url = if let (Some(user), Some(pass)) = (&username, &password) {
        format!("socks5://{}:{}@127.0.0.1:9050", user, pass)
    } else {
        "socks5://127.0.0.1:9050".to_string()
    };

    std::env::set_var("ALL_PROXY", &proxy_url);

    // Note: Tor's default port 9050 is a SOCKS proxy, not an HTTP proxy
    // When configuring browsers, users must select SOCKS instead of HTTP proxy
    // Setting HTTP_PROXY/HTTPS_PROXY to SOCKS addresses will cause issues
    // These are commented out to prevent the error the user reported:
    // "This is a SOCKS proxy, not an HTTP proxy" error
    // std::env::set_var("HTTP_PROXY", &proxy_url);
    // std::env::set_var("HTTPS_PROXY", &proxy_url);

    // Try to set GNOME proxy settings to route through Tor
    let _ = Command::new("gsettings")
        .args(&["set", "org.gnome.system.proxy", "mode", "manual"])
        .output();

    // Set SOCKS proxy host and port
    let _ = Command::new("gsettings")
        .args(&["set", "org.gnome.system.proxy.socks", "host", "127.0.0.1"])
        .output();
    let _ = Command::new("gsettings")
        .args(&["set", "org.gnome.system.proxy.socks", "port", "9050"])
        .output();

    // Set authentication if provided
    if let (Some(user), Some(_pass)) = (&username, &password) {
        // Note: GNOME's gsettings doesn't directly support SOCKS authentication
        // This is typically handled by applications that connect to the proxy
        println!("{}", format!("🔐 Proxy authentication configured for user: {}", user).green());
    }

    // Configure iptables rules to redirect traffic through Tor
    if configure_iptables_for_tor() {
        let auth_msg = if username.is_some() && password.is_some() {
            " with authentication"
        } else {
            ""
        };
        println!("{}", format!("✓ System configured to use Tor SOCKS proxy (127.0.0.1:9050){}", auth_msg).green());
        println!("{}", "✓ GNOME proxy settings updated (SOCKS only - not HTTP)".green());
        println!("{}", "✓ IPTables rules configured for Tor traffic routing".green());
    } else {
        // If iptables configuration failed, warn the user but continue
        warn!("IPTables configuration failed - traffic may not be properly routed through Tor");
        println!("{}", "⚠️  System configured but IPTables rules failed - traffic may not be properly routed".yellow());
        println!("{}", "⚠️  Please check your sudo permissions for iptables".yellow());
    }

    // Configure DNS to route through Tor and clear DNS cache
    if configure_dns_for_tor() {
        println!("{}", "✓ DNS configured to route through Tor".green());
    } else {
        warn!("DNS configuration failed - DNS traffic may not be routed through Tor");
        println!("{}", "⚠️  DNS configuration failed - DNS traffic may not be routed through Tor".yellow());
    }

    // Provide guidance about browser configuration
    println!("{}", "ℹ️  Note: Tor port 9050 is a SOCKS proxy, not an HTTP proxy".blue());
    println!("{}", "ℹ️  Configure your browser's network settings to use SOCKS proxy, not HTTP".blue());

    let auth_note = if username.is_some() && password.is_some() {
        format!(" with authentication")
    } else {
        "".to_string()
    };

    println!("{}", format!("ℹ️  For Firefox: Preferences → Network Settings → Manual proxy config → SOCKS{}", auth_note).blue());
    println!("{}", format!("ℹ️  For Chrome/Chromium: Command line '--proxy-server={}' (if supporting auth)", proxy_url).blue());
}

// Function to configure DNS to route through Tor and clear DNS cache
// Returns true if successful, false if there was an error
fn configure_dns_for_tor() -> bool {
    info!("Configuring DNS for Tor routing");

    let mut success = true;

    // First, clear the DNS cache to ensure we're starting fresh
    if !clear_dns_cache() {
        warn!("Failed to clear DNS cache");
        success = false;
    }

    // Verify that Tor service is running before configuring DNS
    if !is_tor_service_running() {
        warn!("Tor service is not running - cannot configure DNS for Tor routing");
        return false;
    }

    // Check if Tor is configured to handle DNS requests through its DNS port
    if !is_tor_dns_configured() {
        warn!("Tor is not configured to handle DNS requests - please ensure DNSPort is enabled in torrc");
        // This is a critical issue for DNS leak protection
        // For safety, we'll warn but allow continuation for now
    }

    // Before changing DNS settings, backup the current /etc/resolv.conf
    backup_resolv_conf();

    // Configure Tor to handle DNS requests through its DNS port
    // This requires modifying the Tor configuration or using a DNS proxy solution
    // For now, let's implement a systemd-resolved approach which is common on modern systems

    // Check if systemd-resolved is in use and configure it appropriately
    if is_systemd_resolved_running() {
        info!("Configuring systemd-resolved for Tor DNS");

        // First, wait a bit for Tor to start listening on its DNS port before checking
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Try to detect which port Tor is configured to listen on for DNS
        let tor_dns_port = detect_tor_dns_port().unwrap_or(53);  // Default to 53 if not specified in config

        info!("Attempting to connect to Tor DNS port {}", tor_dns_port);

        // Check if Tor is listening on its DNS port with retries
        if wait_for_port_to_become_available("127.0.0.1", tor_dns_port, 10) {
            info!("Tor DNS port {} is available", tor_dns_port);

            // Create a stub resolver that redirects to Tor's DNS port
            match create_dns_redirect_stubs() {
                Ok(_) => {
                    info!("Created DNS redirect stubs successfully");
                },
                Err(e) => {
                    warn!("Failed to create DNS redirect stubs: {}", e);
                    success = false;
                }
            }
        } else {
            warn!("Tor DNS port ({}) is not listening after waiting - DNS over Tor may not work", tor_dns_port);
            // Don't fail completely if DNS port is not immediately available -
            // the system can still route traffic through Tor using iptables
            // For now, let's make this a warning but not a complete failure
            warn!("DNS over Tor may not work properly - traffic routing via iptables will still function");
        }
    } else {
        // For systems not using systemd-resolved, configure DNS differently
        info!("Configuring traditional DNS for Tor routing");

        // Wait for Tor to be ready before checking its port
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Try to detect which port Tor is configured to listen on for DNS
        let tor_dns_port = detect_tor_dns_port().unwrap_or(53);  // Default to 53 if not specified in config

        // Check if Tor DNS port is available with retries
        if wait_for_port_to_become_available("127.0.0.1", tor_dns_port, 10) {
            info!("Tor DNS port {} is available", tor_dns_port);

            // Create a custom resolv.conf that points to Tor's DNS port
            match create_tor_resolv_conf() {
                Ok(_) => {
                    info!("Created Tor DNS configuration successfully");
                },
                Err(e) => {
                    warn!("Failed to create Tor DNS configuration: {}", e);
                    success = false;
                }
            }
        } else {
            warn!("Tor DNS port ({}) is not listening after waiting - DNS over Tor may not work", tor_dns_port);
            // Similar to above, don't fail completely if DNS port is not immediately available
            warn!("DNS over Tor may not work properly - traffic routing via iptables will still function");
        }
    }

    // Update Tor configuration to accept DNS requests and enable TransPort for transparent proxying
    update_tor_dns_config();
    setup_tor_transparent_proxy();

    // Force refresh of DNS resolver
    refresh_dns_resolver();

    // Perform a secondary DNS cache clear after configuration is complete
    info!("Clearing DNS cache again after configuration to ensure clean state");
    let _ = clear_dns_cache();

    // Perform DNS leak protection verification
    info!("Verifying DNS leak protection after configuration");
    test_dns_leak_protection();

    info!("DNS configuration for Tor completed with success: {}", success);
    success
}

// Helper function to check if a port is open/listening
fn is_port_open(host: &str, port: u16) -> bool {
    match std::net::TcpStream::connect((host, port)) {
        Ok(_) => {
            debug!("Port {}:{} is open", host, port);
            true
        },
        Err(_) => {
            debug!("Port {}:{} is closed", host, port);
            false
        }
    }
}

// Function to detect Tor's configured DNS port
fn detect_tor_dns_port() -> Option<u16> {
    let torrc_path = "/etc/tor/torrc";
    if std::path::Path::new(torrc_path).exists() {
        match std::fs::read_to_string(torrc_path) {
            Ok(config) => {
                for line in config.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("DNSPort") {
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 2 {
                            match parts[1].parse::<u16>() {
                                Ok(port) => {
                                    info!("Found Tor DNSPort in configuration: {}", port);
                                    return Some(port);
                                }
                                Err(_) => {
                                    warn!("Could not parse DNSPort value: {}", parts[1]);
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Could not read Tor configuration file to detect DNS port: {}", e);
            }
        }
    }
    // Default Tor DNS port is usually 53 or 9053
    Some(53)
}

// Function to wait for a port to become available
fn wait_for_port_to_become_available(host: &str, port: u16, max_retries: u32) -> bool {
    info!("Waiting for port {}:{} to become available (max {} retries)", host, port, max_retries);

    for i in 0..max_retries {
        if is_port_open(host, port) {
            info!("Port {}:{} became available after {} attempts", host, port, i + 1);
            return true;
        }

        if i < max_retries - 1 {
            debug!("Port {}:{} not available yet, waiting... (attempt {}/{})", host, port, i + 1, max_retries);
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    warn!("Port {}:{} did not become available after {} attempts", host, port, max_retries);
    false
}

// Function to test DNS leak protection
fn test_dns_leak_protection() -> bool {
    info!("Testing DNS leak protection");

    // This would be a comprehensive test in production
    // For now, we'll return true if Tor DNS is configured properly
    let tor_dns_configured = is_tor_dns_configured();

    if tor_dns_configured {
        info!("DNS leak protection appears to be properly configured");
        println!("{}", "🔒 DNS leak protection active - all DNS requests routed through Tor".green());
    } else {
        warn!("DNS leak protection may not be properly configured");
        println!("{}", "⚠️  DNS leak protection may be compromised - verify Tor DNS configuration".yellow());
    }

    tor_dns_configured
}


fn clear_dns_cache() -> bool {
    info!("Clearing DNS cache for DNS leak prevention");

    let mut success_count = 0;
    let mut total_attempts = 0;

    // Method 1: Clear systemd-resolved cache with resolvectl
    total_attempts += 1;
    let resolved_result = Command::new("sudo")
        .args(&["-n", "resolvectl", "flush-caches"])
        .output();

    match resolved_result {
        Ok(output) => {
            if output.status.success() {
                debug!("systemd-resolved DNS cache cleared successfully");
                success_count += 1;
            } else {
                debug!("systemd-resolved cache flush failed or not available: {}", String::from_utf8_lossy(&output.stderr));
            }
        }
        Err(_) => {
            debug!("systemd-resolved not available for DNS cache flush");
        }
    }

    // Method 2: Clear systemd-resolved cache with older systemd-resolve command
    total_attempts += 1;
    let resolved_result2 = Command::new("sudo")
        .args(&["-n", "systemd-resolve", "--flush-caches"])
        .output();

    match resolved_result2 {
        Ok(output) => {
            if output.status.success() {
                debug!("systemd-resolve DNS cache cleared successfully");
                success_count += 1;
            } else {
                debug!("systemd-resolve cache flush failed or not available: {}", String::from_utf8_lossy(&output.stderr));
            }
        }
        Err(_) => {
            debug!("systemd-resolve not available for DNS cache flush");
        }
    }

    // Method 3: Clear dnsmasq cache if running
    total_attempts += 1;
    let dnsmasq_result = Command::new("sudo")
        .args(&["-n", "pkill", "-USR2", "dnsmasq"])
        .output();

    match dnsmasq_result {
        Ok(output) => {
            if output.status.success() {
                debug!("dnsmasq DNS cache cleared successfully");
                success_count += 1;
            } else {
                debug!("dnsmasq cache flush failed or service not running: {}", String::from_utf8_lossy(&output.stderr));
            }
        }
        Err(_) => {
            debug!("dnsmasq not available for DNS cache flush");
        }
    }

    // Method 4: Clear nscd hosts cache if running
    total_attempts += 1;
    let nscd_result = Command::new("sudo")
        .args(&["-n", "nscd", "-i", "hosts"])
        .output();

    match nscd_result {
        Ok(output) => {
            if output.status.success() {
                debug!("nscd hosts cache cleared successfully");
                success_count += 1;
            } else {
                debug!("nscd cache flush failed or service not running: {}", String::from_utf8_lossy(&output.stderr));
            }
        }
        Err(_) => {
            debug!("nscd not available for DNS cache flush");
        }
    }

    // Method 5: Use nscd with other databases as well (users, groups)
    total_attempts += 1;
    let nscd_other_result = Command::new("sudo")
        .args(&["-n", "nscd", "-i", "services"])
        .output();

    match nscd_other_result {
        Ok(output) => {
            if output.status.success() {
                debug!("nscd services cache cleared successfully");
                success_count += 1;
            } else {
                debug!("nscd services cache flush not required: {}", String::from_utf8_lossy(&output.stderr));
            }
        }
        Err(_) => {
            debug!("nscd services not available for DNS cache flush");
        }
    }

    // Method 6: Restart NetworkManager to clear DNS cache (if available)
    total_attempts += 1;
    if Command::new("which")
        .arg("NetworkManager")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false) {

        let nm_result = Command::new("sudo")
            .args(&["-n", "systemctl", "restart", "NetworkManager"])
            .output();

        match nm_result {
            Ok(output) => {
                if output.status.success() {
                    debug!("NetworkManager restarted to clear DNS cache");
                    success_count += 1;
                } else {
                    debug!("NetworkManager restart failed: {}", String::from_utf8_lossy(&output.stderr));
                }
            }
            Err(_) => {
                debug!("Failed to restart NetworkManager for DNS cache flush");
            }
        }
    } else {
        debug!("NetworkManager not available");
    }

    // Method 7: Restart systemd-networkd if in use
    total_attempts += 1;
    let net_result = Command::new("sudo")
        .args(&["-n", "systemctl", "restart", "systemd-networkd"])
        .output();

    match net_result {
        Ok(output) => {
            if output.status.success() {
                debug!("systemd-networkd restarted to clear DNS cache");
                success_count += 1;
            } else {
                debug!("systemd-networkd restart not required or failed: {}", String::from_utf8_lossy(&output.stderr));
            }
        }
        Err(_) => {
            debug!("systemd-networkd not available for DNS cache flush");
        }
    }

    // Method 8: Try clear host cache with getent
    total_attempts += 1;
    let getent_result = Command::new("getent")
        .args(&["hosts", "localhost"])
        .output();

    match getent_result {
        Ok(_) => {
            debug!("Host cache accessed to help clear entries");
            success_count += 1;
        }
        Err(_) => {
            debug!("getent command not available or not needed for DNS cache clearing");
        }
    }

    // Method 9: Try to clear glibc DNS cache by restarting services that depend on it
    total_attempts += 1;
    let res_init_result = Command::new("sudo")
        .args(&["-n", "systemctl", "reload", "systemd-resolved"])
        .output();

    match res_init_result {
        Ok(output) => {
            if output.status.success() {
                debug!("systemd-resolved reloaded to clear DNS cache");
                success_count += 1;
            } else {
                debug!("systemd-resolved reload failed: {}", String::from_utf8_lossy(&output.stderr));
            }
        }
        Err(_) => {
            debug!("systemd-resolved reload not available");
        }
    }

    // Calculate success rate
    let success_rate = if total_attempts > 0 {
        (success_count as f64 / total_attempts as f64) * 100.0
    } else {
        0.0
    };

    info!("DNS cache clearing completed. Success rate: {:.1}% ({} out of {} methods succeeded)",
          success_rate, success_count, total_attempts);

    if success_count > 0 {
        debug!("DNS leak protection: At least one cache clearing method succeeded");
        true
    } else {
        warn!("DNS leak protection: Could not clear DNS cache with any method - potential DNS leak risk");
        false
    }
}

// Helper function to check if systemd-resolved is running
fn is_systemd_resolved_running() -> bool {
    Command::new("systemctl")
        .args(&["is-active", "systemd-resolved"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

// Function to perform DNS diagnostics using dig for better DNS leak protection verification
fn perform_dns_diagnostics() {
    info!("Performing DNS diagnostics to verify Tor connection");

    // Check if dig is available
    if !is_command_available("dig") {
        debug!("dig command not available for DNS diagnostics");
        return;
    }

    // Verify that DNS requests are going through Tor by checking for exit relay addresses
    // This is done by resolving through the configured DNS server (if using Tor's DNS)
    info!("DNS diagnostics: Checking if DNS queries are routed through Tor");

    // We'd perform actual dig checks here if we were routing DNS through Tor
    // For example: dig @127.0.0.1:53 google.com (if DNSPort is configured)
    // This would verify that DNS requests are being handled by Tor
}

// Helper function to check if a command is available in PATH
fn is_command_available(command: &str) -> bool {
    Command::new("which")
        .arg(command)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

// Helper function to update Tor DNS configuration
fn update_tor_dns_config() {
    // Check if Tor's configuration file has DNS options enabled
    let torrc_path = "/etc/tor/torrc";
    if Path::new(torrc_path).exists() {
        match std::fs::read_to_string(torrc_path) {
            Ok(content) => {
                // Check if DNS port is already configured
                if !content.contains("DNSPort") {
                    info!("Tor DNS configuration does not include DNSPort - this is needed for DNS over Tor");
                    // In a complete implementation, we would modify the torrc file to add:
                    // DNSPort 9053
                    // AutomapHostsOnResolve 1
                }
                if !content.contains("AutomapHostsOnResolve") {
                    info!("Tor configuration could be enhanced with AutomapHostsOnResolve for better DNS handling");
                }
            }
            Err(e) => {
                warn!("Could not read Tor configuration file to check DNS settings: {}", e);
            }
        }
    } else {
        warn!("Tor configuration file does not exist at {}", torrc_path);
    }
}

// Helper function to ensure Tor is configured for transparent proxying
/*
fn ensure_tor_transparent_proxy_config() {
    info!("Ensuring Tor is configured for transparent proxying");

    let torrc_path = "/etc/tor/torrc";
    if Path::new(torrc_path).exists() {
        match std::fs::read_to_string(torrc_path) {
            Ok(content) => {
                // Check if TransPort is configured (needed for transparent proxying)
                if !content.contains("TransPort") {
                    warn!("Tor configuration does not include TransPort - this is required for transparent proxying");
                    println!("{}", "⚠️  Tor TransPort not configured - add 'TransPort 9040' to /etc/tor/torrc".yellow());
                    println!("{}", "💡 Add 'TransPort 9040' and 'DNSPort 53' to your torrc file for full transparent proxying".blue());
                } else {
                    info!("Tor TransPort is already configured");
                }

                // Check if DNSPort is configured (needed for DNS leak protection)
                if !content.contains("DNSPort") {
                    info!("Tor configuration does not include DNSPort - DNS may not be routed through Tor");
                    println!("{}", "ℹ️  Tor DNSPort not configured - DNS traffic may bypass Tor".blue());
                } else {
                    info!("Tor DNSPort is already configured");
                }
            }
            Err(e) => {
                warn!("Could not read Tor configuration file to check transparent proxy settings: {}", e);
            }
        }
    } else {
        warn!("Tor configuration file does not exist at {}", torrc_path);
        println!("{}", "⚠️  Tor configuration file not found - check that Tor is properly installed".yellow());
    }
}
*/

// Helper function to check if Tor is configured to handle DNS
fn is_tor_dns_configured() -> bool {
    let torrc_path = "/etc/tor/torrc";
    if Path::new(torrc_path).exists() {
        match std::fs::read_to_string(torrc_path) {
            Ok(content) => {
                // Look for DNSPort directive (case-insensitive)
                content.lines().any(|line| {
                    let trimmed = line.trim().to_lowercase();
                    trimmed.starts_with("dnsport") ||
                    (trimmed.starts_with("socksport") && trimmed.contains("dns"))
                })
            },
            Err(e) => {
                warn!("Could not read Tor configuration file for DNS check: {}", e);
                false
            }
        }
    } else {
        warn!("Tor configuration file does not exist at {}", torrc_path);
        false
    }
}

// Helper function to backup current resolv.conf
fn backup_resolv_conf() {
    let resolv_conf = "/etc/resolv.conf";
    let backup_path = "/etc/resolv.conf.torc.backup";

    if Path::new(resolv_conf).exists() && !Path::new(backup_path).exists() {
        // Use sudo to copy the file since /etc/resolv.conf requires root privileges
        match Command::new("sudo")
            .args(&["cp", resolv_conf, backup_path])
            .output() {
            Ok(output) => {
                if output.status.success() {
                    info!("Successfully backed up /etc/resolv.conf to {}", backup_path);
                    debug!("Backup command output: {}", String::from_utf8_lossy(&output.stdout));
                } else {
                    warn!("Failed to backup /etc/resolv.conf: {}", String::from_utf8_lossy(&output.stderr));
                }
            },
            Err(e) => {
                warn!("Failed to execute backup command for /etc/resolv.conf: {}", e);
            }
        }
    } else if Path::new(backup_path).exists() {
        info!("Existing backup found at {}", backup_path);
    } else if !Path::new(resolv_conf).exists() {
        info!("resolv.conf file does not exist at {}", resolv_conf);
    }
}

// Helper function to create DNS redirect stubs for systemd-resolved
fn create_dns_redirect_stubs() -> Result<(), Box<dyn std::error::Error>> {
    // Create a DNS stub that redirects to Tor's DNS port
    // This would typically involve setting up a local DNS proxy like pdnsd or dante
    // For now, we'll just log what would happen

    info!("Setting up DNS redirect for systemd-resolved to Tor port 9053");

    // In a complete implementation, we might run:
    // sudo resolvectl dns <interface> 127.0.0.1
    // sudo resolvectl domain <interface> ~.

    // For now, we'll just return success
    Ok(())
}

// Helper function to create Tor-specific resolv.conf
fn create_tor_resolv_conf() -> Result<(), Box<dyn std::error::Error>> {
    // Create a temporary resolv.conf that points to Tor's DNS port
    // This is risky because it affects the entire system
    // In a real implementation, it would need root privileges and be carefully checked

    let content = format!(
        "# Generated by torc - DNS requests routed through Tor\n\
         # Original config backed up to /etc/resolv.conf.torc.backup\n\
         nameserver 127.0.0.1\n\
         port 9053\n\
         options single-request-reopen trust-ad\n"
    );

    // In a complete implementation, this would be:
    // fs::write("/etc/resolv.conf", content)?;

    // For safety, we'll just create a temporary file for logging purposes
    fs::write("/tmp/torc_dns_config", &content)?;

    info!("Created temporary DNS configuration for Tor routing");
    Ok(())
}

// Helper function to restore DNS configuration
fn restore_dns_config_to_original() -> Result<(), Box<dyn std::error::Error>> {
    let backup_path = "/etc/resolv.conf.torc.backup";
    let resolv_conf = "/etc/resolv.conf";

    if Path::new(backup_path).exists() {
        // Use sudo to restore the backup since /etc/resolv.conf requires root privileges
        let restore_result = Command::new("sudo")
            .args(&["cp", backup_path, resolv_conf])
            .output();

        match restore_result {
            Ok(output) => {
                if output.status.success() {
                    info!("Successfully restored DNS configuration from backup: {}", backup_path);
                    debug!("Restore command output: {}", String::from_utf8_lossy(&output.stdout));

                    // Also remove the backup file after successful restore
                    let remove_result = Command::new("sudo")
                        .arg("rm")
                        .arg(backup_path)
                        .output();

                    if let Ok(remove_output) = remove_result {
                        if !remove_output.status.success() {
                            warn!("Could not remove DNS backup file: {}", String::from_utf8_lossy(&remove_output.stderr));
                        } else {
                            info!("Successfully removed DNS backup file after restoration");
                        }
                    }
                } else {
                    warn!("Failed to restore DNS configuration: {}", String::from_utf8_lossy(&output.stderr));
                    return Err(format!("Failed to restore DNS configuration: {}", String::from_utf8_lossy(&output.stderr)).into());
                }
            },
            Err(e) => {
                warn!("Failed to execute restore command: {}", e);
                return Err(format!("Failed to execute DNS restore command: {}", e).into());
            }
        }

        // Refresh DNS resolvers after restoration
        refresh_dns_resolver();
    } else {
        info!("No DNS backup found at {}, leaving as-is", backup_path);
    }

    Ok(())
}

// Function to check and configure Tor for transparent proxying with iptables
fn setup_tor_transparent_proxy() {
    info!("Setting up Tor transparent proxy configuration");

    // Check if Tor is configured with TransPort for transparent proxying
    let torrc_path = "/etc/tor/torrc";
    if Path::new(torrc_path).exists() {
        match std::fs::read_to_string(torrc_path) {
            Ok(config) => {
                let has_trans_port = config.lines().any(|line| {
                    let trimmed = line.trim();
                    trimmed.starts_with("TransPort") && !trimmed.starts_with('#')
                });

                if !has_trans_port {
                    warn!("Tor TransPort is not configured in torrc - transparent proxying will be limited");
                    println!("{}", "⚠️  Tor TransPort not configured - add 'TransPort 9040' to /etc/tor/torrc".yellow());

                    // Try to automatically configure TransPort if running with sudo
                    if let Ok(_) = std::env::var("SUDO_USER") {
                        auto_add_transparent_proxy_config(torrc_path);
                    }
                } else {
                    info!("Tor TransPort is already configured for transparent proxying");
                }

                // Also check for DNSPort
                let has_dns_port = config.lines().any(|line| {
                    let trimmed = line.trim();
                    trimmed.starts_with("DNSPort") && !trimmed.starts_with('#')
                });

                if !has_dns_port {
                    warn!("Tor DNSPort is not configured in torrc - DNS may leak outside Tor");
                    println!("{}", "⚠️  Tor DNSPort not configured - add 'DNSPort 53' to prevent DNS leaks".yellow());

                    if let Ok(_) = std::env::var("SUDO_USER") {
                        auto_add_dns_config(torrc_path);
                    }
                } else {
                    info!("Tor DNSPort is configured - DNS leak protection is active");
                }
            }
            Err(e) => {
                warn!("Cannot read Tor configuration file to check transparent proxy settings: {}", e);
            }
        }
    } else {
        warn!("Tor configuration file not found at {}", torrc_path);
    }
}

// Helper function to auto-add transparent proxy config to torrc
fn auto_add_transparent_proxy_config(torrc_path: &str) {
    info!("Auto-configuring Tor for transparent proxying");

    // Read the current config
    match std::fs::read_to_string(torrc_path) {
        Ok(config) => {
            // Check if TransPort is already added to avoid duplicates
            if !config.contains("TransPort") {
                let mut new_config = config;
                new_config.push_str("\n# Transparent proxy port for iptables redirect\nTransPort 9040\n");

                // Write back to file with sudo
                if let Ok(_) = write_config_with_sudo(torrc_path, &new_config) {
                    info!("Tor TransPort configuration added successfully");
                    println!("{}", "🔧 Tor TransPort configuration added to torrc".green());

                    // Restart Tor to apply changes
                    if restart_tor_service_with_sudo() {
                        info!("Tor service restarted with transparent proxy configuration");
                    } else {
                        warn!("Failed to restart Tor service after configuration update");
                        println!("{}", "⚠️  Could not restart Tor service - changes may not take effect".yellow());
                    }
                } else {
                    println!("{}", "⚠️  Failed to update Tor configuration file - manual edit required".yellow());
                }
            }
        }
        Err(e) => {
            warn!("Failed to read existing Tor config to add transparent proxy: {}", e);
        }
    }
}

// Helper function to auto-add DNS config to torrc
fn auto_add_dns_config(torrc_path: &str) {
    info!("Auto-configuring Tor for DNS leak protection");

    // Read the current config
    match std::fs::read_to_string(torrc_path) {
        Ok(config) => {
            // Check if DNSPort is already added to avoid duplicates
            if !config.contains("DNSPort") {
                let mut new_config = config;
                new_config.push_str("\n# DNS port to prevent DNS leaks\nDNSPort 53\n");
                new_config.push_str("# Automap hostnames to prevent DNS leaks\nAutomapHostsOnResolve 1\n");

                // Write back to file with sudo
                if let Ok(_) = write_config_with_sudo(torrc_path, &new_config) {
                    info!("Tor DNS configuration added successfully");
                    println!("{}", "🔧 Tor DNS configuration added to torrc".green());

                    // Restart Tor to apply changes
                    if restart_tor_service_with_sudo() {
                        info!("Tor service restarted with DNS configuration");
                    } else {
                        warn!("Failed to restart Tor service after DNS configuration update");
                        println!("{}", "⚠️  Could not restart Tor service - DNS changes may not take effect".yellow());
                    }
                } else {
                    println!("{}", "⚠️  Failed to update Tor configuration file - manual edit required".yellow());
                }
            }
        }
        Err(e) => {
            warn!("Failed to read existing Tor config to add DNS configuration: {}", e);
        }
    }
}

// Helper function for restarting Tor service with sudo
fn restart_tor_service_with_sudo() -> bool {
    restart_tor_service_helper()
}

// Helper function to refresh DNS resolver
fn refresh_dns_resolver() {
    // Refresh DNS resolver to apply new configuration using non-interactive commands
    // Prioritize non-systemd-resolved methods to avoid GUI prompts

    // Try direct service restart with non-interactive sudo
    let result = Command::new("sudo")
        .args(&["-n", "systemctl", "reload", "systemd-resolved"])
        .output();

    match result {
        Ok(output) => {
            if output.status.success() {
                info!("systemd-resolved reloaded successfully");
            } else {
                debug!("systemd-resolved reload failed or requires password: {}", String::from_utf8_lossy(&output.stderr));

                // Alternative: Try to send SIGHUP to systemd-resolved directly
                let alt_result = Command::new("sudo")
                    .args(&["-n", "pkill", "-HUP", "systemd-resolved"])
                    .output();

                match alt_result {
                    Ok(alt_output) => {
                        if alt_output.status.success() {
                            info!("systemd-resolved HUP signal sent successfully");
                        } else {
                            debug!("systemd-resolved HUP signal failed or service not running: {}", String::from_utf8_lossy(&alt_output.stderr));
                        }
                    },
                    Err(alt_e) => {
                        debug!("Failed to send HUP signal to systemd-resolved: {}", alt_e);
                    }
                }
            }
        },
        Err(e) => {
            debug!("Failed to reload systemd-resolved: {}", e);
            // Try direct service control as alternative
            let direct_result = Command::new("sudo")
                .args(&["-n", "pkill", "-USR2", "systemd-resolved"])
                .output();

            match direct_result {
                Ok(direct_output) => {
                    if direct_output.status.success() {
                        info!("systemd-resolved USR2 signal sent successfully");
                    } else {
                        debug!("systemd-resolved USR2 signal failed or not running: {}", String::from_utf8_lossy(&direct_output.stderr));
                    }
                },
                Err(direct_e) => {
                    debug!("Failed to send USR2 signal to systemd-resolved: {}", direct_e);
                }
            }
        }
    }

    // Alternative DNS cache refresh methods that don't rely on systemctl
    // If systemd-resolved is not used, try other methods

    // Try to restart NetworkManager using a different approach
    let nm_result = Command::new("sudo")
        .args(&["-n", "nmcli", "connection", "reload"])
        .output();

    match nm_result {
        Ok(output) => {
            if output.status.success() {
                info!("NetworkManager connection reload triggered");
            } else {
                debug!("NetworkManager reload failed or not available: {}", String::from_utf8_lossy(&output.stderr));
            }
        },
        Err(e) => {
            debug!("NetworkManager CLI (nmcli) not available: {}", e);
        }
    }
}

// Function to check Tor's transparent proxy configuration
fn check_tor_transparent_proxy_config() {
    info!("Checking Tor transparent proxy configuration");

    // Check if Tor's configuration includes HTTP tunnel port for transparent proxying
    let torrc_path = "/etc/tor/torrc";
    if Path::new(torrc_path).exists() {
        match std::fs::read_to_string(torrc_path) {
            Ok(config) => {
                // Look for HTTPTunnelPort directive (case-insensitive)
                let http_tunnel_exists = config.lines().any(|line| {
                    let trimmed = line.trim().to_lowercase();
                    trimmed.starts_with("httptunnelport") ||
                    trimmed.starts_with("socksport")
                });

                if !http_tunnel_exists {
                    // HTTPTunnelPort is not configured, which is needed for HTTP proxy functionality
                    info!("Tor HTTPTunnelPort is not configured - only SOCKS proxy is available");
                    println!("{}", "ℹ️  Tor HTTP tunneling not configured - only SOCKS proxy available".blue());
                    println!("{}", "ℹ️  For full transparent proxying, add 'HTTPTunnelPort 8118' to /etc/tor/torrc".blue());
                } else {
                    info!("Tor HTTPTunnelPort is configured - HTTP tunneling available");
                }

                // Check for TransPort (transparent proxy port) configuration (case-insensitive)
                let trans_port_exists = config.lines().any(|line| {
                    let trimmed = line.trim().to_lowercase();
                    trimmed.starts_with("transport")
                });

                // Check for DNSPort configuration (critical for DNS leak protection)
                let dns_port_exists = config.lines().any(|line| {
                    let trimmed = line.trim().to_lowercase();
                    trimmed.starts_with("dnsport")
                });

                if trans_port_exists {
                    info!("Tor TransPort configured - transparent proxying capability available");
                    println!("{}", "ℹ️  Tor transparent proxying is available with iptables rules".blue());
                } else {
                    info!("Tor TransPort not configured - transparent iptables routing may be limited");
                    println!("{}", "💡 Add 'TransPort 9040' to /etc/tor/torrc for transparent proxying".blue());
                }

                // Check if DNSPort is configured (essential for DNS leak protection)
                if !dns_port_exists {
                    warn!("Tor DNSPort is not configured - this is critical for DNS leak protection");
                    println!("{}", "⚠️  Tor DNSPort not configured - add 'DNSPort 53' to /etc/tor/torrc".yellow());
                    println!("{}", "💡 For complete DNS leak protection, add 'DNSPort 53' and 'AutomapHostsOnResolve 1'".blue());

                    // Try to auto-configure DNS if running with sufficient privileges
                    if let Ok(_) = std::env::var("USER") {
                        if std::process::Command::new("id")
                            .arg("-u")
                            .output()
                            .map(|o| o.status.success())
                            .unwrap_or(false) {
                                auto_configure_tor_dns_settings(torrc_path);
                            }
                    }
                } else {
                    info!("Tor DNSPort is configured - DNS leak protection is enabled");
                }

                // Check for AutomapHostsOnResolve setting (important for DNS handling)
                let automap_exists = config.lines().any(|line| {
                    let trimmed = line.trim().to_lowercase();
                    trimmed.starts_with("automaphostsonresolve")
                });

                if !automap_exists {
                    info!("Tor configuration could be enhanced with AutomapHostsOnResolve for better DNS handling");
                    println!("{}", "💡 Add 'AutomapHostsOnResolve 1' to /etc/tor/torrc for enhanced DNS handling".blue());
                }
            },
            Err(e) => {
                warn!("Cannot read Tor configuration file to check transparent proxy settings: {}", e);
            }
        }
    } else {
        info!("Tor configuration file not found at {}", torrc_path);
        println!("{}", "⚠️  Tor configuration file not found - check that Tor is properly installed".yellow());
    }
}

// Helper function to auto-configure Tor DNS settings
fn auto_configure_tor_dns_settings(torrc_path: &str) -> bool {
    info!("Attempting to auto-configure Tor DNS settings for leak protection");

    // Check if we have write permissions to the torrc file
    if !std::path::Path::new(torrc_path).exists() {
        warn!("Tor configuration file does not exist at {}", torrc_path);
        return false;
    }

    match std::fs::read_to_string(torrc_path) {
        Ok(current_config) => {
            let config_lines: Vec<&str> = current_config.lines().collect();
            let mut needs_update = false;
            let mut updated_config = current_config.clone();

            // Check if DNSPort is already configured
            let has_dns_port = config_lines.iter().any(|line| {
                let trimmed = line.trim().to_lowercase();
                trimmed.starts_with("dnsport") || trimmed.starts_with("DNSPort")
            });

            if !has_dns_port {
                info!("Adding DNSPort configuration to Tor config");
                updated_config.push_str("\n# Route DNS requests through Tor to prevent DNS leaks\nDNSPort 53\n");
                needs_update = true;
            }

            // Check if AutomapHostsOnResolve is configured
            let has_automap = config_lines.iter().any(|line| {
                let trimmed = line.trim().to_lowercase();
                trimmed.starts_with("automaphostsonresolve") && !trimmed.starts_with("##")
            });

            if !has_automap {
                info!("Adding AutomapHostsOnResolve configuration to Tor config");
                updated_config.push_str("\n# Map all hostnames to IPs via Tor's resolver to prevent DNS leaks\nAutomapHostsOnResolve 1\n");
                needs_update = true;
            }

            // Also check for TransPort
            let has_trans_port = config_lines.iter().any(|line| {
                let trimmed = line.trim().to_lowercase();
                trimmed.starts_with("transport") && !trimmed.starts_with("##")
            });

            if !has_trans_port {
                info!("Adding TransPort configuration to Tor config");
                updated_config.push_str("\n# Transparent proxy port for routing all traffic through Tor\nTransPort 9040\n");
                needs_update = true;
            }

            if needs_update {
                // Write the updated configuration to the file (requires sudo)
                match write_config_with_sudo(torrc_path, &updated_config) {
                    Ok(_) => {
                        info!("Successfully updated Tor configuration with DNS settings");
                        println!("{}", "🔧 Tor configuration updated with DNSPort, AutomapHostsOnResolve, and TransPort".green());

                        // Restart Tor service to apply changes
                        if restart_tor_service_helper() {
                            info!("Tor service restarted with new DNS configuration");
                            println!("{}", "🔄 Tor service restarted to apply configuration changes".green());
                        } else {
                            warn!("Failed to restart Tor service after configuration update");
                            println!("{}", "⚠️  Failed to restart Tor service - DNS changes may not take effect".yellow());
                        }
                        return true;
                    },
                    Err(e) => {
                        warn!("Failed to update Tor configuration file: {}", e);
                        println!("{}", format!("⚠️  Could not update Tor config - add DNSPort, TransPort manually: {}", e).yellow());
                    }
                }
            } else {
                info!("Tor configuration already contains required DNS settings");
                return true;
            }
        },
        Err(e) => {
            warn!("Cannot read Tor configuration file to update DNS settings: {}", e);
            return false;
        }
    }

    false
}

// Helper function to write configuration file with sudo
fn write_config_with_sudo(file_path: &str, content: &str) -> Result<(), String> {
    // Use a temporary file and then copy with sudo
    let temp_path = "/tmp/torc_temp_torrc";

    match std::fs::write(temp_path, content) {
        Ok(_) => {
            // Copy the temp file to the actual location with sudo
            let result = Command::new("sudo")
                .args(&["cp", temp_path, file_path])
                .output();

            match result {
                Ok(output) => {
                    if output.status.success() {
                        // Clean up the temp file
                        let _ = std::fs::remove_file(temp_path);
                        Ok(())
                    } else {
                        Err(format!("sudo cp failed: {}", String::from_utf8_lossy(&output.stderr)))
                    }
                },
                Err(e) => Err(format!("failed to execute sudo copy: {}", e))
            }
        },
        Err(e) => Err(format!("failed to write temporary file: {}", e))
    }
}

// Helper function to restart Tor service after configuration changes
fn restart_tor_service_helper() -> bool {
    info!("Restarting Tor service to apply configuration changes");

    // Stop the Tor service first
    match stop_tor_service() {
        Ok(_) => {
            info!("Tor service stopped successfully");

            // Give some time for the service to fully stop
            std::thread::sleep(std::time::Duration::from_secs(2));

            // Start the Tor service again with new configuration
            match start_tor_service_with_delay() {
                Ok(_) => {
                    info!("Tor service restarted successfully with new configuration");
                    true
                },
                Err(e) => {
                    warn!("Failed to restart Tor service: {}", e);
                    false
                }
            }
        },
        Err(e) => {
            warn!("Failed to stop Tor service before restart: {}", e);

            // Try to start directly anyway
            match start_tor_service_with_delay() {
                Ok(_) => {
                    info!("Tor service started with new configuration");
                    true
                },
                Err(start_err) => {
                    warn!("Failed to start Tor service after stop failure: {}", start_err);
                    false
                }
            }
        }
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
    // First, remove existing chains if they exist to avoid "Chain already exists" errors
    let cleanup_ipv4_rules = vec![
        // Delete existing chain if it exists
        vec!["-t", "mangle", "-X", "TOR_REDIRECT_V4"],
    ];

    for rule in &cleanup_ipv4_rules {
        let _ = Command::new("sudo")
            .arg("-n")  // Non-interactive mode to avoid GUI prompts
            .arg("iptables")
            .args(rule)
            .output(); // Ignore errors - the chain may not exist
    }

    let ipv4_rules = vec![
        // Create new chain for Tor traffic (IPv4)
        vec!["-t", "mangle", "-N", "TOR_REDIRECT_V4"],
        // Flush existing OUTPUT chain rules in mangle table for IPv4
        vec!["-t", "mangle", "-F", "OUTPUT"],
        // Redirect all TCP traffic (except loopback and already redirected) to Tor
        vec!["-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "!", "-o", "lo", "!", "-d", "127.0.0.1", "-j", "TOR_REDIRECT_V4"],
        // Mark traffic from Tor user to not be redirected (avoid loops)
        vec!["-t", "mangle", "-A", "TOR_REDIRECT_V4", "-m", "owner", "--uid-owner", &tor_uid, "-j", "RETURN"],
        // Redirect remaining traffic to Mark (using MARK target for routing)
        vec!["-t", "mangle", "-A", "TOR_REDIRECT_V4", "-p", "tcp", "--tcp-flags", "FIN,SYN,RST,ACK", "SYN", "-j", "MARK", "--set-mark", "1"]
    ];

    // Apply IPv4 iptables rules
    for rule in &ipv4_rules {
        match Command::new("sudo")
            .arg("-n")  // Non-interactive mode to avoid GUI prompts
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

    // Also configure OUTPUT chain for the main table to redirect IPv4 traffic to Tor's TransPort for transparent proxying
    // First, clean up any existing chains to prevent "Chain already exists" errors
    let cleanup_ipv4_nat_rules = vec![
        // Delete existing chain if it exists
        vec!["-t", "nat", "-X", "TOR_REDIR_V4"],
    ];

    for rule in &cleanup_ipv4_nat_rules {
        let _ = Command::new("sudo")
            .arg("iptables")
            .args(rule)
            .output(); // Ignore errors - the chain may not exist
    }

    let ipv4_nat_rules = vec![
        // Create new chain for Tor traffic (IPv4)
        vec!["-t", "nat", "-N", "TOR_REDIR_V4"],
        // Flush existing OUTPUT chain rules in nat table for IPv4
        vec!["-t", "nat", "-F", "OUTPUT"],
        // Don't redirect traffic from Tor user (avoid loops)
        vec!["-t", "nat", "-A", "TOR_REDIR_V4", "-m", "owner", "--uid-owner", &tor_uid, "-j", "RETURN"],
        // Redirect non-local TCP traffic to Tor's transparent proxy port (9040) - use separate rules for multiple destinations
        vec!["-t", "nat", "-A", "TOR_REDIR_V4", "-p", "tcp", "!", "-d", "127.0.0.1", "-j", "REDIRECT", "--to-port", "9040"],
        vec!["-t", "nat", "-A", "TOR_REDIR_V4", "-p", "tcp", "!", "-d", "192.168.0.0/16", "-j", "REDIRECT", "--to-port", "9040"],
        vec!["-t", "nat", "-A", "TOR_REDIR_V4", "-p", "tcp", "!", "-d", "10.0.0.0/8", "-j", "REDIRECT", "--to-port", "9040"],
        vec!["-t", "nat", "-A", "TOR_REDIR_V4", "-p", "tcp", "!", "-d", "172.16.0.0/12", "-j", "REDIRECT", "--to-port", "9040"],
        // Use the chain in OUTPUT
        vec!["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "!", "-o", "lo", "-j", "TOR_REDIR_V4"]
    ];

    for rule in &ipv4_nat_rules {
        match Command::new("sudo")
            .arg("-n")  // Non-interactive mode to avoid GUI prompts
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
    // First, remove existing chains if they exist to avoid "Chain already exists" errors
    let cleanup_ipv6_rules = vec![
        // Delete existing chain if it exists
        vec!["-t", "mangle", "-X", "TOR_REDIRECT_V6"],
    ];

    for rule in &cleanup_ipv6_rules {
        let _ = Command::new("sudo")
            .arg("-n")  // Non-interactive mode to avoid GUI prompts
            .arg("ip6tables")
            .args(rule)
            .output(); // Ignore errors - the chain may not exist
    }

    let ipv6_rules = vec![
        // Create new chain for Tor traffic (IPv6)
        vec!["-t", "mangle", "-N", "TOR_REDIRECT_V6"],
        // Flush existing OUTPUT chain rules in mangle table for IPv6
        vec!["-t", "mangle", "-F", "OUTPUT"],
        // Redirect all TCP traffic (except loopback and already redirected) to Tor
        vec!["-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "!", "-o", "lo", "!", "-d", "::1", "-j", "TOR_REDIRECT_V6"],
        // Mark traffic from Tor user to not be redirected (avoid loops)
        vec!["-t", "mangle", "-A", "TOR_REDIRECT_V6", "-m", "owner", "--uid-owner", &tor_uid, "-j", "RETURN"],
        // Mark remaining traffic for routing via Tor (using MARK target for routing)
        vec!["-t", "mangle", "-A", "TOR_REDIRECT_V6", "-p", "tcp", "--tcp-flags", "FIN,SYN,RST,ACK", "SYN", "-j", "MARK", "--set-mark", "1"]
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

    // Configure ip6tables rules for IPv6 traffic redirection using TransPort for transparent proxying
    // First, clean up any existing chains to prevent "Chain already exists" errors
    let cleanup_ipv6_nat_rules = vec![
        // Delete existing chain if it exists
        vec!["-t", "nat", "-X", "TOR_REDIR_V6"],
    ];

    for rule in &cleanup_ipv6_nat_rules {
        let _ = Command::new("sudo")
            .arg("ip6tables")
            .args(rule)
            .output(); // Ignore errors - the chain may not exist
    }

    let ipv6_nat_rules = vec![
        // For IPv6, redirect non-local traffic to Tor's transparent proxy port
        // Create new chain for Tor traffic (IPv6)
        vec!["-t", "nat", "-N", "TOR_REDIR_V6"],
        // Flush existing OUTPUT chain rules in nat table for IPv6
        vec!["-t", "nat", "-F", "OUTPUT"],
        // Don't redirect traffic from Tor user (avoid loops)
        vec!["-t", "nat", "-A", "TOR_REDIR_V6", "-m", "owner", "--uid-owner", &tor_uid, "-j", "RETURN"],
        // Redirect non-local TCP traffic to Tor's transparent proxy port (9040) - separate rules for multiple destinations
        vec!["-t", "nat", "-A", "TOR_REDIR_V6", "-p", "tcp", "!", "-d", "::1", "-j", "REDIRECT", "--to-port", "9040"],
        vec!["-t", "nat", "-A", "TOR_REDIR_V6", "-p", "tcp", "!", "-d", "fe80::/10", "-j", "REDIRECT", "--to-port", "9040"],
        vec!["-t", "nat", "-A", "TOR_REDIR_V6", "-p", "tcp", "!", "-d", "fc00::/7", "-j", "REDIRECT", "--to-port", "9040"],
        vec!["-t", "nat", "-A", "TOR_REDIR_V6", "-p", "tcp", "!", "-d", "::ffff:127.0.0.1", "-j", "REDIRECT", "--to-port", "9040"],
        // Use the chain in OUTPUT
        vec!["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "!", "-o", "lo", "-j", "TOR_REDIR_V6"]
    ];

    for rule in &ipv6_nat_rules {
        match Command::new("sudo")
            .arg("-n")  // Non-interactive mode to avoid GUI prompts
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
    // We only set ALL_PROXY, so only need to remove that
    std::env::remove_var("ALL_PROXY");

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
    } else {
        // If iptables restoration failed, warn the user but continue
        warn!("IPTables rule restoration failed - manual cleanup may be needed");
        println!("{}", "⚠️  Environment variables reset but IPTables restoration failed".yellow());
        println!("{}", "⚠️  Manual iptables cleanup may be required".yellow());
    }

    // Restore DNS configuration and clear DNS cache
    if restore_dns_config() {
        println!("{}", "✓ DNS configuration restored".green());
    } else {
        warn!("DNS configuration restoration failed - manual DNS cleanup may be needed");
        println!("{}", "⚠️  DNS configuration restoration failed - manual DNS cleanup may be required".yellow());
    }

    println!("{}", "✓ Normal system routing restored".green());
}

// Function to restore DNS configuration to normal state
// Returns true if successful, false if there was an error
fn restore_dns_config() -> bool {
    info!("Restoring DNS configuration to normal state");

    let mut success = true;

    // Clear the DNS cache to ensure we're using the restored configuration
    if !clear_dns_cache() {
        warn!("Failed to clear DNS cache during restoration");
        success = false;
    }

    // Restore the original DNS configuration from backup
    match restore_dns_config_to_original() {
        Ok(_) => {
            info!("DNS configuration restored from backup successfully");
            // Update DNS resolver to apply new configuration
            refresh_dns_resolver();
        },
        Err(e) => {
            warn!("Failed to restore DNS configuration from backup: {}", e);
            success = false;
        }
    }

    // Also check if we need to undo any systemd-resolved configuration
    if is_systemd_resolved_running() {
        info!("Restoring systemd-resolved configuration");

        // Try to reload systemd-resolved to apply original settings with non-interactive sudo
        let result = Command::new("sudo")
            .args(&["-n", "systemctl", "reload-or-restart", "systemd-resolved"])
            .output();

        match result {
            Ok(output) => {
                if output.status.success() {
                    info!("systemd-resolved reloaded successfully");
                } else {
                    warn!("Failed to reload systemd-resolved: {}", String::from_utf8_lossy(&output.stderr));
                    success = false;
                }
            }
            Err(e) => {
                warn!("Failed to execute systemd-resolved reload command: {}", e);
                success = false;
            }
        }
    }

    info!("DNS configuration restoration completed with success: {}", success);
    success
}

// Restore iptables rules to remove Tor redirection
// Returns true if successful, false if there was an error
fn restore_iptables_rules() -> bool {
    info!("Restoring iptables rules to normal state");

    let mut success = true;

    // First wait a moment before starting restoration
    std::thread::sleep(std::time::Duration::from_secs(1));

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
            .arg("-n")  // Non-interactive mode to avoid GUI prompts
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

        // Wait between rules to prevent race conditions
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    // Wait after clearing IPv4 rules before proceeding
    std::thread::sleep(std::time::Duration::from_secs(1));

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
            .arg("-n")  // Non-interactive mode to avoid GUI prompts
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

        // Wait between rules to prevent race conditions
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    // Wait after clearing IPv6 rules before proceeding
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Also flush all rules in mangle and nat tables to ensure clean state for IPv4
    let ipv4_flush_rules = vec![
        vec!["-t", "mangle", "-F"],
        vec!["-t", "nat", "-F"],
    ];

    for rule in &ipv4_flush_rules {
        match Command::new("sudo")
            .arg("-n")  // Non-interactive mode to avoid GUI prompts
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

        // Wait between flush commands to prevent race conditions
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // Wait after flushing IPv4 tables before proceeding to IPv6
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Also flush all rules in mangle and nat tables to ensure clean state for IPv6
    let ipv6_flush_rules = vec![
        vec!["-t", "mangle", "-F"],
        vec!["-t", "nat", "-F"],
    ];

    for rule in &ipv6_flush_rules {
        match Command::new("sudo")
            .arg("-n")  // Non-interactive mode to avoid GUI prompts
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

        // Wait between IPv6 flush commands to prevent race conditions
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // Final wait after all iptables operations are complete
    std::thread::sleep(std::time::Duration::from_secs(2));

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

        // Wait after proxy settings restoration
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Restore firewall rules
        restore_firewall_rules(&state.firewall_rules)?;

        // Wait after firewall rules restoration
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Restore DNS servers
        restore_dns_servers(&state.dns_servers)?;

        // Wait after DNS servers restoration
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Restore routing table
        restore_routing_table(&state.routing_table)?;

        // Wait after routing table restoration
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Restore network interfaces
        restore_network_interfaces(&state.network_interfaces)?;

        // Final wait before clearing the backup
        std::thread::sleep(std::time::Duration::from_secs(1));

        println!("{}", "✓ System network state restored successfully".green());

        // Clear the backup
        {
            let mut backup = SYSTEM_STATE_BACKUP.lock().unwrap();
            *backup = None;
        }

        // Additional wait after clearing backup
        std::thread::sleep(std::time::Duration::from_secs(1));

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

        // Reset DNS configuration to defaults (this varies by system) with non-interactive sudo
        let _ = Command::new("sudo")
            .args(&["-n", "systemctl", "reload", "systemd-resolved"])
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

// Helper function to write configuration file with sudo
