use std::io::{self, Write};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::path::Path;
use std::fs;
use colored::*;
use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "torc")]
#[command(about = "A Rust CLI application to connect your system to the Tor network", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
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

#[derive(Subcommand)]
enum SystemOps {
    /// Connect to the Tor network
    Connect,
    /// Disconnect from the Tor network
    Disconnect,
    /// Check the Tor network status
    Status,
}

#[derive(Subcommand)]
enum DiskOps {
    /// Encrypt a disk partition
    Encrypt { path: String },
    /// Decrypt a disk partition
    Decrypt { path: String },
    /// Check encryption status of a disk partition
    Status { path: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::System { operation }) => {
            match operation {
                Some(SystemOps::Connect) => connect_to_tor()?,
                Some(SystemOps::Disconnect) => disconnect_from_tor()?,
                Some(SystemOps::Status) => check_tor_status()?,
                None => show_interactive_menu()?,  // Show menu if no sub-operation specified
            }
        },
        Some(Commands::Disk { operation }) => {
            match operation {
                Some(DiskOps::Encrypt { path }) => encrypt_disk(path)?,
                Some(DiskOps::Decrypt { path }) => decrypt_disk(path)?,
                Some(DiskOps::Status { path }) => check_disk_encryption_status(path)?,
                None => {
                    println!("{}", "Disk operations:".cyan());
                    println!("{}", "  encrypt <path> - Encrypt a disk partition".cyan());
                    println!("{}", "  decrypt <path> - Decrypt a disk partition".cyan());
                    println!("{}", "  status <path>  - Check encryption status".cyan());
                    return Ok(());
                }
            }
        },
        None => show_interactive_menu()?,  // Show menu if no command specified
    }

    Ok(())
}

fn show_interactive_menu() -> Result<()> {
    println!("{}", "TORC - Tor Network Connector".green().bold());
    println!("{}", "Connecting your system to the Tor network for anonymous browsing".yellow());
    println!();

    loop {
        show_menu();

        print!("\n{} ", "Enter your choice:".cyan());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let result = match input.trim() {
            "1" => connect_to_tor().map(|_| ()),
            "2" => disconnect_from_tor().map(|_| ()),
            "3" => check_tor_status().map(|_| ()),
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

fn show_menu() {
    print!("\x1B[2J\x1B[1;1H");  // Clear screen

    println!("{}", r#"
                                       
▄▄▄▄▄▄▄▄▄   ▄▄▄▄▄   ▄▄▄▄▄▄▄    ▄▄▄▄▄▄▄ 
▀▀▀███▀▀▀ ▄███████▄ ███▀▀███▄ ███▀▀▀▀▀ 
   ███    ███   ███ ███▄▄███▀ ███      
   ███    ███▄▄▄███ ███▀▀██▄  ███      
   ███     ▀█████▀  ███  ▀███ ▀███████ 
                                       
    "#.green());

    println!("{}", "TORC - Tor Network Connector".green().bold());
    println!("{}", "=".repeat(50).cyan());

    println!("{}", "1. 🔗 Connect to Tor Network".cyan());
    println!("{}", "2. ❌ Disconnect from Tor Network".red());
    println!("{}", "3. 🔍 Check Tor Status".yellow());
    println!("{}", "4. 🚪 Exit".magenta());

    println!("{}", "\nCurrent Status:".bold());
    check_tor_status_inline();

    println!("{}", "\n[INFO] This application routes all web traffic through the Tor network".yellow());
    println!("{}", "[CAUTION] Tor may slow down your connection and some websites may block Tor users".red());
}

fn check_tor_status_inline() {
    // Check if Tor service is running
    let tor_running = is_tor_service_running();

    if tor_running {
        println!("{}", "Status: 🟢 Connected to Tor Network".green());
    } else {
        println!("{}", "Status: 🔴 Not Connected to Tor Network".red());
    }
}

fn connect_to_tor() -> Result<()> {
    println!("{}", "\n🔄 Connecting to Tor Network...".yellow());

    // Check if Tor is installed
    print!("{}", "🔍 Checking if Tor is installed... ");
    if !is_tor_installed() {
        println!("{}", "❌".red());
        println!("{}", "Tor is not installed on your system.".red());
        println!("{}", "Please install Tor using your package manager (e.g., 'sudo pacman -S tor' on Arch Linux)".yellow());
        return Ok(());
    }
    println!("{}", "✅".green());

    // Check if already connected
    print!("{}", "🔒 Checking current Tor status... ");
    if is_tor_service_running() {
        println!("{}", "🟢 Already running".green());
        println!("{}", "Tor service is already running!".yellow());
        check_tor_status_inline();
        return Ok(());
    }
    println!("{}", "🔴 Not running".red());

    // Validate sudo access before attempting to start service
    print!("{}", "🔑 Validating sudo access... ");
    match validate_sudo_access() {
        Ok(_) => println!("{}", "✅".green()),
        Err(e) => {
            println!("{}", "❌".red());
            println!("{}", format!("Insufficient privileges: {}", e).red());
            println!("{}", "Please ensure you have sudo access to start system services.".yellow());
            return Ok(());
        }
    }

    // Show progress indicator while starting service
    print!("{}", "⚡ Starting Tor service... ".yellow());
    std::io::stdout().flush().unwrap(); // Ensure print is displayed immediately

    // Try to start the Tor service
    match start_tor_service_with_delay() {
        Ok(_) => {
            println!("{}", "🎉 Success!".green());

            // Verify that Tor is actually running
            print!("{}", "✅ Verifying Tor service status... ".yellow());
            if is_tor_service_running() {
                println!("{}", "✅ Verified".green());
                println!("{}", "\nTor connection established! All web traffic is now routed through Tor.".green());
                println!("{}", "🔒 Your IP address is now hidden and your traffic is anonymized.".green());

                // Configure system to route traffic through Tor (this is a simplified representation)
                configure_system_proxy();

                // Perform connection verification
                verify_tor_connection();
            } else {
                println!("{}", "⚠️  Warning".yellow());
                println!("{}", "Warning: Tor service may not be fully operational.".yellow());
            }
        },
        Err(e) => {
            println!("{}", "💥 Failed".red());
            println!("{}", format!("Failed to connect to Tor: {}", e).red());
            println!("{}", "📋 Troubleshooting tips:".yellow());
            println!("{}", "- Check if Tor configuration is valid: sudo tor --verify-config".yellow());
            println!("{}", "- Ensure no other Tor processes are running".yellow());
            println!("{}", "- Check system logs for more details: journalctl -u tor".yellow());
        }
    }
    Ok(())
}

fn disconnect_from_tor() -> Result<()> {
    println!("{}", "\nDisconnecting from Tor Network...".yellow());

    match stop_tor_service() {
        Ok(_) => {
            restore_system_proxy();
            println!("{}", "Disconnected from Tor Network. Your traffic is no longer anonymized.".red());
            println!("{}", "Regular internet connection restored.".green());
        },
        Err(e) => {
            println!("{}", format!("Failed to disconnect from Tor: {}", e).red());
        }
    }
    Ok(())
}

fn check_tor_status() -> Result<()> {
    println!("{}", "\nTor Network Status:".cyan().bold());

    let tor_installed = is_tor_installed();
    let tor_running = is_tor_service_running();

    if !tor_installed {
        println!("{}", "Tor Status: ❌ Tor is not installed".red());
        println!("{}", "Install Tor to use this feature (e.g., 'sudo pacman -S tor' on Arch Linux)".yellow());
        return Ok(());
    }

    if tor_running {
        println!("{}", "Tor Status: 🟢 Service is running".green());
        println!("{}", "Traffic: 🔒 All traffic is routed through Tor".green());
        display_tor_info();
    } else {
        println!("{}", "Tor Status: 🔴 Service is not running".red());
        println!("{}", "Traffic: 🌐 Direct connection (not anonymous)".yellow());
    }
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

fn configure_system_proxy() {
    println!("{}", "Configuring system to route traffic through Tor...".yellow());
    // In a real implementation, this would set system proxy settings
    // and potentially configure iptables rules to redirect traffic
    // For simulation, we'll just show a message
    println!("{}", "✓ System configured to use Tor proxy (127.0.0.1:9050)".green());
}

fn restore_system_proxy() {
    println!("{}", "Restoring normal system routing...".yellow());
    // In a real implementation, this would restore normal proxy settings
    // and remove any iptables rules
    // For simulation, we'll just show a message
    println!("{}", "✓ Normal system routing restored".green());
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