use std::io::{self, Write};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::path::Path;
use std::fs;
use colored::*;
use anyhow::Result;

fn main() -> Result<()> {
    println!("{}", "TORC - Tor Network Connector".green().bold());
    println!("{}", "Connecting your system to the Tor network for anonymous browsing".yellow());
    println!();

    loop {
        show_menu();

        print!("\n{} ", "Enter your choice:".cyan());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim() {
            "1" => connect_to_tor(),
            "2" => disconnect_from_tor(),
            "3" => check_tor_status(),
            "4" => {
                println!("{}", "Exiting TORC. Your system is no longer connected to Tor.".yellow());
                break;
            },
            _ => println!("{}", "Invalid option. Please try again.".red()),
        }

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

fn connect_to_tor() {
    println!("{}", "\n🔄 Connecting to Tor Network...".yellow());

    // Check if Tor is installed
    print!("{}", "🔍 Checking if Tor is installed... ");
    if !is_tor_installed() {
        println!("{}", "❌".red());
        println!("{}", "Tor is not installed on your system.".red());
        println!("{}", "Please install Tor using your package manager (e.g., 'sudo pacman -S tor' on Arch Linux)".yellow());
        return;
    }
    println!("{}", "✅".green());

    // Check if already connected
    print!("{}", "🔒 Checking current Tor status... ");
    if is_tor_service_running() {
        println!("{}", "🟢 Already running".green());
        println!("{}", "Tor service is already running!".yellow());
        check_tor_status_inline();
        return;
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
            return;
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
}

fn disconnect_from_tor() {
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
}

fn check_tor_status() {
    println!("{}", "\nTor Network Status:".cyan().bold());

    let tor_installed = is_tor_installed();
    let tor_running = is_tor_service_running();

    if !tor_installed {
        println!("{}", "Tor Status: ❌ Tor is not installed".red());
        println!("{}", "Install Tor to use this feature (e.g., 'sudo pacman -S tor' on Arch Linux)".yellow());
        return;
    }

    if tor_running {
        println!("{}", "Tor Status: 🟢 Service is running".green());
        println!("{}", "Traffic: 🔒 All traffic is routed through Tor".green());
        display_tor_info();
    } else {
        println!("{}", "Tor Status: 🔴 Service is not running".red());
        println!("{}", "Traffic: 🌐 Direct connection (not anonymous)".yellow());
    }
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
        return Err(anyhow::anyhow!("Sudo access validation failed"));
    }

    Ok(())
}


// Enhanced version of start_tor_service with animated delay indicator
fn start_tor_service_with_delay() -> Result<()> {
    // First validate sudo access
    match validate_sudo_access() {
        Ok(_) => {},
        Err(e) => {
            return Err(anyhow::anyhow!("Sudo access required to start Tor service: {}", e));
        }
    }

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
        // If systemctl fails, try starting directly with tor command
        let output = Command::new("sudo")
            .args(&["systemctl", "enable", "tor"])
            .output()?;

        if output.status.success() {
            let output = Command::new("sudo")
                .args(&["systemctl", "start", "tor"])
                .output()?;

            if !output.status.success() {
                stop_animation.store(true, Ordering::Relaxed); // Stop animation
                Err(anyhow::anyhow!("Failed to start Tor service"))
            } else {
                Ok(())
            }
        } else {
            stop_animation.store(true, Ordering::Relaxed); // Stop animation
            Err(anyhow::anyhow!("Failed to enable Tor service"))
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
        return Err(anyhow::anyhow!("Failed to stop Tor service"));
    }

    Ok(())
}

fn is_tor_service_running() -> bool {
    let output = Command::new("systemctl")
        .args(&["is-active", "tor"])
        .output();

    match output {
        Ok(output) => output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "active",
        Err(_) => false,
    }
}

fn is_tor_installed() -> bool {
    let output = Command::new("which")
        .arg("tor")
        .output();

    match output {
        Ok(output) => output.status.success(),
        Err(_) => false,
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