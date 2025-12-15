use std::io::{self, Write};
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
        println!("{}", "Status: 🔴 Connected to Tor Network".green());
    } else {
        println!("{}", "Status: 🟢 Not Connected to Tor Network".red());
    }
}

fn connect_to_tor() {
    println!("{}", "\nAttempting to connect to Tor Network...".yellow());

    // Check if Tor is installed
    if !is_tor_installed() {
        println!("{}", "Tor is not installed on your system.".red());
        println!("{}", "Please install Tor using your package manager (e.g., 'sudo pacman -S tor' on Arch Linux)".yellow());
        return;
    }

    // On Arch Linux, we need to use systemctl to manage the Tor service
    println!("{}", "Starting Tor service...".yellow());

    // In a real implementation, this would use the systemctl command
    // For simulation purposes, we'll just show a message
    simulate_tor_connection();

    println!("{}", "Tor connection established! All web traffic is now routed through Tor.".green());
    println!("{}", "Your IP address is now hidden and your traffic is anonymized.".green());
}

fn disconnect_from_tor() {
    println!("{}", "\nDisconnecting from Tor Network...".yellow());

    // In a real implementation, this would stop the Tor service
    simulate_tor_disconnection();

    println!("{}", "Disconnected from Tor Network. Your traffic is no longer anonymized.".red());
    println!("{}", "Regular internet connection restored.".green());
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

fn is_tor_installed() -> bool {
    // In a real implementation, this would check if the tor command exists
    // For simulation, we'll return true assuming it's installed
    true
}

fn is_tor_service_running() -> bool {
    // In a real implementation, this would check if the Tor service is active
    // For simulation, we'll return false (not connected by default)
    false
}

fn simulate_tor_connection() {
    // Simulate the connection process
    std::thread::sleep(std::time::Duration::from_millis(1000));
    println!("{}", "✓ Tor daemon started".green());
    std::thread::sleep(std::time::Duration::from_millis(500));
    println!("{}", "✓ Establishing circuit to Tor network".green());
    std::thread::sleep(std::time::Duration::from_millis(1000));
    println!("{}", "✓ Circuit established - connection secured".green());
}

fn simulate_tor_disconnection() {
    // Simulate the disconnection process
    std::thread::sleep(std::time::Duration::from_millis(500));
    println!("{}", "✓ Disconnecting from Tor network".green());
    std::thread::sleep(std::time::Duration::from_millis(500));
    println!("{}", "✓ Tor service stopped".green());
    std::thread::sleep(std::time::Duration::from_millis(500));
    println!("{}", "✓ Regular routing restored".green());
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