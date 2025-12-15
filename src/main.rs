use clap::Parser;
use colored::*;
use anyhow::Result;
use sysinfo::{System, SystemExt, CpuExt, DiskExt};

#[derive(Parser)]
#[command(name = "torc")]
#[command(about = "A CLI application for Linux", long_about = None)]
struct Args {
    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Subcommand to execute
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Display system information
    System {
        /// Show detailed system information
        #[arg(short, long)]
        detail: bool,
    },

    /// Manage packages (Arch Linux specific)
    Package {
        /// Action to perform on packages
        #[arg(value_enum)]
        action: PackageAction,

        /// Package names
        packages: Vec<String>,
    },

    /// Show disk usage
    Disk {
        /// Human-readable format
        #[arg(short = 'H', long)]
        human: bool,
    },

    /// Monitor system resources
    Monitor {},
}

#[derive(clap::ValueEnum, Clone)]
enum PackageAction {
    Install,
    Remove,
    Update,
    Search,
    List,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.verbose {
        println!("{}", "Verbose mode enabled".yellow());
    }

    match args.command {
        Commands::System { detail } => cmd_system(detail),
        Commands::Package { action, packages } => cmd_package(action, packages, args.verbose),
        Commands::Disk { human } => cmd_disk(human),
        Commands::Monitor {} => cmd_monitor(),
    }
}

fn cmd_system(detail: bool) -> Result<()> {
    println!("{}", "System Information:".green().bold());

    // Get basic system info
    let sys = System::new_all();
    println!("OS: {} {}",
             sys.name().unwrap_or("Unknown".to_string()),
             sys.os_version().unwrap_or("".to_string()));
    println!("Host: {}", sys.host_name().unwrap_or("Unknown".to_string()));
    println!("Kernel: {}", sys.kernel_version().unwrap_or("Unknown".to_string()));
    println!("Uptime: {} seconds", sys.uptime());

    if detail {
        println!("\nCPU Count: {}", sys.cpus().len());
        println!("Total Memory: {:.2} GB", sys.total_memory() as f64 / (1024.0 * 1024.0 * 1024.0));
        println!("Free Memory: {:.2} GB", sys.free_memory() as f64 / (1024.0 * 1024.0 * 1024.0));
    }

    Ok(())
}

fn cmd_package(action: PackageAction, packages: Vec<String>, verbose: bool) -> Result<()> {
    match action {
        PackageAction::Install => {
            if packages.is_empty() {
                eprintln!("{}", "Error: No packages specified for installation".red());
                std::process::exit(1);
            }

            println!("Installing packages: {}", packages.join(", "));

            // For Arch Linux, we would typically use pacman
            let cmd = format!("sudo pacman -S {}", packages.join(" "));
            if verbose {
                println!("Executing: {}", cmd.green());
            }

            // In a real implementation, we would run the command
            // For now, we'll just simulate it
            println!("{}", "Simulation: Package installation would happen here".blue());
        }
        PackageAction::Remove => {
            if packages.is_empty() {
                eprintln!("{}", "Error: No packages specified for removal".red());
                std::process::exit(1);
            }

            println!("Removing packages: {}", packages.join(", "));
            println!("{}", "Simulation: Package removal would happen here".blue());
        }
        PackageAction::Update => {
            println!("Updating package databases and system...");
            println!("{}", "Simulation: System update would happen here".blue());
        }
        PackageAction::Search => {
            if packages.is_empty() {
                eprintln!("{}", "Error: No packages specified for search".red());
                std::process::exit(1);
            }

            println!("Searching for packages matching: {}", packages.join(", "));
            println!("{}", "Simulation: Package search would happen here".blue());
        }
        PackageAction::List => {
            println!("Listing installed packages...");
            println!("{}", "Simulation: Package listing would happen here".blue());
        }
    }

    Ok(())
}

fn cmd_disk(human: bool) -> Result<()> {
    println!("{}", "Disk Usage Information:".green().bold());

    let mut sys = System::new_all();
    sys.refresh_disks_list(); // Refresh disk list

    for disk in sys.disks() {
        let total_space = disk.total_space();
        let available_space = disk.available_space();
        let used_space = total_space - available_space;
        let usage_percentage = (used_space as f64 / total_space as f64) * 100.0;

        if human {
            println!("{}: {} used of {} ({:.1}%) [{}] mounted on {}",
                disk.name().to_string_lossy(),
                bytes_to_human(used_space),
                bytes_to_human(total_space),
                usage_percentage,
                String::from_utf8_lossy(disk.file_system()),
                disk.mount_point().to_string_lossy()
            );
        } else {
            println!("{}: {} bytes used of {} bytes ({:.1}%) [{}] mounted on {}",
                disk.name().to_string_lossy(),
                used_space,
                total_space,
                usage_percentage,
                String::from_utf8_lossy(disk.file_system()),
                disk.mount_point().to_string_lossy()
            );
        }
    }

    Ok(())
}

fn cmd_monitor() -> Result<()> {
    println!("Starting system monitor...");
    println!("Press Ctrl+C to exit");

    loop {
        let mut sys = System::new_all();
        sys.refresh_all();

        // Clear screen (simple approach)
        print!("\x1B[2J\x1B[1;1H");

        println!("{}", "TORC System Monitor".green().bold());
        println!("{}", "=".repeat(40));

        // CPU info
        if let Some(cpu_info) = sys.cpus().first() {
            println!("CPU Usage: {:.1}%", cpu_info.cpu_usage());
        } else {
            println!("CPU Usage: N/A");
        }

        // Memory info
        let used_memory = sys.used_memory();
        let total_memory = sys.total_memory();
        let memory_pct = (used_memory as f64 / total_memory as f64) * 100.0;
        println!("Memory: {:.1}% ({} / {})",
                 memory_pct,
                 bytes_to_human(used_memory),
                 bytes_to_human(total_memory));

        // Load average - sysinfo doesn't have load average on all platforms
        // We'll skip this for now to avoid errors
        // if let Some(load_avg) = sys.load_average() {
        //     println!("Load Avg: {:.2}, {:.2}, {:.2}",
        //              load_avg.one, load_avg.five, load_avg.fifteen);
        // }

        println!("\n{} (Press Ctrl+C to exit)", "Refreshing...".yellow());

        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

fn bytes_to_human(bytes: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < units.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", size, units[unit_index])
}