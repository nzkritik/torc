# TORC - A Rust CLI Application for Linux

TORC is a comprehensive command-line interface application built in Rust, specifically designed for Linux systems with initial focus on Arch Linux.

## Features

- **System Information**: View detailed system information including OS, kernel, uptime, CPU count, memory usage, etc.
- **Package Management**: Interface with package managers (specifically designed for Arch Linux's pacman)
- **Disk Monitoring**: Check disk usage across all mounted drives with human-readable output
- **System Monitoring**: Real-time monitoring of CPU, memory, and load averages

## Installation

### Prerequisites

- Rust (latest stable version recommended)
- On Arch Linux: `sudo pacman -S rust`

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/torc.git
cd torc

# Build the application
cargo build --release

# Install globally (optional)
cargo install --path .
```

## Usage

```bash
# Show system information
torc system

# Show detailed system information
torc system --detail

# Manage packages (Arch Linux specific)
torc package install package_name
torc package remove package_name  
torc package update
torc package search package_name
torc package list

# Show disk usage
torc disk
torc disk --human  # Human-readable format

# Monitor system resources in real-time
torc monitor

# Enable verbose output
torc --verbose system
```

## Commands

### System Information
```bash
torc system [OPTIONS]
```
Display system information with optional detailed view.

Options:
- `-d, --detail`: Show detailed system information

### Package Management
```bash
torc package [ACTION] [PACKAGES]...
```
Manage system packages with pacman integration.

Actions:
- `install`: Install packages
- `remove`: Remove packages
- `update`: Update the system
- `search`: Search for packages
- `list`: List installed packages

### Disk Usage
```bash
torc disk [OPTIONS]
```
Show disk usage information.

Options:
- `-h, --human`: Display sizes in human-readable format

### System Monitor
```bash
torc monitor
```
Run real-time system resource monitor.

## Dependencies

- `clap`: For command-line argument parsing
- `sysinfo`: For system information retrieval
- `colored`: For colored terminal output
- `anyhow`: For error handling

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is dual licensed under either:

- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.

## Target Platforms

Initially targeting Arch Linux with plans to expand to other major Linux distributions.