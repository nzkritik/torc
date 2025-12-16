# TORC - Tor Network Connector

⚠️ **UNDER DEVELOPMENT - NOT READY FOR USE** ⚠️

**This application is currently under development and contains known issues. DO NOT use this software until it is explicitly marked as ready for testing. The current implementation does not properly route system traffic through Tor, meaning your IP address may not be hidden despite status messages indicating a connection.**

```
▄▄▄▄▄▄▄▄▄   ▄▄▄▄▄   ▄▄▄▄▄▄▄    ▄▄▄▄▄▄▄
▀▀▀███▀▀▀ ▄███████▄ ███▀▀███▄ ███▀▀▀▀▀
   ███    ███   ███ ███▄▄███▀ ███
   ███    ███▄▄▄███ ███▀▀██▄  ███
   ███     ▀█████▀  ███  ▀███ ▀███████

```

TORC is a Rust CLI application that allows you to safely connect your system to the Tor network for anonymous browsing. The application provides a simple menu-driven interface to connect, disconnect, and check the status of your Tor connection.

## Features

- **Connect to Tor**: Route all web traffic through the Tor network for anonymity
- **Disconnect from Tor**: Restore your regular internet connection
- **Check Status**: View current connection status and Tor configuration
- **System Integration**: Designed for easy use on Linux systems, especially Arch Linux

## Installation

### Prerequisites

- Rust (latest stable version recommended)
- Tor must be installed on your system
  - On Arch Linux: `sudo pacman -S tor`
  - On Ubuntu/Debian: `sudo apt install tor`

### Automatic Installation

The repository includes platform-specific installation scripts:

- For Arch-based distributions: Use `archlinux/install.sh`
- For Debian-based distributions: Use `debian/install.sh`

Run the appropriate script to automatically install all dependencies and build the application:

```bash
# For Arch-based systems
./archlinux/install.sh

# For Debian-based systems
./debian/install.sh
```

### Building from Source (Manual)

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
# Run the Tor connector
torc
```

This will open an interactive menu with the following options:
1. Connect to Tor Network
2. Disconnect from Tor Network
3. Check Tor Status
4. Exit

## How It Works

TORC works by managing the Tor service on your system. When you connect:
- The system's Tor daemon is started
- Traffic is routed through the Tor network
- Your IP address is hidden and traffic is anonymized

When you disconnect:
- The Tor service is stopped
- Regular internet routing is restored

## Dependencies

- `colored`: For colored terminal output
- `anyhow`: For error handling

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security Notice

- Tor provides anonymity by routing traffic through multiple nodes
- Tor may slow down your connection significantly
- Some websites block Tor users
- Always practice safe browsing habits even when using Tor

## License

This project is dual licensed under either:

- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.

## Target Platforms

Currently targeting Arch-based and Debian-based Linux distributions with plans to expand to other major Linux distributions.

## TODO List

### Core Functionality
- [ ] Implement actual system-wide traffic routing through Tor (currently only starts Tor service)
- [ ] Configure iptables rules to redirect all traffic through Tor SOCKS proxy
- [ ] Implement proper DNS leak protection
- [ ] Add connection status verification that checks if traffic is actually routed through Tor
- [ ] Implement circuit monitoring to show active Tor circuits
- [ ] Add proxy authentication support if needed

### Security & Privacy
- [ ] Implement proper cleanup of DNS cache on connection/disconnection
- [ ] Add support for Tor Browser integration
- [ ] Implement MAC address spoofing for additional anonymity
- [ ] Add detection for Tor blocking/interference
- [ ] Implement anti-fingerprinting measures

### System Integration
- [ ] Create proper systemd service for the application itself
- [ ] Add integration with NetworkManager for better network management
- [ ] Implement automatic restart on system boot (when configured)
- [ ] Add support for multiple Tor configurations/profiles
- [x] Implement proper logging system

### Backup & Restore System
- [x] Implement actual network configuration restoration (currently uses placeholder functions)
- [x] Add backup of routing table with `ip route` commands
- [x] Add backup of DNS configuration in `/etc/resolv.conf`
- [x] Add backup of firewall rules with `iptables` commands
- [x] Add backup of network interface states
- [x] Implement restore functionality for all backed up configurations

### Platform Support
- [ ] Add support for other major Linux distributions (Fedora, openSUSE, etc.)
- [ ] Create installation scripts for other package managers (dnf, zypper, etc.)
- [ ] Add macOS support (requires significant architecture changes)
- [ ] Add support for containerized environments

### User Experience
- [ ] Implement bandwidth monitoring
- [ ] Add configuration file support for custom settings
- [ ] Create desktop notification system for connection status changes
- [ ] Add support for selecting specific Tor circuits or exit nodes
- [ ] Implement kill switch functionality to block all traffic if Tor connection drops
- [x] Add system information display to main menu (OS, Host, Kernel)

### Testing & Quality
- [ ] Add comprehensive unit tests for all functionality
- [ ] Create integration tests for the network configuration changes
- [ ] Implement automated testing for different Linux distributions
- [ ] Add performance monitoring and benchmarking
- [ ] Create security testing framework