#!/bin/bash
# Installation script for torc on Debian-based Linux distributions

set -e  # Exit on any error

echo "Installing torc CLI application and dependencies..."

# Update package database
echo "Updating package database..."
sudo apt update

# Install Rust if not present
if ! command -v rustc &>/dev/null; then
    echo "Rust is not installed. Installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # Reload environment to get access to Rust commands
    source ~/.cargo/env
else
    echo "Rust is already installed."
fi

# Install Tor and related packages
if ! command -v tor &>/dev/null; then
    echo "Installing Tor..."
    sudo apt install -y tor
else
    echo "Tor is already installed."
fi

# Install additional packages that may be needed for network configuration
echo "Installing additional dependencies..."
for pkg in iptables iproute2 net-tools which procps; do
    if ! dpkg -l | grep -q "^ii  $pkg "; then
        sudo apt install -y "$pkg"
    fi
done

# Build the application
echo "Building torc..."
source ~/.cargo/env  # Ensure cargo is available
cargo build --release

# Install the binary
echo "Installing torc binary to /usr/local/bin..."
sudo install -Dm755 target/release/torc /usr/local/bin/torc

# Create necessary directories for tor service
sudo mkdir -p /etc/tor
sudo chown -R root:root /etc/tor

# Enable Tor service (but dont start it by default)
echo "Configuring Tor service..."
sudo systemctl enable tor.service

# Create man page directory if it doesnt exist
sudo mkdir -p /usr/local/share/man/man1/

echo "Installation complete!"
echo ""
echo "Before using torc, please:"
echo "1. Review and customize your Tor configuration in /etc/tor/torrc if needed"
echo "2. Run torc --help to get started"
echo ""
echo "Note: The application is still under development and should not be used until marked as ready for testing."

