#!/bin/bash
# Installation script for torc on Arch Linux

set -e  # Exit on any error

echo "Installing torc CLI application and dependencies..."

# Update package database
echo "Updating package database..."
sudo pacman -Sy

# Check if Rust is installed
if ! command -v rustc &>/dev/null; then
    echo "Rust is not installed. Installing..."
    sudo pacman -S --noconfirm rust
else
    echo "Rust is already installed."
fi

# Install Tor and related packages
if ! command -v tor &>/dev/null; then
    echo "Installing Tor..."
    sudo pacman -S --noconfirm tor
else
    echo "Tor is already installed."
fi

# Install additional packages that may be needed for network configuration
echo "Installing additional dependencies..."
if ! command -v iptables &>/dev/null; then
    sudo pacman -S --noconfirm iptables
fi

if ! command -v ip &>/dev/null; then
    sudo pacman -S --noconfirm iproute2
fi

if ! command -v route &>/dev/null; then
    # route command is part of net-tools
    if ! pacman -Q net-tools &>/dev/null; then
        sudo pacman -S --noconfirm net-tools
    fi
fi

# Install dig command for DNS diagnostics
if ! command -v dig &>/dev/null; then
    if ! pacman -Q dnsutils &>/dev/null; then
        sudo pacman -S --noconfirm dnsutils
    fi
fi

# Install other potential dependencies
for pkg in which procps-ng; do
    if ! pacman -Q "$pkg" &>/dev/null; then
        sudo pacman -S --noconfirm "$pkg"
    fi
done

# Build the application
echo "Building torc..."
cargo build --release

# Install the binary
echo "Installing torc binary to /usr/local/bin..."
sudo install -Dm755 target/release/torc /usr/local/bin/torc

# Create necessary directories for tor service
sudo mkdir -p /etc/tor
sudo chown -R root:root /etc/tor

# Enable and start Tor service (but don't start it by default)
echo "Configuring Tor service..."
sudo systemctl enable tor.service

# Create man page directory if it doesn't exist
sudo mkdir -p /usr/local/share/man/man1/

echo "Installation complete!"
echo ""
echo "Before using torc, please:"
echo "1. Review and customize your Tor configuration in /etc/tor/torrc if needed"
echo "2. Run 'torc --help' to get started"
echo ""
echo "Note: The application is still under development and should not be used until marked as ready for testing."
