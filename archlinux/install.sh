#!/bin/bash
# Installation script for torc on Arch Linux

set -e  # Exit on any error

echo "Installing torc CLI application..."

# Check if Rust is installed
if ! command -v rustc &>/dev/null; then
    echo "Rust is not installed. Installing..."
    sudo pacman -S rust
fi

# Build the application
echo "Building torc..."
cargo build --release

# Install the binary
echo "Installing torc binary to /usr/local/bin..."
sudo install -Dm755 target/release/torc /usr/local/bin/torc

# Create man page directory if it doesn't exist
sudo mkdir -p /usr/local/share/man/man1/

echo "Installation complete!"
echo "Run 'torc --help' to get started."\
