#!/bin/bash
# Update script for torc: pulls the latest changes from git, builds a
# release binary, and installs it to /usr/local/bin.

set -e  # Exit on any error

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_PATH="/usr/local/bin/torc"

cd "$REPO_DIR"

if [ ! -d .git ]; then
    echo "Error: $REPO_DIR is not a git repository." >&2
    exit 1
fi

BRANCH="$(git rev-parse --abbrev-ref HEAD)"

if [ -n "$(git status --porcelain)" ]; then
    echo "Error: working tree has uncommitted changes." >&2
    echo "Commit, stash, or discard them before updating." >&2
    exit 1
fi

echo "Fetching latest changes for branch '$BRANCH'..."
git fetch origin "$BRANCH"

LOCAL_REV="$(git rev-parse HEAD)"
REMOTE_REV="$(git rev-parse "origin/$BRANCH")"

if [ "$LOCAL_REV" = "$REMOTE_REV" ]; then
    echo "Already up to date ($LOCAL_REV)."
else
    echo "Pulling changes..."
    git pull --ff-only origin "$BRANCH"
fi

if ! command -v cargo &>/dev/null; then
    echo "Error: cargo is not installed. Install Rust first (see archlinux/install.sh or debian/install.sh)." >&2
    exit 1
fi

echo "Building torc (release)..."
cargo build --release

echo "Installing torc binary to $INSTALL_PATH..."
sudo install -Dm755 target/release/torc "$INSTALL_PATH"

echo ""
echo "Update complete!"
"$INSTALL_PATH" --version || true
