#!/bin/bash
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root (e.g., sudo $0)" >&2
    exit 1
fi

# 1. Install Docker
if ! command -v docker &>/dev/null; then
    if ! command -v curl &>/dev/null; then
        apt-get update && apt-get install -y curl
    fi
    curl -fsSL https://get.docker.com | sh
    if [ -n "${SUDO_USER:-}" ]; then
        usermod -aG docker "$SUDO_USER"
        echo "Note: '$SUDO_USER' added to docker group. Run 'newgrp docker' or log out and back in to apply."
    fi
fi

# 2. Start the stack
cd "$(dirname "$0")"
docker compose up -d --build
