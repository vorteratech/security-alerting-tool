#!/bin/bash
# Security Alerting Tool - Quick Install Script
# For Raspberry Pi / Ubuntu Server / Any Linux with Docker
#
# Usage: curl -fsSL https://raw.githubusercontent.com/vorteratech/security-alerting-tool/main/install.sh | bash

set -e

INSTALL_DIR="${INSTALL_DIR:-$HOME/security-alerting-tool}"
REPO_URL="https://github.com/vorteratech/security-alerting-tool.git"

echo "=========================================="
echo "Security Alerting Tool - Quick Install"
echo "=========================================="
echo ""

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed."
    echo "Install Docker first: curl -fsSL https://get.docker.com | sh"
    exit 1
fi

# Check for Docker Compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "ERROR: Docker Compose is not installed."
    echo "Install with: sudo apt install docker-compose-plugin"
    exit 1
fi

# Check if directory exists
if [ -d "$INSTALL_DIR" ]; then
    echo "Directory $INSTALL_DIR already exists."
    read -p "Update existing installation? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cd "$INSTALL_DIR"
        git pull
    else
        echo "Aborted."
        exit 1
    fi
else
    echo "Cloning to $INSTALL_DIR..."
    git clone "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

echo ""
echo "Building and starting container..."
echo ""

# Use docker compose (v2) or docker-compose (v1)
if docker compose version &> /dev/null; then
    docker compose -f truenas-docker-compose.yml up -d --build
else
    docker-compose -f truenas-docker-compose.yml up -d --build
fi

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "View logs (includes encryption key on first run):"
echo "  docker logs securityalerting"
echo ""
echo "Access the app:"
echo "  Health: http://localhost:8000/health"
echo "  API Docs: http://localhost:8000/docs"
echo ""
echo "Configure integrations via API - see README.md"
echo "=========================================="
