#!/bin/bash
# Security Alerting Tool - Run Script
#
# Usage: ./run.sh [--dev]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Security Alerting Tool${NC}"
echo "========================"

# Check for .env file
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}Warning: .env file not found${NC}"
    echo "Creating from template..."
    cp .env.example .env
    echo -e "${RED}Please edit .env and add your MASTER_ENCRYPTION_KEY${NC}"
    echo "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
    exit 1
fi

# Check if MASTER_ENCRYPTION_KEY is set
if ! grep -q "^MASTER_ENCRYPTION_KEY=.\+" .env; then
    echo -e "${RED}Error: MASTER_ENCRYPTION_KEY not set in .env${NC}"
    echo "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
    exit 1
fi

# Check for virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install/update dependencies
echo "Checking dependencies..."
pip install -q -r requirements.txt

# Create data directory if needed
mkdir -p data

# Run the application
if [ "$1" == "--dev" ]; then
    echo -e "${GREEN}Starting in development mode (auto-reload)...${NC}"
    exec uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
else
    echo -e "${GREEN}Starting server...${NC}"
    exec uvicorn src.main:app --host 0.0.0.0 --port 8000
fi
