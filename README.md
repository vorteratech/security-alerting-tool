# Security Alerting Tool

A modular security alerting application for MSPs that processes EDR detections, enriches them with threat intelligence, analyzes with AI, and creates tickets and chat alerts.

## Features

- **EDR Integration**: SentinelOne and CrowdStrike Falcon webhook support
- **Threat Intelligence**: VirusTotal and AlienVault enrichment
- **AI Analysis**: Claude, OpenAI GPT, and Google Gemini support
- **Ticketing**: SuperOps PSA integration
- **Chat Alerts**: Microsoft Teams with action buttons
- **Security**: AES-256-GCM encryption for API keys (government-ready)

## Quick Start

### Prerequisites

- Python 3.11 or higher
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/vorteratech/security-alerting-tool.git
cd security-alerting-tool

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

1. **Create environment file:**
   ```bash
   cp .env.example .env
   ```

2. **Generate encryption key:**
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```

3. **Edit `.env` and add your encryption key:**
   ```bash
   MASTER_ENCRYPTION_KEY=<paste-your-64-char-key-here>
   ```

4. **Optional: Edit `config.yaml`** to change server settings:
   ```yaml
   server:
     host: "0.0.0.0"
     port: 8000
     debug: false
   ```

### Running the Application

```bash
# Option 1: Using Python module
python3 -m src.main

# Option 2: Using uvicorn directly
uvicorn src.main:app --host 0.0.0.0 --port 8000

# Option 3: Using the run script
./run.sh
```

The server will start at `http://localhost:8000`

### Verify It's Running

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{"status": "healthy", "version": "0.1.0", "service": "security-alerting-tool"}
```

## Docker Deployment

```bash
# Build and run
docker-compose up --build

# Or run in background
docker-compose up -d --build
```

## Running as a System Service (Linux)

Create `/etc/systemd/system/security-alerting.service`:

```ini
[Unit]
Description=Security Alerting Tool
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/security-alerting-tool
Environment=PATH=/home/pi/security-alerting-tool/venv/bin
EnvironmentFile=/home/pi/security-alerting-tool/.env
ExecStart=/home/pi/security-alerting-tool/venv/bin/uvicorn src.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable security-alerting
sudo systemctl start security-alerting
sudo systemctl status security-alerting
```

## API Endpoints

### Health Check
```
GET /health
```

### Webhooks (Inbound from EDR)
```
POST /webhooks/sentinelone    # SentinelOne alerts
POST /webhooks/crowdstrike    # CrowdStrike alerts
```

### Actions (From Teams buttons)
```
POST /actions/resolve         # Resolve alert in EDR
POST /actions/contain         # Network isolate endpoint
POST /actions/escalate        # Escalate to senior engineer
```

### Settings Management
```
GET    /api/settings                           # List all integrations
GET    /api/settings/{type}/{provider}         # Get specific integration
PUT    /api/settings/{type}/{provider}         # Create/update integration
DELETE /api/settings/{type}/{provider}         # Delete integration
POST   /api/settings/{type}/{provider}/test    # Test connectivity
```

## Configuring Integrations

Use the Settings API to configure your integrations:

### Example: Add SentinelOne

```bash
curl -X PUT http://localhost:8000/api/settings/edr/sentinelone \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "is_primary": true,
    "config": {
      "api_url": "https://usea1.sentinelone.net"
    },
    "api_key": "your-s1-api-key"
  }'
```

### Example: Add VirusTotal

```bash
curl -X PUT http://localhost:8000/api/settings/threat_intel/virustotal \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "api_key": "your-vt-api-key"
  }'
```

## Setting Up EDR Webhooks

### SentinelOne

1. Go to **Settings > Integrations > Webhooks** in S1 console
2. Create new webhook with URL: `https://your-server:8000/webhooks/sentinelone`
3. Select event types: Threats
4. Copy the webhook secret to your `.env` file as `S1_WEBHOOK_SECRET`

### CrowdStrike

1. Go to **Support > API Clients and Keys** in Falcon console
2. Create webhook integration with URL: `https://your-server:8000/webhooks/crowdstrike`
3. Copy the webhook secret to your `.env` file as `CS_WEBHOOK_SECRET`

## Exposing to Internet (for Webhooks)

EDR platforms need to reach your server. Options:

### Option 1: Cloudflare Tunnel (Recommended)
```bash
# Install cloudflared
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64 -o cloudflared
chmod +x cloudflared

# Create tunnel
./cloudflared tunnel login
./cloudflared tunnel create security-alerts
./cloudflared tunnel route dns security-alerts alerts.yourdomain.com
./cloudflared tunnel run security-alerts
```

### Option 2: ngrok (For Testing)
```bash
ngrok http 8000
```

### Option 3: Reverse Proxy with Let's Encrypt
Use nginx with certbot for production deployments.

## Project Structure

```
security-alerting-tool/
├── src/
│   ├── main.py                 # FastAPI application
│   ├── config/                 # Configuration management
│   ├── database/               # SQLAlchemy models
│   ├── security/               # Encryption module
│   ├── adapters/               # Integration adapters
│   │   ├── edr/                # SentinelOne, CrowdStrike
│   │   ├── ai/                 # Claude, OpenAI, Gemini
│   │   ├── threat_intel/       # VirusTotal, AlienVault
│   │   ├── psa/                # SuperOps
│   │   └── chat/               # Microsoft Teams
│   ├── services/               # Business logic
│   └── api/                    # API endpoints
├── tests/                      # Test suite
├── config.yaml                 # Base configuration
├── .env.example                # Environment template
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Container build
└── docker-compose.yml          # Docker orchestration
```

## Development

### Running Tests
```bash
pytest
```

### Running with Auto-reload
```bash
uvicorn src.main:app --reload
```

## Troubleshooting

### "MASTER_ENCRYPTION_KEY not set"
Generate and add the key to your `.env` file:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### "Database not initialized"
The database auto-creates on first run. Ensure the `data/` directory is writable:
```bash
mkdir -p data
chmod 755 data
```

### Port already in use
Change the port in `config.yaml` or use:
```bash
uvicorn src.main:app --port 8080
```

## License

MIT
