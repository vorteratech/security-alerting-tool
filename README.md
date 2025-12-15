# Security Alerting Tool

A modular security alerting application for MSPs that processes EDR detections, enriches them with threat intelligence, analyzes with AI, and creates tickets and chat alerts with action buttons.

## Features

- **EDR Integration**: SentinelOne and CrowdStrike Falcon webhook support
- **Threat Intelligence**: VirusTotal and AlienVault OTX enrichment
- **AI Analysis**: Claude, OpenAI GPT, and Google Gemini support
- **Ticketing**: SuperOps PSA integration (auto-creates tickets)
- **Chat Alerts**: Microsoft Teams Bot with Adaptive Cards
- **Action Buttons**: Resolve, Contain, Escalate, Uncontain directly from Teams
- **Security**: AES-256-GCM encryption for API keys (government-compliant)

## How It Works

```
EDR Detection → Webhook → Parse → Enrich → AI Analyze → Create Ticket → Teams Alert
                                                                            ↓
                                                              [Resolve] [Contain] [Escalate]
                                                                            ↓
                                                              Call EDR API → Update Ticket → Notify
```

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
# Build and run in production mode
docker-compose up -d --build

# Or run in development mode with hot reload
docker-compose --profile dev up --build
```

## Running as a System Service (Raspberry Pi / Linux)

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

### Actions (From Teams buttons or API)
```
POST /actions/resolve         # Resolve alert in EDR
POST /actions/contain         # Network isolate endpoint
POST /actions/escalate        # Escalate to senior engineer
POST /actions/uncontain       # Remove network isolation
```

### Teams Bot
```
POST /api/v1/bot/messages     # Teams Bot Framework webhook
GET  /api/v1/bot/messages     # Health check for bot
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

Use the Settings API to configure your integrations. All API keys are encrypted at rest.

### EDR: SentinelOne

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

### EDR: CrowdStrike

```bash
curl -X PUT http://localhost:8000/api/settings/edr/crowdstrike \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "config": {
      "cloud": "us-1",
      "api_url": "auto"
    },
    "api_key": "your-client-id",
    "api_secret": "your-client-secret"
  }'
```

### Threat Intel: VirusTotal

```bash
curl -X PUT http://localhost:8000/api/settings/threat_intel/virustotal \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "api_key": "your-vt-api-key"
  }'
```

### Threat Intel: AlienVault OTX

```bash
curl -X PUT http://localhost:8000/api/settings/threat_intel/alienvault \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "api_key": "your-otx-api-key"
  }'
```

### AI: Claude (Anthropic)

```bash
curl -X PUT http://localhost:8000/api/settings/ai/claude \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "is_primary": true,
    "config": {
      "model": "claude-3-haiku-20240307"
    },
    "api_key": "your-anthropic-api-key"
  }'
```

### AI: OpenAI GPT

```bash
curl -X PUT http://localhost:8000/api/settings/ai/openai \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "config": {
      "model": "gpt-4o-mini"
    },
    "api_key": "your-openai-api-key"
  }'
```

### AI: Google Gemini

```bash
curl -X PUT http://localhost:8000/api/settings/ai/gemini \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "config": {
      "model": "gemini-1.5-flash"
    },
    "api_key": "your-google-api-key"
  }'
```

### PSA: SuperOps

```bash
curl -X PUT http://localhost:8000/api/settings/psa/superops \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "is_primary": true,
    "config": {
      "api_url": "https://api.superops.ai",
      "default_client_id": "your-default-client-id",
      "ticket_type": "incident"
    },
    "api_key": "your-superops-api-key"
  }'
```

### Chat: Microsoft Teams

```bash
curl -X PUT http://localhost:8000/api/settings/chat/teams \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "is_primary": true,
    "config": {
      "tenant_id": "your-azure-tenant-id",
      "default_channel_id": "19:xxx@thread.tacv2"
    },
    "api_key": "your-bot-app-id",
    "api_secret": "your-bot-app-secret"
  }'
```

## Setting Up Microsoft Teams Bot

1. **Register a Bot in Azure:**
   - Go to [Azure Portal](https://portal.azure.com) > Bot Services > Create
   - Choose "Multi Tenant" for Bot Type
   - Note the **App ID** and create a **Client Secret**

2. **Configure Bot Messaging Endpoint:**
   - Set endpoint to: `https://your-public-url/api/v1/bot/messages`

3. **Add to Teams:**
   - In Azure Bot, go to Channels > Teams
   - Download the Teams app manifest or create custom app

4. **Update `.env`:**
   ```bash
   TEAMS_BOT_APP_ID=your-bot-app-id
   TEAMS_BOT_APP_SECRET=your-bot-client-secret
   ACTION_CALLBACK_URL=https://your-public-url/api/v1/actions
   ```

## Setting Up EDR Webhooks

### SentinelOne

1. Go to **Settings > Integrations > Webhooks** in S1 console
2. Create new webhook with URL: `https://your-server/webhooks/sentinelone`
3. Select event types: Threats
4. Copy the webhook secret to `.env` as `S1_WEBHOOK_SECRET`

### CrowdStrike

1. Go to **Support > API Clients and Keys** in Falcon console
2. Create API client with Detection read scope
3. Configure webhook to: `https://your-server/webhooks/crowdstrike`
4. Copy the webhook secret to `.env` as `CS_WEBHOOK_SECRET`

## Exposing to Internet (for Webhooks)

EDR platforms and Teams need to reach your server. Options:

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
│   ├── main.py                 # FastAPI application entry point
│   ├── config/                 # Configuration management
│   │   ├── settings.py         # Pydantic settings
│   │   └── logging.py          # Structured logging
│   ├── database/               # SQLAlchemy models
│   │   ├── models.py           # IntegrationSetting, AuditLog
│   │   └── connection.py       # Async SQLite connection
│   ├── security/               # Encryption module
│   │   └── encryption.py       # AES-256-GCM encryption
│   ├── adapters/               # Integration adapters
│   │   ├── edr/                # SentinelOne, CrowdStrike
│   │   ├── ai/                 # Claude, OpenAI, Gemini
│   │   ├── threat_intel/       # VirusTotal, AlienVault
│   │   ├── psa/                # SuperOps
│   │   └── chat/               # Microsoft Teams
│   ├── services/               # Business logic
│   │   ├── alert_processor.py  # Main pipeline orchestration
│   │   ├── enrichment.py       # Threat intel enrichment
│   │   ├── ai_analyzer.py      # AI analysis service
│   │   ├── psa_service.py      # Ticket management
│   │   ├── notification_service.py  # Chat notifications
│   │   └── alert_formatter.py  # Output formatting
│   └── api/                    # API endpoints
│       ├── webhooks.py         # EDR webhook handlers
│       ├── actions.py          # Action button handlers
│       ├── teams_bot.py        # Teams Bot Framework
│       └── settings_api.py     # Settings CRUD
├── config.yaml                 # Base configuration
├── .env.example                # Environment template
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Multi-stage container build
├── docker-compose.yml          # Docker orchestration
└── run.sh                      # Quick start script
```

## Alert Processing Pipeline

1. **Webhook Received** - EDR sends detection webhook
2. **Parse** - Normalize to common Alert format
3. **Enrich** - Look up hashes/IPs/domains in threat intel
4. **Analyze** - Send to AI for summary and recommendations
5. **Create Ticket** - Auto-create in PSA with all details
6. **Post to Teams** - Send Adaptive Card with action buttons
7. **Action Taken** - User clicks button → API called → EDR action → Ticket updated

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

### Teams Bot not responding
1. Verify your bot messaging endpoint is correct in Azure
2. Check that ACTION_CALLBACK_URL is publicly accessible
3. Review logs for authentication errors

### Webhook signature verification failing
Ensure your webhook secrets in `.env` match what's configured in EDR console.

## Security Notes

- API keys are encrypted with AES-256-GCM using PBKDF2 key derivation
- Master encryption key should be backed up securely
- Webhook signatures are verified (when secret is configured)
- All sensitive data is stored encrypted in SQLite

## License

MIT
