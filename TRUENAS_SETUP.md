# TrueNAS SCALE Deployment Guide

This guide covers deploying the Security Alerting Tool on TrueNAS SCALE.

## Prerequisites

- TrueNAS SCALE 22.12 or later
- A dataset for app data (e.g., `pool/appdata`)
- Docker/Apps enabled in TrueNAS

## Option 1: Using TrueNAS Custom App (Recommended)

### Step 1: Create Storage Dataset

```bash
# In TrueNAS Shell or via UI
# Create dataset: pool/appdata/security-alerting
# Create subdirectories:
mkdir -p /mnt/pool/appdata/security-alerting/data
```

### Step 2: Create Config File

```bash
# Create config.yaml
cat > /mnt/pool/appdata/security-alerting/config.yaml << 'EOF'
server:
  host: "0.0.0.0"
  port: 8000
  debug: false

logging:
  level: INFO
  format: json

database:
  path: /app/data/settings.db

security:
  verify_webhooks: true

defaults:
  ai_provider: claude
  threat_intel_providers:
    - virustotal
    - alienvault
EOF
```

### Step 3: Create Environment File

```bash
# Generate encryption key
python3 -c "import secrets; print(secrets.token_hex(32))"

# Create .env file
cat > /mnt/pool/appdata/security-alerting/.env << 'EOF'
# Paste your generated key here
MASTER_ENCRYPTION_KEY=your-64-character-hex-key-here

# EDR Webhook Secrets (get from S1/CS console)
S1_WEBHOOK_SECRET=
CS_WEBHOOK_SECRET=

# Teams Bot (from Azure)
TEAMS_BOT_APP_ID=
TEAMS_BOT_APP_SECRET=

# Your public URL (use your domain or Cloudflare Tunnel)
ACTION_CALLBACK_URL=https://alerts.yourdomain.com/api/v1/actions

# Timezone
TZ=America/New_York
EOF
```

### Step 4: Deploy via TrueNAS UI

1. Go to **Apps** → **Discover Apps** → **Custom App**
2. Fill in:
   - **Application Name**: `security-alerting`
   - **Image Repository**: `python`
   - **Image Tag**: `3.11-slim`
3. Or use **Launch Docker Image** with these settings:
   - **Image**: Build from repo or use pre-built image
   - **Port**: 8000 → 8000
   - **Environment Variables**: Add all from .env
   - **Host Path Volumes**:
     - `/mnt/pool/appdata/security-alerting/data` → `/app/data`
     - `/mnt/pool/appdata/security-alerting/config.yaml` → `/app/config.yaml`

## Option 2: Using Portainer/Dockge (If Installed)

If you have Portainer or Dockge on TrueNAS:

1. Copy `truenas-docker-compose.yml` to your TrueNAS
2. Create stack in Portainer/Dockge
3. Set environment variables
4. Deploy

## Option 3: Command Line Deployment

```bash
# SSH into TrueNAS

# Clone repo
cd /mnt/pool/appdata
git clone https://github.com/vorteratech/security-alerting-tool.git
cd security-alerting-tool

# Copy and edit env file
cp .env.example .env
nano .env  # Add your keys

# Create data directory
mkdir -p data

# Build and run
docker-compose -f truenas-docker-compose.yml up -d
```

## Option 4: TrueCharts Custom App (Advanced)

If using TrueCharts catalog:

1. Add custom app template
2. Use the Helm values below

```yaml
# values.yaml for TrueCharts
image:
  repository: ghcr.io/vorteratech/security-alerting-tool
  tag: latest
  pullPolicy: IfNotPresent

service:
  main:
    ports:
      main:
        port: 8000
        targetPort: 8000

persistence:
  data:
    enabled: true
    mountPath: /app/data
    type: pvc
    size: 1Gi
  config:
    enabled: true
    mountPath: /app/config.yaml
    type: configMap

env:
  MASTER_ENCRYPTION_KEY:
    secretKeyRef:
      name: security-alerting-secrets
      key: encryption-key
  TZ: America/New_York
```

## Exposing to Internet

For EDR webhooks and Teams to reach your server:

### Cloudflare Tunnel (Recommended)

```bash
# Install cloudflared on TrueNAS
# Or run as separate container

docker run -d \
  --name cloudflared \
  --restart unless-stopped \
  cloudflare/cloudflared:latest \
  tunnel --no-autoupdate run --token YOUR_TUNNEL_TOKEN
```

### Reverse Proxy with Traefik

If using Traefik on TrueNAS:

```yaml
# Add labels to container
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.security-alerting.rule=Host(`alerts.yourdomain.com`)"
  - "traefik.http.routers.security-alerting.entrypoints=websecure"
  - "traefik.http.routers.security-alerting.tls.certresolver=letsencrypt"
  - "traefik.http.services.security-alerting.loadbalancer.server.port=8000"
```

## Verify Deployment

```bash
# Check container status
docker ps | grep security-alerting

# Check logs
docker logs security-alerting-tool

# Test health endpoint
curl http://YOUR_TRUENAS_IP:8000/health
```

## Configure Integrations

Once running, use curl or a tool like Postman to configure:

```bash
# Example: Add SentinelOne
curl -X PUT http://YOUR_TRUENAS_IP:8000/api/settings/edr/sentinelone \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "is_primary": true,
    "config": {"api_url": "https://usea1.sentinelone.net"},
    "api_key": "your-api-key"
  }'
```

## Updating

```bash
# Pull latest and restart
cd /mnt/pool/appdata/security-alerting-tool
git pull
docker-compose -f truenas-docker-compose.yml down
docker-compose -f truenas-docker-compose.yml up -d --build
```

## Troubleshooting

### Container won't start
- Check logs: `docker logs security-alerting-tool`
- Verify MASTER_ENCRYPTION_KEY is set (64 hex characters)
- Ensure data directory is writable

### Can't access from network
- Check TrueNAS firewall rules
- Verify port 8000 is mapped correctly
- Try host network mode if bridge doesn't work

### Database errors
- Ensure `/app/data` volume is mounted correctly
- Check permissions on mounted directory
