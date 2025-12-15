# TrueNAS SCALE - One-Click Deploy

## Quick Start (Copy & Paste)

**Option A: Via TrueNAS Shell**
```bash
curl -sL https://raw.githubusercontent.com/vorteratech/security-alerting-tool/main/truenas-docker-compose.yml | docker-compose -f - up -d
```

**Option B: Via Portainer/Dockge**
1. Create new Stack
2. Paste contents of `truenas-docker-compose.yml`
3. Deploy

**Option C: Manual**
```bash
# Download compose file
curl -O https://raw.githubusercontent.com/vorteratech/security-alerting-tool/main/truenas-docker-compose.yml

# Run it
docker-compose -f truenas-docker-compose.yml up -d
```

## What Happens Automatically

1. Downloads Python 3.11 image
2. Clones the Security Alerting Tool repo
3. Installs all dependencies
4. Generates encryption key (saved to volume)
5. Creates config files
6. Starts the server on port 8000

## First Run

Check the logs to see your auto-generated encryption key:
```bash
docker logs security-alerting-tool
```

Look for:
```
==========================================
NEW ENCRYPTION KEY GENERATED!
==========================================
Key: abc123...your-key-here...
==========================================
```

**Save this key!** If you ever recreate the container, add it to your compose file.

## Verify It's Running

```bash
curl http://YOUR_TRUENAS_IP:8000/health
```

Or open in browser: `http://YOUR_TRUENAS_IP:8000/docs`

## Configure Your Integrations

Once running, add your API keys via the Settings API:

### Add SentinelOne
```bash
curl -X PUT http://YOUR_TRUENAS_IP:8000/api/settings/edr/sentinelone \
  -H "Content-Type: application/json" \
  -d '{"enabled":true,"is_primary":true,"config":{"api_url":"https://usea1.sentinelone.net"},"api_key":"YOUR_S1_KEY"}'
```

### Add VirusTotal
```bash
curl -X PUT http://YOUR_TRUENAS_IP:8000/api/settings/threat_intel/virustotal \
  -H "Content-Type: application/json" \
  -d '{"enabled":true,"api_key":"YOUR_VT_KEY"}'
```

### Add Claude AI
```bash
curl -X PUT http://YOUR_TRUENAS_IP:8000/api/settings/ai/claude \
  -H "Content-Type: application/json" \
  -d '{"enabled":true,"is_primary":true,"api_key":"YOUR_ANTHROPIC_KEY"}'
```

### Add SuperOps
```bash
curl -X PUT http://YOUR_TRUENAS_IP:8000/api/settings/psa/superops \
  -H "Content-Type: application/json" \
  -d '{"enabled":true,"is_primary":true,"config":{"api_url":"https://api.superops.ai"},"api_key":"YOUR_SUPEROPS_KEY"}'
```

## Expose to Internet (Required for Webhooks)

EDR platforms need to reach your server. Easiest option:

### Cloudflare Tunnel
```bash
docker run -d --name cloudflared --restart unless-stopped \
  cloudflare/cloudflared:latest tunnel --no-autoupdate run --token YOUR_TUNNEL_TOKEN
```

Then update your compose with:
```yaml
- ACTION_CALLBACK_URL=https://alerts.yourdomain.com/api/v1/actions
```

## Updating

```bash
docker-compose -f truenas-docker-compose.yml down
docker-compose -f truenas-docker-compose.yml pull
docker-compose -f truenas-docker-compose.yml up -d
```

## Troubleshooting

**Container keeps restarting?**
```bash
docker logs security-alerting-tool
```

**Can't clone repo?**
- Check TrueNAS has internet access
- Firewall allowing GitHub access

**Port 8000 in use?**
- Edit compose file: change `"8000:8000"` to `"8080:8000"`
