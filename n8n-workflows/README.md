# n8n Security Alert Workflow

This workflow processes security alerts from EDR platforms, enriches them with threat intelligence, analyzes them with AI, creates tickets, and sends Teams notifications.

## Workflow Overview

```
Webhook → Detect EDR → Parse Alert → Extract IOCs → Parallel Enrichment → AI Analysis → Create Ticket → Teams Notification
```

## Import Instructions

1. Open your n8n instance
2. Go to **Workflows** → **Import from File**
3. Select `security-alert-workflow.json`
4. The workflow will appear in your canvas

## Required Credentials

You need to create the following credentials in n8n before the workflow will function:

### 1. VirusTotal API
- **Type:** Header Auth
- **Name:** `VirusTotal API`
- **Header Name:** `x-apikey`
- **Header Value:** Your VirusTotal API key
- Get a free key at: https://www.virustotal.com/gui/join-us

### 2. AlienVault API
- **Type:** Header Auth
- **Name:** `AlienVault API`
- **Header Name:** `X-OTX-API-KEY`
- **Header Value:** Your AlienVault OTX API key
- Get a free key at: https://otx.alienvault.com/api

### 3. Anthropic API (Claude)
- **Type:** Header Auth
- **Name:** `Anthropic API`
- **Header Name:** `x-api-key`
- **Header Value:** Your Anthropic API key
- Get a key at: https://console.anthropic.com/

### 4. SuperOps API
- **Type:** Header Auth
- **Name:** `SuperOps API`
- **Header Name:** `Authorization`
- **Header Value:** `Bearer YOUR_SUPEROPS_TOKEN`
- Note: Also requires `CustomerSubDomain` header (configure in the node)

### 5. Microsoft Teams
- **Type:** Microsoft Teams OAuth2
- **Name:** `Microsoft Teams`
- Follow n8n's OAuth2 setup for Teams

## Webhook Configuration

After importing, your webhook URL will be:
```
https://your-n8n-instance.com/webhook/security-alert
```

### SentinelOne Setup
1. Go to SentinelOne Console → Settings → Notifications
2. Add a new webhook with your n8n webhook URL
3. Select threat events to forward

### CrowdStrike Setup
1. Go to Falcon Console → Support → API Clients & Keys
2. Create a Streaming API client or use SIEM Connector
3. Configure to forward to your n8n webhook URL

## Nodes Explained

| Node | Purpose |
|------|---------|
| **Webhook Trigger** | Receives incoming EDR alerts |
| **Detect EDR Source** | Routes to correct parser based on payload structure |
| **Parse SentinelOne/CrowdStrike** | Normalizes vendor-specific format to common schema |
| **Extract IOCs** | Pulls out hashes, IPs, domains for enrichment |
| **VirusTotal/AlienVault Lookups** | Parallel threat intel queries |
| **Merge Enrichment Results** | Combines all TI data with threat scoring |
| **Claude AI Analysis** | Security analyst prompt for recommendations |
| **Parse AI Response** | Extracts structured analysis from Claude |
| **Create SuperOps Ticket** | Opens incident ticket via GraphQL |
| **Prepare Teams Message** | Formats data for Adaptive Card |
| **Send Teams Notification** | Posts rich card to channel |

## Customization

### Change AI Model
Edit the **Claude AI Analysis** node and modify the `model` field:
- `claude-3-haiku-20240307` - Fast, cost-effective (default)
- `claude-3-sonnet-20240229` - Balanced
- `claude-3-opus-20240229` - Most capable

### Adjust Severity Colors
Edit the **Prepare Teams Message** node to customize the color mapping.

### Add More Threat Intel
Duplicate an existing HTTP Request node and connect it to the Extract IOCs output. Make sure to update the Merge Enrichment Results code to process the new source.

## Testing

1. Activate the workflow
2. Use a tool like `curl` or Postman to send a test payload:

```bash
# Test SentinelOne format
curl -X POST https://your-n8n-instance.com/webhook/security-alert \
  -H "Content-Type: application/json" \
  -d '{
    "threatInfo": {
      "threatId": "test-123",
      "threatName": "Test Malware",
      "classification": "Malware",
      "confidenceLevel": "malicious",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    "agentRealtimeInfo": {
      "agentComputerName": "WORKSTATION-01",
      "agentIpAddress": "192.168.1.100",
      "siteName": "Default Site"
    }
  }'
```

## Troubleshooting

### Workflow not triggering
- Ensure the workflow is **Active** (toggle in top right)
- Check the webhook URL is correct
- Verify n8n is accessible from your EDR platform

### API errors
- Check credentials are correctly configured
- Verify API keys have not expired
- Check rate limits (VirusTotal free tier: 4 req/min)

### Teams message not sending
- Verify OAuth2 credentials are valid
- Check the channel/chat ID in the Teams node
- Ensure the bot has permissions to post

## Rate Limits

| Service | Free Tier Limit |
|---------|-----------------|
| VirusTotal | 4 requests/minute, 500/day |
| AlienVault | No published limit |
| Claude | Based on your plan |
| SuperOps | Based on your plan |
