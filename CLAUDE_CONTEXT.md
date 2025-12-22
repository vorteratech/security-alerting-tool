# Security Alerting Tool - Claude Code Context

## Project Overview

MSP Security Alerting Tool that:
1. Receives webhooks from EDR platforms (SentinelOne, CrowdStrike)
2. Enriches alerts with threat intelligence (VirusTotal, AlienVault)
3. Analyzes with AI (Claude, OpenAI, Gemini)
4. Creates tickets in PSA (SuperOps via GraphQL)
5. Sends notifications to chat (Microsoft Teams webhook)

## Tech Stack

- **Framework**: FastAPI (Python 3.11)
- **Database**: SQLite with SQLAlchemy async
- **Deployment**: Docker/TrueNAS via docker-compose
- **Branch**: `claude/security-alerting-tool-adyBx`

## Key Architecture

### Webhook Flow
```
EDR (SentinelOne/CrowdStrike)
    → POST /webhooks/sentinelone or /webhooks/crowdstrike
    → AlertProcessor.process_webhook()
    → Enrich with threat intel
    → Analyze with AI
    → Create PSA ticket (SuperOps GraphQL)
    → Send Teams notification
```

### Authentication (Added This Session)
- Password-based auth with session cookies
- Set via `APP_PASSWORD` environment variable
- Public paths (no auth required): `/webhooks/*`, `/health`, `/login`, `/static/*`
- Sessions expire after 24 hours
- Logout button in settings page header

## Key Files

### Core Application
- `src/main.py` - FastAPI app, middleware, routes
- `src/api/auth.py` - Authentication module (login, logout, sessions)
- `src/api/webhooks.py` - EDR webhook endpoints
- `src/api/settings_api.py` - Settings REST API
- `src/services/alert_processor.py` - Main alert processing pipeline
- `src/services/alert_formatter.py` - Formats tickets and chat cards

### Adapters
- `src/adapters/edr/sentinelone.py` - SentinelOne webhook parsing
- `src/adapters/edr/crowdstrike.py` - CrowdStrike webhook parsing
- `src/adapters/psa/superops.py` - SuperOps GraphQL API (tickets)
- `src/adapters/chat/teams.py` - Teams webhook notifications

### Configuration
- `config.yaml` - Non-sensitive settings
- Environment variables for secrets (see below)

### Templates
- `src/templates/settings.html` - Main settings UI
- `src/templates/login.html` - Login page
- `src/static/css/settings.css` - UI styling

## Environment Variables

```bash
# REQUIRED
MASTER_ENCRYPTION_KEY=<64-char-hex>  # For encrypting stored API keys

# WEB UI AUTH
APP_PASSWORD=<your-password>  # Password to access web UI

# OPTIONAL
S1_WEBHOOK_SECRET=             # SentinelOne webhook verification
CS_WEBHOOK_SECRET=             # CrowdStrike webhook verification
TEAMS_BOT_APP_ID=              # Azure bot app ID (not needed for webhooks)
TEAMS_BOT_APP_SECRET=          # Azure bot secret (not needed for webhooks)
ACTION_CALLBACK_URL=           # URL for Teams action buttons
TZ=UTC                         # Timezone
```

## SuperOps Integration Details

Uses GraphQL API at `https://api.superops.ai/msp`

### Required Headers
```
Authorization: Bearer <api_key>
Content-Type: application/json
CustomerSubDomain: <subdomain>  # e.g., "vendettacd"
```

### CreateTicket Mutation
```graphql
mutation createTicket($input: CreateTicketInput!) {
  createTicket(input: $input) {
    id
    displayId
  }
}
```

Required input fields:
- `subject`: String
- `description`: String (supports HTML)
- `priority`: LOW, MEDIUM, HIGH, CRITICAL
- `source`: "INTEGRATION"
- `requestType`: "INCIDENT"
- `client`: `{ accountId: "<client_id>" }`

### Ticket URL Format
```
https://<subdomain>.superops.ai/#/tickets/<ticket_id>/ticket
```

## Teams Integration

Uses incoming webhook (not bot). Webhook URL configured in Teams channel settings.

### Message Card Format
- Uses MessageCard schema (not Adaptive Cards)
- Sections: Alert Overview, Endpoint, Threat Details, Network, Intel, AI Analysis
- `potentialAction` with `OpenUri` for clickable "View Ticket" button

## TrueNAS Deployment

Docker-compose pulls from GitHub branch, installs deps, runs app:

```yaml
environment:
  - APP_PASSWORD=your-password-here
  - MASTER_ENCRYPTION_KEY=${MASTER_ENCRYPTION_KEY:-}
  - TZ=${TZ:-UTC}
```

The compose file clones the repo, runs `pip install -r requirements.txt`, then starts uvicorn.

## Recent Changes (This Session)

1. **SuperOps ticket HTML formatting** - Tables, sections, emojis
2. **EDR alert links** - Link to SentinelOne/CrowdStrike console in tickets
3. **Teams ticket URL fix** - Correct format: `/#/tickets/{id}/ticket`
4. **Password authentication** - Login page, session cookies, auth middleware
5. **APP_PASSWORD env var** - For TrueNAS deployment
6. **python-multipart dependency** - Required for login form

## Pending/Future Work

1. **SuperOps ticket formatting** - HTML tables have wide spacing in SuperOps UI (CSS not supported, need different approach)
2. **User management** - Add page to create multiple users
3. **Password change** - Allow changing password from UI
4. **Remove Teams bot complexity** - User mentioned webhook-only is fine
5. **Session persistence** - Currently in-memory, could use DB

## Testing

### Manual Webhook Test
```bash
curl -X POST http://localhost:8000/webhooks/sentinelone \
  -H "Content-Type: application/json" \
  -d '{
    "sentinelone": {
      "alert": {
        "id": "test-123",
        "name": "Test Threat",
        "severity": "critical",
        "classification": "Malware",
        "createdAt": "2024-01-01T00:00:00Z"
      },
      "agent": {
        "hostname": "TEST-PC",
        "osType": "windows"
      }
    }
  }'
```

### Test Connections
Use "Test Connections" button in settings UI to verify all integrations.

## Cloudflare Tunnel

App exposed at: `http://iea.vorteratechnologies.com`

Webhooks path (`/webhooks/*`) must bypass Cloudflare Access for EDR platforms to reach it.

## Important Notes

- Webhook endpoints don't require auth (for EDR platforms)
- All API keys stored encrypted in SQLite using MASTER_ENCRYPTION_KEY
- Settings page at `/` or `/settings`
- Health check at `/health`
