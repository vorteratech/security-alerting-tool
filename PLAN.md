# Security Alerting Tool - Implementation Plan

## Overview

A modular security alerting application for MSPs that:
1. Receives real-time detections from EDR platforms via webhooks
2. Enriches alerts with threat intelligence
3. Uses AI to analyze and provide recommendations
4. Creates tickets in PSA platforms
5. Posts alerts to chat platforms with action buttons

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SECURITY ALERTING TOOL                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐     ┌──────────────────────────────────────────────────┐  │
│  │   INBOUND    │     │              PROCESSING PIPELINE                 │  │
│  │              │     │                                                  │  │
│  │ ┌──────────┐ │     │  ┌─────────┐   ┌─────────┐   ┌───────────────┐  │  │
│  │ │SentinelOne│─┼────▶│  │ Parse & │──▶│ Enrich  │──▶│  AI Analysis  │  │  │
│  │ │ Webhook  │ │     │  │ Normalize│   │ (Threat │   │ (Claude/GPT/  │  │  │
│  │ └──────────┘ │     │  │         │   │  Intel) │   │   Gemini)     │  │  │
│  │              │     │  └─────────┘   └─────────┘   └───────────────┘  │  │
│  │ ┌──────────┐ │     │       │             │               │           │  │
│  │ │CrowdStrike│ │     │       │      ┌─────┴─────┐         │           │  │
│  │ │ (future) │ │     │       │      │VirusTotal │         │           │  │
│  │ └──────────┘ │     │       │      │AlienVault │         │           │  │
│  │              │     │       │      └───────────┘         │           │  │
│  └──────────────┘     │       └─────────────────────────────┘           │  │
│                       └──────────────────────────────────────────────────┘  │
│                                           │                                  │
│                                           ▼                                  │
│                       ┌──────────────────────────────────────────────────┐  │
│                       │                  OUTBOUND                         │  │
│                       │                                                   │  │
│                       │  ┌─────────────┐          ┌─────────────────┐    │  │
│                       │  │   SuperOps  │          │  Microsoft Teams │    │  │
│                       │  │   (Ticket)  │          │  (Alert + Buttons│    │  │
│                       │  └─────────────┘          └─────────────────┘    │  │
│                       │                                                   │  │
│                       │  ┌─────────────┐          ┌─────────────────┐    │  │
│                       │  │ ConnectWise │          │      Slack      │    │  │
│                       │  │  (future)   │          │    (future)     │    │  │
│                       │  └─────────────┘          └─────────────────┘    │  │
│                       └──────────────────────────────────────────────────┘  │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                              CONFIGURATION                                   │
│                                                                              │
│  ┌─────────────────┐    ┌─────────────────────────────────────────────┐    │
│  │   config.yaml   │    │              SQLite Database                 │    │
│  │  (base settings)│    │  - API Keys (encrypted)                     │    │
│  │  - Server port  │    │  - Integration settings                     │    │
│  │  - Log level    │    │  - Alert history                            │    │
│  │  - DB path      │    │  - Action audit log                         │    │
│  └─────────────────┘    └─────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
security-alerting-tool/
├── src/
│   ├── __init__.py
│   ├── main.py                     # FastAPI application entry point
│   │
│   ├── config/
│   │   ├── __init__.py
│   │   ├── settings.py             # Settings management (YAML + DB)
│   │   └── logging.py              # Logging configuration
│   │
│   ├── database/
│   │   ├── __init__.py
│   │   ├── connection.py           # Database connection management
│   │   └── models.py               # SQLAlchemy models
│   │
│   ├── adapters/                   # Plugin architecture for integrations
│   │   ├── __init__.py
│   │   │
│   │   ├── edr/                    # EDR platform adapters
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # Abstract base class
│   │   │   └── sentinelone.py      # SentinelOne implementation
│   │   │
│   │   ├── ai/                     # AI provider adapters
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # Abstract base class
│   │   │   ├── claude.py           # Anthropic Claude
│   │   │   ├── openai.py           # OpenAI GPT
│   │   │   └── gemini.py           # Google Gemini
│   │   │
│   │   ├── threat_intel/           # Threat intelligence adapters
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # Abstract base class
│   │   │   ├── virustotal.py       # VirusTotal
│   │   │   └── alienvault.py       # AlienVault OTX
│   │   │
│   │   ├── psa/                    # PSA/Ticketing adapters
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # Abstract base class
│   │   │   └── superops.py         # SuperOps implementation
│   │   │
│   │   └── chat/                   # Chat platform adapters
│   │       ├── __init__.py
│   │       ├── base.py             # Abstract base class
│   │       └── teams.py            # Microsoft Teams (Adaptive Cards)
│   │
│   ├── services/                   # Business logic
│   │   ├── __init__.py
│   │   ├── alert_processor.py      # Main orchestration service
│   │   ├── enrichment.py           # Threat intelligence enrichment
│   │   └── formatter.py            # Alert formatting for output
│   │
│   └── api/                        # API endpoints
│       ├── __init__.py
│       ├── webhooks.py             # Inbound webhook endpoints
│       ├── actions.py              # Action button callbacks
│       └── settings_api.py         # Settings management API
│
├── tests/                          # Test suite
│   ├── __init__.py
│   ├── conftest.py                 # Pytest fixtures
│   ├── test_webhooks.py
│   ├── test_enrichment.py
│   └── adapters/
│       └── ...
│
├── config.yaml                     # Base configuration file
├── requirements.txt                # Python dependencies
├── Dockerfile                      # Container definition
├── docker-compose.yml              # Local development setup
├── .env.example                    # Environment variables template
└── README.md                       # Documentation
```

---

## Data Models

### Alert (Normalized)

```python
class Alert:
    id: str                         # Unique identifier
    source: str                     # EDR source (e.g., "sentinelone")
    source_alert_id: str            # Original alert ID from EDR
    timestamp: datetime             # When alert occurred
    severity: str                   # critical, high, medium, low, info

    # Endpoint info
    hostname: str
    endpoint_ip: str
    endpoint_os: str
    endpoint_user: str

    # Threat info
    threat_name: str
    threat_classification: str      # malware, ransomware, pup, etc.
    file_path: str
    file_hash_sha256: str
    file_hash_sha1: str
    file_hash_md5: str
    process_name: str
    command_line: str

    # Network indicators (if applicable)
    remote_ip: str
    remote_domain: str
    remote_port: int

    # Enrichment data (populated after processing)
    enrichment: dict                # VirusTotal, AlienVault results
    ai_analysis: dict               # AI-generated analysis

    # Status tracking
    status: str                     # new, processing, ticketed, resolved
    ticket_id: str                  # PSA ticket ID
    created_at: datetime
    updated_at: datetime
```

### Integration Settings (Database)

```python
class IntegrationSetting:
    id: int
    integration_type: str           # edr, ai, threat_intel, psa, chat
    provider: str                   # sentinelone, claude, virustotal, etc.
    enabled: bool
    config: dict                    # Provider-specific configuration
    api_key_encrypted: str          # Encrypted API key
    created_at: datetime
    updated_at: datetime
```

---

## Implementation Phases

### Phase 1: Foundation (Core Infrastructure)
1. Project setup (dependencies, structure)
2. Configuration management (YAML + environment variables)
3. Database setup (SQLite with SQLAlchemy)
4. FastAPI application skeleton
5. Logging infrastructure
6. Base adapter classes (abstract interfaces)

### Phase 2: EDR Integration
1. SentinelOne webhook endpoint
2. S1 payload parsing and normalization
3. Webhook signature verification (security)
4. Alert storage in database

### Phase 3: Threat Intelligence Enrichment
1. VirusTotal adapter (hash lookup)
2. AlienVault OTX adapter (IP/domain/hash lookup)
3. Enrichment service (orchestrates lookups)
4. Rate limiting for API calls

### Phase 4: AI Analysis
1. Claude adapter
2. OpenAI adapter
3. Gemini adapter
4. Analysis prompt engineering
5. AI service with provider selection

### Phase 5: Outbound Integrations
1. SuperOps ticket creation adapter
2. Microsoft Teams adapter (Adaptive Cards with buttons)
3. Action button callback handling
4. Alert formatting service

### Phase 6: Actions & Automation
1. Action endpoint for button callbacks
2. S1 API integration for:
   - Resolve/clear alert
   - Network containment
3. Escalation workflow
4. Audit logging for actions

### Phase 7: Polish & Deployment
1. Settings management API
2. Docker configuration
3. Health check endpoints
4. Documentation
5. Example configurations

---

## API Endpoints

### Webhooks (Inbound)
```
POST /webhooks/sentinelone          # S1 alert webhook
POST /webhooks/crowdstrike          # Future: CrowdStrike
```

### Actions (Button Callbacks)
```
POST /actions/resolve               # Resolve alert in EDR
POST /actions/contain               # Network contain endpoint
POST /actions/escalate              # Escalate to senior engineer
```

### Settings Management
```
GET  /api/settings                  # List all settings
GET  /api/settings/{integration}    # Get specific integration settings
PUT  /api/settings/{integration}    # Update integration settings
POST /api/settings/{integration}/test  # Test integration connectivity
```

### Health & Status
```
GET  /health                        # Health check
GET  /api/alerts                    # List recent alerts
GET  /api/alerts/{id}               # Get specific alert details
```

---

## Teams Adaptive Card Example

The Teams alert will include action buttons:

```
┌─────────────────────────────────────────────────────────────────┐
│  🚨 SECURITY ALERT - HIGH SEVERITY                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Endpoint: WORKSTATION-PC01                                      │
│  User: jsmith                                                    │
│  Threat: Cobalt Strike Beacon                                    │
│  Classification: Malware - Command & Control                     │
│                                                                  │
│  ─────────────────────────────────────────────────────────────  │
│                                                                  │
│  📋 AI Analysis:                                                 │
│  This detection indicates a Cobalt Strike beacon, commonly       │
│  used in targeted attacks. The beacon was attempting to          │
│  establish C2 communication. Immediate containment recommended.  │
│                                                                  │
│  🔍 Threat Intel:                                                │
│  • VirusTotal: 45/70 detections                                  │
│  • AlienVault: Associated with APT29                             │
│                                                                  │
│  📝 Recommended Actions:                                         │
│  1. Immediately isolate the endpoint                             │
│  2. Preserve forensic evidence                                   │
│  3. Check for lateral movement                                   │
│  4. Reset user credentials                                       │
│                                                                  │
│  ─────────────────────────────────────────────────────────────  │
│                                                                  │
│  Ticket: SUP-12345                                               │
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ ✅ Resolve  │  │ 🔒 Contain  │  │ ⬆️ Escalate to Senior   │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Configuration Examples

### config.yaml (Base Settings)
```yaml
server:
  host: "0.0.0.0"
  port: 8000
  debug: false

logging:
  level: "INFO"
  format: "json"

database:
  path: "./data/alerts.db"

security:
  webhook_secret_header: "X-Webhook-Secret"
  encrypt_api_keys: true
```

### Environment Variables (.env)
```bash
# Encryption key for API keys in database
ENCRYPTION_KEY=your-32-byte-encryption-key

# Default AI provider
DEFAULT_AI_PROVIDER=claude

# S1 Webhook secret (for signature verification)
S1_WEBHOOK_SECRET=your-webhook-secret
```

---

## Questions for You

Before I start implementing, please confirm or adjust:

1. **Alert History**: Should we store all alerts in the database for history/reporting, or just process and forward them?

2. **Multiple Tenants**: Will this serve multiple clients/tenants, or is it single-tenant for your MSP?

3. **S1 API Access**: Do you have API access to SentinelOne for the action buttons (resolve, contain)? This requires Management Console API credentials.

4. **Teams Setup**: Do you have a Teams webhook URL, or will you need to set up a Teams Bot for the action buttons to work?

5. **Encryption**: For storing API keys, should I use simple encryption (AES) or integrate with a secrets manager?

---

## Next Steps

Once you approve this plan (with any modifications), I'll implement in this order:

1. ✅ Set up project structure and dependencies
2. ✅ Implement configuration and database
3. ✅ Create base adapter interfaces
4. ✅ Build SentinelOne webhook handler
5. ✅ Add threat intel enrichment
6. ✅ Implement AI analysis
7. ✅ Add SuperOps and Teams integrations
8. ✅ Add action buttons and callbacks
9. ✅ Dockerize and document

Let me know your thoughts!
