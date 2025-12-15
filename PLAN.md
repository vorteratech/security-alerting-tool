# Security Alerting Tool - Implementation Plan

## Overview

A modular security alerting application for MSPs that:
1. Receives real-time detections from EDR platforms via webhooks
2. Enriches alerts with threat intelligence
3. Uses AI to analyze and provide recommendations
4. Creates tickets in PSA platforms
5. Posts alerts to chat platforms with action buttons

**Deployment**: Single-tenant (for your MSP and clients)
**Compliance**: Government-ready (secure API key storage)

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
│  │ │CrowdStrike│─┼────▶│      │      ┌─────┴─────┐         │           │  │
│  │ │  Falcon  │ │     │       │      │VirusTotal │         │           │  │
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
│                       │  │   (Ticket)  │          │  (Bot + Buttons) │    │  │
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
│  │  (base settings)│    │  - API Keys (AES-256-GCM encrypted)         │    │
│  │  - Server port  │    │  - Integration settings                     │    │
│  │  - Log level    │    │  - Action audit log (compliance)            │    │
│  │  - Enabled      │    │                                             │    │
│  │    integrations │    │  * No alert storage - history in PSA        │    │
│  └─────────────────┘    └─────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Security & Compliance

### API Key Encryption (Government-Ready)

For storing sensitive credentials with government clients in mind:

```
┌─────────────────────────────────────────────────────────────────┐
│                    ENCRYPTION ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Master Key (Environment Variable or File)                       │
│       │                                                          │
│       ▼                                                          │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  PBKDF2 Key Derivation (100,000 iterations)             │    │
│  │  - Unique salt per encrypted value                       │    │
│  │  - SHA-256 hash function                                 │    │
│  └─────────────────────────────────────────────────────────┘    │
│       │                                                          │
│       ▼                                                          │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  AES-256-GCM Encryption                                  │    │
│  │  - Authenticated encryption (integrity + confidentiality)│    │
│  │  - Unique nonce per encryption                           │    │
│  │  - 128-bit authentication tag                            │    │
│  └─────────────────────────────────────────────────────────┘    │
│       │                                                          │
│       ▼                                                          │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Stored Format: base64(salt + nonce + tag + ciphertext) │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  Additional Security Measures:                                   │
│  - Master key never stored in database                          │
│  - Audit logging of all key access                              │
│  - Key rotation support                                         │
│  - Memory clearing after use                                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Compliance Features
- **Audit Logging**: All actions (resolve, contain, escalate) logged with timestamp, user, and result
- **Secure Transport**: HTTPS required for all webhook endpoints
- **Webhook Verification**: HMAC signature verification for S1 and CrowdStrike webhooks
- **No PII Storage**: Alerts processed in-memory, not stored (history in PSA)

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
│   │   └── models.py               # SQLAlchemy models (settings + audit)
│   │
│   ├── security/
│   │   ├── __init__.py
│   │   └── encryption.py           # AES-256-GCM encryption for API keys
│   │
│   ├── adapters/                   # Plugin architecture for integrations
│   │   ├── __init__.py
│   │   │
│   │   ├── edr/                    # EDR platform adapters
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # Abstract base class
│   │   │   ├── sentinelone.py      # SentinelOne implementation
│   │   │   └── crowdstrike.py      # CrowdStrike Falcon implementation
│   │   │
│   │   ├── ai/                     # AI provider adapters
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # Abstract base class
│   │   │   ├── claude.py           # Anthropic Claude
│   │   │   ├── openai_adapter.py   # OpenAI GPT
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
│   │       └── teams.py            # Microsoft Teams Bot (Adaptive Cards)
│   │
│   ├── services/                   # Business logic
│   │   ├── __init__.py
│   │   ├── alert_processor.py      # Main orchestration service
│   │   ├── enrichment.py           # Threat intelligence enrichment
│   │   └── formatter.py            # Alert formatting for output
│   │
│   └── api/                        # API endpoints
│       ├── __init__.py
│       ├── webhooks.py             # Inbound webhook endpoints (S1 + CS)
│       ├── actions.py              # Action button callbacks
│       └── settings_api.py         # Settings management API
│
├── tests/                          # Test suite
│   ├── __init__.py
│   ├── conftest.py                 # Pytest fixtures
│   ├── test_webhooks.py
│   ├── test_enrichment.py
│   ├── test_encryption.py
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

### Alert (In-Memory - Not Stored)

```python
@dataclass
class Alert:
    id: str                         # Unique identifier (UUID)
    source: str                     # EDR source: "sentinelone" | "crowdstrike"
    source_alert_id: str            # Original alert ID from EDR
    timestamp: datetime             # When alert occurred
    severity: str                   # critical, high, medium, low, info

    # Endpoint info
    hostname: str
    endpoint_ip: str
    endpoint_os: str
    endpoint_user: str

    # Site/Group info (for multi-client MSP)
    site_name: str                  # S1 Site or CS Host Group
    client_name: str                # Derived client name

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
    enrichment: EnrichmentResult    # VirusTotal, AlienVault results
    ai_analysis: AIAnalysisResult   # AI-generated analysis

    # Output tracking (not persisted)
    ticket_id: str                  # PSA ticket ID (returned from SuperOps)
    teams_message_id: str           # Teams message ID (for updates)
```

### Integration Settings (Database)

```python
class IntegrationSetting(Base):
    __tablename__ = "integration_settings"

    id: int                         # Primary key
    integration_type: str           # edr, ai, threat_intel, psa, chat
    provider: str                   # sentinelone, crowdstrike, claude, etc.
    enabled: bool                   # Is this integration active?
    is_primary: bool                # Primary provider for this type?
    config_json: str                # Provider-specific config (JSON)
    api_key_encrypted: str          # AES-256-GCM encrypted API key
    created_at: datetime
    updated_at: datetime
```

### Audit Log (Database - Compliance)

```python
class AuditLog(Base):
    __tablename__ = "audit_log"

    id: int                         # Primary key
    timestamp: datetime             # When action occurred
    action_type: str                # resolve, contain, escalate, config_change
    alert_source: str               # sentinelone, crowdstrike
    alert_id: str                   # Original alert ID
    hostname: str                   # Affected endpoint
    performed_by: str               # Teams user who clicked button
    result: str                     # success, failure
    details: str                    # Additional context (JSON)
```

---

## Implementation Phases

### Phase 1: Foundation (Core Infrastructure)
1. Project setup (dependencies, structure)
2. Configuration management (YAML + environment variables)
3. Database setup (SQLite with SQLAlchemy) - settings & audit only
4. **AES-256-GCM encryption module** for API keys
5. FastAPI application skeleton
6. Logging infrastructure
7. Base adapter classes (abstract interfaces)

### Phase 2: EDR Integration
1. **SentinelOne** webhook endpoint + payload parsing
2. **CrowdStrike Falcon** webhook endpoint + payload parsing
3. Alert normalization (common format from both EDRs)
4. Webhook signature verification (HMAC)

### Phase 3: Threat Intelligence Enrichment
1. VirusTotal adapter (hash/IP/domain lookup)
2. AlienVault OTX adapter (hash/IP/domain lookup)
3. Enrichment service (orchestrates lookups)
4. Rate limiting and caching for API calls

### Phase 4: AI Analysis
1. Claude adapter (Anthropic)
2. OpenAI adapter (GPT-4)
3. Gemini adapter (Google)
4. Analysis prompt engineering (security-focused)
5. AI service with configurable provider selection

### Phase 5: Outbound Integrations
1. SuperOps ticket creation adapter
2. **Microsoft Teams Bot** (Adaptive Cards with action buttons)
3. Alert formatting service (pretty output for techs)

### Phase 6: Actions & Automation
1. Action endpoint for Teams button callbacks
2. S1 API integration: resolve alert, network containment
3. CrowdStrike API integration: resolve alert, network containment
4. Escalation workflow (update ticket priority, notify channel)
5. **Audit logging** for all actions

### Phase 7: Polish & Deployment
1. Settings management API (CRUD for integrations)
2. Docker configuration
3. Health check endpoints
4. Documentation
5. Example configurations

---

## API Endpoints

### Webhooks (Inbound)
```
POST /webhooks/sentinelone          # S1 alert webhook
POST /webhooks/crowdstrike          # CrowdStrike Falcon webhook
```

### Actions (Teams Bot Callbacks)
```
POST /actions/resolve               # Resolve alert in EDR
POST /actions/contain               # Network contain endpoint
POST /actions/escalate              # Escalate to senior engineer
```

### Settings Management
```
GET  /api/settings                  # List all integration settings
GET  /api/settings/{type}/{provider}  # Get specific integration
PUT  /api/settings/{type}/{provider}  # Update integration settings
DELETE /api/settings/{type}/{provider} # Remove integration
POST /api/settings/{type}/{provider}/test  # Test connectivity
```

### Health & Audit
```
GET  /health                        # Health check (for monitoring)
GET  /api/audit                     # List audit log (with filters)
```

---

## Teams Bot with Adaptive Cards

The Teams Bot will post alerts as Adaptive Cards with action buttons:

```
┌─────────────────────────────────────────────────────────────────┐
│  🚨 SECURITY ALERT - HIGH SEVERITY                [SentinelOne] │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Client: Acme Corporation                                        │
│  Endpoint: WORKSTATION-PC01 (192.168.1.50)                      │
│  User: jsmith                                                    │
│  OS: Windows 11 Pro                                              │
│                                                                  │
│  ─────────────────────────────────────────────────────────────  │
│                                                                  │
│  Threat: Cobalt Strike Beacon                                    │
│  Classification: Malware - Command & Control                     │
│  File: C:\Users\jsmith\Downloads\update.exe                     │
│  Hash: a1b2c3d4e5f6...                                          │
│                                                                  │
│  ─────────────────────────────────────────────────────────────  │
│                                                                  │
│  📋 AI Analysis:                                                 │
│  This detection indicates a Cobalt Strike beacon, commonly       │
│  used in targeted attacks. The beacon was attempting to          │
│  establish C2 communication to 185.x.x.x. This is consistent    │
│  with initial access techniques. Immediate containment is        │
│  strongly recommended.                                           │
│                                                                  │
│  🔍 Threat Intel:                                                │
│  • VirusTotal: 45/70 engines detected                           │
│  • AlienVault: Associated with APT29, known IOCs match          │
│                                                                  │
│  📝 Recommended Actions:                                         │
│  1. Immediately isolate the endpoint from network                │
│  2. Preserve forensic evidence (memory dump, disk image)        │
│  3. Check for lateral movement to other systems                  │
│  4. Reset user credentials for jsmith                            │
│  5. Review email logs for initial infection vector               │
│                                                                  │
│  ─────────────────────────────────────────────────────────────  │
│                                                                  │
│  📄 Ticket: SUP-12345 (Created in SuperOps)                     │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ ✅ Resolve  │  │ 🔒 Contain   │  │ ⬆️ Escalate to Senior  │  │
│  │   Alert    │  │   Machine    │  │      Engineer          │  │
│  └─────────────┘  └──────────────┘  └────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Button Actions

| Button | Action |
|--------|--------|
| **Resolve Alert** | Marks alert as resolved in S1/CS, updates ticket status, logs action |
| **Contain Machine** | Triggers network isolation via S1/CS API, updates ticket, logs action |
| **Escalate to Senior** | Updates ticket priority to critical, posts to escalation channel |

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
  format: "json"  # json for production, text for development

database:
  path: "./data/settings.db"

security:
  # Webhook signature verification
  verify_webhooks: true

  # API key encryption (key from environment)
  encryption_key_env: "MASTER_ENCRYPTION_KEY"

# Default providers (can be changed via API)
defaults:
  ai_provider: "claude"
  threat_intel_providers:
    - "virustotal"
    - "alienvault"
```

### Environment Variables (.env)
```bash
# CRITICAL: 32-byte key for AES-256 encryption
# Generate with: python -c "import secrets; print(secrets.token_hex(32))"
MASTER_ENCRYPTION_KEY=your-64-char-hex-key-here

# Webhook secrets for signature verification
S1_WEBHOOK_SECRET=your-sentinelone-webhook-secret
CS_WEBHOOK_SECRET=your-crowdstrike-webhook-secret

# Teams Bot credentials (from Azure Bot registration)
TEAMS_BOT_APP_ID=your-azure-app-id
TEAMS_BOT_APP_SECRET=your-azure-app-secret
```

---

## Dependencies

```
# requirements.txt

# Web framework
fastapi>=0.104.0
uvicorn[standard]>=0.24.0

# Database
sqlalchemy>=2.0.0
aiosqlite>=0.19.0

# HTTP client
httpx>=0.25.0
aiohttp>=3.9.0

# Security
cryptography>=41.0.0          # AES-256-GCM encryption
python-jose[cryptography]     # JWT for Teams Bot

# AI Providers
anthropic>=0.7.0              # Claude
openai>=1.3.0                 # GPT
google-generativeai>=0.3.0    # Gemini

# Configuration
pyyaml>=6.0.0
pydantic>=2.5.0
pydantic-settings>=2.1.0

# Teams Bot
botbuilder-core>=4.14.0
botbuilder-schema>=4.14.0

# Utilities
python-dotenv>=1.0.0
structlog>=23.2.0             # Structured logging
```

---

## Ready to Implement

With CrowdStrike Falcon added to initial scope and the security/compliance requirements clarified, here's the final implementation order:

1. **Phase 1**: Foundation + AES-256-GCM encryption
2. **Phase 2**: Both S1 and CrowdStrike webhook handlers
3. **Phase 3**: VirusTotal + AlienVault enrichment
4. **Phase 4**: Claude, OpenAI, Gemini AI adapters
5. **Phase 5**: SuperOps + Teams Bot
6. **Phase 6**: Action buttons + audit logging
7. **Phase 7**: Docker + documentation

**Shall I start implementing Phase 1?**
