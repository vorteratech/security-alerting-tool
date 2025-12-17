"""
Integration connectivity testing service.

Provides real connectivity tests for all integration types:
- EDR: Test API authentication
- PSA: Create a test ticket
- Threat Intel: Test API lookup
- AI: Send a test prompt
- Chat: Send a test message
"""

import json
from datetime import datetime
from typing import Any, Optional

import httpx

from ..config.logging import get_logger
from ..config.settings import Settings
from ..database.models import IntegrationSetting
from ..security.encryption import create_encryption_service

logger = get_logger(__name__)


class IntegrationTester:
    """Tests integration connectivity with real API calls."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.encryption = create_encryption_service(settings.master_encryption_key)

    def _decrypt_credentials(
        self, setting: IntegrationSetting
    ) -> tuple[Optional[str], Optional[str], dict]:
        """Decrypt API credentials from setting."""
        api_key = None
        api_secret = None
        config = {}

        if setting.api_key_encrypted:
            api_key = self.encryption.decrypt(setting.api_key_encrypted)
        if setting.api_secret_encrypted:
            api_secret = self.encryption.decrypt(setting.api_secret_encrypted)
        if setting.config_json:
            config = json.loads(setting.config_json)

        return api_key, api_secret, config

    async def test_integration(
        self, setting: IntegrationSetting
    ) -> dict[str, Any]:
        """
        Test an integration based on its type and provider.

        Returns dict with:
            - success: bool
            - message: str
            - details: Optional[dict]
        """
        integration_type = setting.integration_type
        provider = setting.provider

        api_key, api_secret, config = self._decrypt_credentials(setting)

        if not api_key and integration_type not in ("chat",):
            return {
                "success": False,
                "message": "No API key configured",
                "details": None,
            }

        try:
            if integration_type == "edr":
                return await self._test_edr(provider, api_key, api_secret, config)
            elif integration_type == "psa":
                return await self._test_psa(provider, api_key, api_secret, config)
            elif integration_type == "threat_intel":
                return await self._test_threat_intel(provider, api_key, config)
            elif integration_type == "ai":
                return await self._test_ai(provider, api_key, config)
            elif integration_type == "chat":
                return await self._test_chat(provider, api_key, api_secret, config)
            else:
                return {
                    "success": False,
                    "message": f"Unknown integration type: {integration_type}",
                    "details": None,
                }
        except Exception as e:
            logger.error(
                "Integration test failed",
                integration_type=integration_type,
                provider=provider,
                error=str(e),
            )
            return {
                "success": False,
                "message": str(e),
                "details": {"error_type": type(e).__name__},
            }

    async def _test_edr(
        self,
        provider: str,
        api_key: str,
        api_secret: Optional[str],
        config: dict,
    ) -> dict[str, Any]:
        """Test EDR connectivity."""
        base_url = config.get("base_url", "")

        if provider == "sentinelone":
            if not base_url:
                return {"success": False, "message": "Base URL not configured", "details": None}

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{base_url}/web/api/v2.1/system/status",
                    headers={
                        "Authorization": f"ApiToken {api_key}",
                        "Content-Type": "application/json",
                    },
                )
                response.raise_for_status()
                data = response.json()

                return {
                    "success": True,
                    "message": "SentinelOne API connection successful",
                    "details": {
                        "health": data.get("data", {}).get("health", "unknown"),
                    },
                }

        elif provider == "crowdstrike":
            if not base_url:
                base_url = "https://api.crowdstrike.com"

            client_id = config.get("client_id", "")
            if not client_id:
                return {"success": False, "message": "Client ID not configured", "details": None}

            # Get OAuth token
            async with httpx.AsyncClient(timeout=30.0) as client:
                token_response = await client.post(
                    f"{base_url}/oauth2/token",
                    data={
                        "client_id": client_id,
                        "client_secret": api_secret or api_key,
                    },
                )
                token_response.raise_for_status()
                token_data = token_response.json()
                access_token = token_data["access_token"]

                # Test with a simple API call
                response = await client.get(
                    f"{base_url}/sensors/queries/sensors/v1",
                    headers={"Authorization": f"Bearer {access_token}"},
                    params={"limit": 1},
                )
                response.raise_for_status()

                return {
                    "success": True,
                    "message": "CrowdStrike API connection successful",
                    "details": {"authenticated": True},
                }

        return {"success": False, "message": f"Unknown EDR provider: {provider}", "details": None}

    async def _test_psa(
        self,
        provider: str,
        api_key: str,
        api_secret: Optional[str],
        config: dict,
    ) -> dict[str, Any]:
        """Test PSA connectivity."""
        base_url = config.get("base_url", "")

        if provider == "superops":
            # SuperOps uses GraphQL API
            base_url = "https://api.superops.ai/msp"
            subdomain = config.get("subdomain", "")

            if not subdomain:
                return {
                    "success": False,
                    "message": "Customer subdomain not configured. Find it in SuperOps Settings > Company Information.",
                    "details": None,
                }

            async with httpx.AsyncClient(timeout=30.0) as client:
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "CustomerSubDomain": subdomain,
                }

                # Simple GraphQL query to test connectivity - fetch one ticket
                # Using inline input - field is 'page' not 'pageNumber'
                graphql_query = {
                    "query": """
                        {
                            getTicketList(input: { page: 1, pageSize: 1 }) {
                                tickets {
                                    ticketId
                                }
                            }
                        }
                    """
                }

                response = await client.post(
                    base_url,
                    headers=headers,
                    json=graphql_query,
                )

                # Check for errors
                if response.status_code != 200:
                    try:
                        error_data = response.json()
                        error_msg = error_data.get("message", response.text[:200])
                    except Exception:
                        error_msg = response.text[:200]
                    return {
                        "success": False,
                        "message": f"SuperOps API error ({response.status_code}): {error_msg}",
                        "details": {"status_code": response.status_code},
                    }

                data = response.json()

                # Check for GraphQL errors
                if "errors" in data:
                    error_msg = data["errors"][0].get("message", str(data["errors"]))
                    return {
                        "success": False,
                        "message": f"SuperOps GraphQL error: {error_msg}",
                        "details": {"errors": data["errors"]},
                    }

                # Success - count tickets returned
                tickets = data.get("data", {}).get("getTicketList", {}).get("tickets", [])

                return {
                    "success": True,
                    "message": "SuperOps API connection successful",
                    "details": {
                        "tickets_found": len(tickets),
                        "api_type": "GraphQL",
                    },
                }

        return {"success": False, "message": f"Unknown PSA provider: {provider}", "details": None}

    async def send_test_ticket(
        self, setting: IntegrationSetting
    ) -> dict[str, Any]:
        """
        Create a test ticket in SuperOps.

        Returns dict with success, message, and details.
        """
        from datetime import datetime

        api_key, api_secret, config = self._decrypt_credentials(setting)

        if setting.provider != "superops":
            return {
                "success": False,
                "message": "Test ticket only supported for SuperOps",
                "details": None,
            }

        base_url = "https://api.superops.ai/msp"
        subdomain = config.get("subdomain", "")
        default_client_id = config.get("default_client_id", "")

        if not subdomain:
            return {
                "success": False,
                "message": "Customer subdomain not configured",
                "details": None,
            }

        if not default_client_id:
            return {
                "success": False,
                "message": "Default Client ID not configured. Set it in SuperOps settings to create test tickets.",
                "details": None,
            }

        async with httpx.AsyncClient(timeout=30.0) as http_client:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "CustomerSubDomain": subdomain,
            }

            # GraphQL mutation to create a ticket
            # Client field is required - use accountId per SuperOps schema
            graphql_mutation = {
                "query": """
                    mutation createTicket($input: CreateTicketInput!) {
                        createTicket(input: $input) {
                            ticketId
                            displayId
                        }
                    }
                """,
                "variables": {
                    "input": {
                        "subject": "[TEST] Security Alerting Tool - Connection Test",
                        "description": f"This is an automated test ticket created by the Security Alerting Tool to verify PSA connectivity.\\n\\nThis ticket can be safely deleted.\\n\\nTest performed at: {datetime.utcnow().isoformat()} UTC",
                        "priority": "LOW",
                        "client": {
                            "accountId": default_client_id
                        }
                    }
                }
            }

            response = await http_client.post(
                base_url,
                headers=headers,
                json=graphql_mutation,
            )

            if response.status_code != 200:
                try:
                    error_data = response.json()
                    error_msg = error_data.get("message", response.text[:200])
                except Exception:
                    error_msg = response.text[:200]
                return {
                    "success": False,
                    "message": f"SuperOps API error ({response.status_code}): {error_msg}",
                    "details": {"status_code": response.status_code},
                }

            data = response.json()

            # Check for GraphQL errors
            if "errors" in data:
                error_msg = data["errors"][0].get("message", str(data["errors"]))
                return {
                    "success": False,
                    "message": f"SuperOps GraphQL error: {error_msg}",
                    "details": {"errors": data["errors"]},
                }

            # Success - get ticket info
            ticket = data.get("data", {}).get("createTicket", {})
            ticket_id = ticket.get("ticketId", "")
            display_id = ticket.get("displayId", "")

            return {
                "success": True,
                "message": f"Test ticket created: #{display_id}",
                "details": {
                    "ticket_id": ticket_id,
                    "display_id": display_id,
                    "note": "A test ticket was created in SuperOps. You can delete it manually.",
                },
            }

    async def _test_threat_intel(
        self,
        provider: str,
        api_key: str,
        config: dict,
    ) -> dict[str, Any]:
        """Test threat intelligence connectivity."""
        if provider == "virustotal":
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Look up a known safe hash (SHA256 of empty file)
                test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                response = await client.get(
                    f"https://www.virustotal.com/api/v3/files/{test_hash}",
                    headers={
                        "x-apikey": api_key,
                        "Accept": "application/json",
                    },
                )
                # 404 means API key works but hash not found - that's OK
                if response.status_code in (200, 404):
                    return {
                        "success": True,
                        "message": "VirusTotal API connection successful",
                        "details": {"api_version": "v3"},
                    }
                response.raise_for_status()

        elif provider == "alienvault":
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Test with a simple API call
                response = await client.get(
                    "https://otx.alienvault.com/api/v1/user/me",
                    headers={"X-OTX-API-KEY": api_key},
                )
                response.raise_for_status()
                data = response.json()

                return {
                    "success": True,
                    "message": "AlienVault OTX API connection successful",
                    "details": {
                        "username": data.get("username", "unknown"),
                        "member_since": data.get("member_since", ""),
                    },
                }

        return {"success": False, "message": f"Unknown threat intel provider: {provider}", "details": None}

    async def _test_ai(
        self,
        provider: str,
        api_key: str,
        config: dict,
    ) -> dict[str, Any]:
        """Test AI provider connectivity with a simple prompt."""
        model = config.get("model", "")

        if provider == "anthropic":
            if not model:
                model = "claude-3-5-haiku-20241022"

            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": model,
                        "max_tokens": 50,
                        "messages": [{"role": "user", "content": "Say 'Connection successful' in exactly 2 words."}],
                    },
                )

                # Check for errors and get detailed message
                if response.status_code != 200:
                    try:
                        error_data = response.json()
                        error_msg = error_data.get("error", {}).get("message", response.text[:200])
                    except Exception:
                        error_msg = response.text[:200]
                    return {
                        "success": False,
                        "message": f"Anthropic API error ({response.status_code}): {error_msg}",
                        "details": {"status_code": response.status_code, "model": model},
                    }

                data = response.json()
                return {
                    "success": True,
                    "message": "Claude API connection successful",
                    "details": {
                        "model": model,
                        "response": data.get("content", [{}])[0].get("text", "")[:100],
                    },
                }

        elif provider == "openai":
            if not model:
                model = "gpt-4o-mini"

            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": model,
                        "max_tokens": 50,
                        "messages": [{"role": "user", "content": "Say 'Connection successful' in exactly 2 words."}],
                    },
                )

                # Check for errors and get detailed message
                if response.status_code != 200:
                    try:
                        error_data = response.json()
                        error_msg = error_data.get("error", {}).get("message", response.text[:200])
                    except Exception:
                        error_msg = response.text[:200]
                    return {
                        "success": False,
                        "message": f"OpenAI API error ({response.status_code}): {error_msg}",
                        "details": {"status_code": response.status_code, "model": model},
                    }

                data = response.json()
                return {
                    "success": True,
                    "message": "OpenAI API connection successful",
                    "details": {
                        "model": model,
                        "response": data.get("choices", [{}])[0].get("message", {}).get("content", "")[:100],
                    },
                }

        elif provider == "gemini":
            if not model:
                model = "gemini-pro"

            async with httpx.AsyncClient(timeout=60.0) as client:
                # Google AI Studio uses v1beta for all models
                response = await client.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                    params={"key": api_key},
                    headers={"Content-Type": "application/json"},
                    json={
                        "contents": [{"parts": [{"text": "Say 'Connection successful' in exactly 2 words."}]}],
                        "generationConfig": {"maxOutputTokens": 50},
                    },
                )

                # Check for errors and get detailed message
                if response.status_code != 200:
                    try:
                        error_data = response.json()
                        error_msg = error_data.get("error", {}).get("message", response.text[:200])
                    except Exception:
                        error_msg = response.text[:200]
                    return {
                        "success": False,
                        "message": f"Gemini API error ({response.status_code}): {error_msg}",
                        "details": {"status_code": response.status_code, "model": model},
                    }

                data = response.json()
                return {
                    "success": True,
                    "message": "Gemini API connection successful",
                    "details": {
                        "model": model,
                        "response": data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")[:100],
                    },
                }

        return {"success": False, "message": f"Unknown AI provider: {provider}", "details": None}

    async def _test_chat(
        self,
        provider: str,
        api_key: Optional[str],
        api_secret: Optional[str],
        config: dict,
    ) -> dict[str, Any]:
        """Test chat connectivity by sending a test message."""
        if provider == "teams":
            webhook_url = config.get("webhook_url", "")
            bot_app_id = config.get("bot_app_id", "")

            # If webhook URL is configured, use incoming webhook (simpler)
            if webhook_url:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    # Send a simple test card
                    test_card = {
                        "@type": "MessageCard",
                        "@context": "http://schema.org/extensions",
                        "themeColor": "0076D7",
                        "summary": "Security Alerting Tool - Test",
                        "sections": [
                            {
                                "activityTitle": "Connection Test Successful",
                                "activitySubtitle": f"Test performed at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
                                "activityImage": "https://adaptivecards.io/content/cats/1.png",
                                "facts": [
                                    {"name": "Status", "value": "Connected"},
                                    {"name": "Source", "value": "Security Alerting Tool"},
                                ],
                                "markdown": True,
                            }
                        ],
                    }

                    response = await client.post(webhook_url, json=test_card)
                    response.raise_for_status()

                    return {
                        "success": True,
                        "message": "Teams webhook test message sent successfully",
                        "details": {
                            "type": "incoming_webhook",
                            "note": "Check your Teams channel for the test message",
                        },
                    }

            # If bot credentials are configured, use Bot Framework
            elif bot_app_id and api_secret:
                service_url = config.get("service_url", "")
                conversation_id = config.get("conversation_id", "")

                async with httpx.AsyncClient(timeout=30.0) as client:
                    # Get Bot Framework token
                    token_response = await client.post(
                        "https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token",
                        data={
                            "grant_type": "client_credentials",
                            "client_id": bot_app_id,
                            "client_secret": api_secret,
                            "scope": "https://api.botframework.com/.default",
                        },
                    )
                    token_response.raise_for_status()
                    token_data = token_response.json()
                    access_token = token_data.get("access_token")

                    # If service URL and conversation ID are configured, send a test message
                    if service_url and conversation_id:
                        # Send message via Bot Framework
                        message_url = f"{service_url.rstrip('/')}/v3/conversations/{conversation_id}/activities"

                        test_message = {
                            "type": "message",
                            "text": f"**Security Alerting Tool - Bot Test**\n\nConnection test successful!\n\nTest performed at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
                        }

                        msg_response = await client.post(
                            message_url,
                            headers={
                                "Authorization": f"Bearer {access_token}",
                                "Content-Type": "application/json",
                            },
                            json=test_message,
                        )

                        if msg_response.status_code in (200, 201):
                            return {
                                "success": True,
                                "message": "Teams Bot test message sent successfully",
                                "details": {
                                    "type": "bot_framework",
                                    "note": "Check your Teams channel for the test message",
                                },
                            }
                        else:
                            try:
                                error_data = msg_response.json()
                                error_msg = error_data.get("message", msg_response.text[:200])
                            except Exception:
                                error_msg = msg_response.text[:200]
                            return {
                                "success": False,
                                "message": f"Bot auth OK but message failed ({msg_response.status_code}): {error_msg}",
                                "details": {
                                    "type": "bot_framework",
                                    "note": "Check Service URL and Channel ID configuration",
                                },
                            }

                    # No service URL/conversation ID - just validate credentials
                    return {
                        "success": True,
                        "message": "Teams Bot credentials validated (configure Service URL & Channel ID to send test message)",
                        "details": {
                            "type": "bot_framework",
                            "note": "Add Service URL and Channel ID to enable bot messaging",
                        },
                    }

            return {
                "success": False,
                "message": "No Teams webhook URL or Bot credentials configured",
                "details": None,
            }

        return {"success": False, "message": f"Unknown chat provider: {provider}", "details": None}
