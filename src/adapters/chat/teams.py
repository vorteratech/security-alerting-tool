"""
Microsoft Teams Bot adapter.

Handles sending Adaptive Card alerts and processing action button callbacks.
Uses Microsoft Bot Framework for proper Teams integration.
"""

from datetime import datetime
from typing import Any, Optional

import httpx

from ...config.logging import get_logger
from ..edr.base import Alert
from .base import BaseChatAdapter, AlertCard, MessageResult

logger = get_logger(__name__)


class TeamsAdapter(BaseChatAdapter):
    """
    Microsoft Teams Bot adapter.

    Uses Bot Framework to send Adaptive Cards with action buttons.
    Supports:
    - Rich alert cards with all alert details
    - Action buttons (Resolve, Contain, Escalate)
    - Message updates for status changes
    - Threaded replies
    """

    # Microsoft Graph API endpoint for bots
    BOT_API_BASE = "https://smba.trafficmanager.net"

    # Colors for severity levels
    SEVERITY_COLORS = {
        "critical": "attention",  # Red
        "high": "warning",  # Orange/Yellow
        "medium": "accent",  # Blue
        "low": "good",  # Green
        "info": "default",
    }

    def __init__(
        self,
        app_id: str = "",
        app_password: str = "",
        tenant_id: str = "",
        service_url: str = "",
        webhook_url: str = "",
        **kwargs
    ):
        """
        Initialize the Teams Bot adapter.

        Args:
            app_id: Microsoft Bot App ID.
            app_password: Microsoft Bot App Password.
            tenant_id: Azure AD Tenant ID (optional for multi-tenant bots).
            service_url: Teams service URL (usually obtained from incoming activity).
            webhook_url: Incoming webhook URL for simple notifications (no bot required).
            **kwargs: Additional config including:
                - default_channel_id: Default channel to post to
                - action_callback_url: Base URL for action callbacks
        """
        super().__init__(**kwargs)
        self.app_id = app_id
        self.app_password = app_password
        self.tenant_id = tenant_id
        self.service_url = service_url or self.BOT_API_BASE
        self.webhook_url = webhook_url
        self.default_channel_id = kwargs.get("default_channel_id", "")
        self.action_callback_url = kwargs.get("action_callback_url", "")
        self._client: Optional[httpx.AsyncClient] = None
        self._access_token: Optional[str] = None
        self._token_expires: Optional[datetime] = None

    @property
    def provider_name(self) -> str:
        return "teams"

    async def _get_access_token(self) -> str:
        """Get or refresh Bot Framework access token."""
        # Check if we have a valid token
        if self._access_token and self._token_expires:
            if datetime.utcnow() < self._token_expires:
                return self._access_token

        # Get new token from Azure AD
        async with httpx.AsyncClient() as client:
            token_url = "https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token"

            response = await client.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.app_id,
                    "client_secret": self.app_password,
                    "scope": "https://api.botframework.com/.default",
                },
            )
            response.raise_for_status()

            data = response.json()
            self._access_token = data["access_token"]
            # Token usually expires in 1 hour, refresh 5 min early
            expires_in = data.get("expires_in", 3600) - 300
            from datetime import timedelta
            self._token_expires = datetime.utcnow() + timedelta(seconds=expires_in)

            logger.debug("Obtained new Bot Framework access token")
            return self._access_token

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client with auth."""
        token = await self._get_access_token()

        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )
        else:
            # Update token in case it was refreshed
            self._client.headers["Authorization"] = f"Bearer {token}"

        return self._client

    def _build_adaptive_card(self, card: AlertCard) -> dict[str, Any]:
        """
        Build an Adaptive Card from an AlertCard.

        Args:
            card: The AlertCard to convert.

        Returns:
            Adaptive Card JSON structure.
        """
        severity_color = self.SEVERITY_COLORS.get(card.severity.lower(), "default")

        # Build the card body
        body = [
            # Header with severity indicator
            {
                "type": "Container",
                "style": severity_color,
                "items": [
                    {
                        "type": "TextBlock",
                        "text": f"{'🔴' if card.severity.lower() == 'critical' else '🟠' if card.severity.lower() == 'high' else '🟡' if card.severity.lower() == 'medium' else '🟢'} {card.title}",
                        "weight": "bolder",
                        "size": "large",
                        "wrap": True,
                    },
                    {
                        "type": "TextBlock",
                        "text": f"Severity: **{card.severity.upper()}** | Source: {card.source.upper()}",
                        "spacing": "none",
                        "isSubtle": True,
                    },
                ],
            },

            # Endpoint information
            {
                "type": "Container",
                "items": [
                    {
                        "type": "TextBlock",
                        "text": "Endpoint Information",
                        "weight": "bolder",
                        "spacing": "medium",
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {"title": "Hostname", "value": card.hostname or "N/A"},
                            {"title": "IP Address", "value": card.endpoint_ip or "N/A"},
                            {"title": "User", "value": card.endpoint_user or "N/A"},
                            {"title": "OS", "value": card.endpoint_os or "N/A"},
                            {"title": "Client", "value": card.client_name or "N/A"},
                        ],
                    },
                ],
            },

            # Threat details
            {
                "type": "Container",
                "items": [
                    {
                        "type": "TextBlock",
                        "text": "Threat Details",
                        "weight": "bolder",
                        "spacing": "medium",
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {"title": "Threat", "value": card.threat_name or "Unknown"},
                            {"title": "Classification", "value": card.threat_classification or "N/A"},
                        ],
                    },
                ],
            },
        ]

        # Add file path if present
        if card.file_path:
            body.append({
                "type": "TextBlock",
                "text": f"**File Path:** `{card.file_path[:100]}{'...' if len(card.file_path) > 100 else ''}`",
                "wrap": True,
                "spacing": "small",
            })

        # Add command line if present
        if card.command_line:
            body.append({
                "type": "TextBlock",
                "text": f"**Command:** `{card.command_line[:150]}{'...' if len(card.command_line) > 150 else ''}`",
                "wrap": True,
                "spacing": "small",
            })

        # Add network info if present
        if card.remote_ip or card.remote_domain:
            network_facts = []
            if card.remote_ip:
                network_facts.append({"title": "Remote IP", "value": card.remote_ip})
            if card.remote_domain:
                network_facts.append({"title": "Domain", "value": card.remote_domain})

            body.append({
                "type": "Container",
                "items": [
                    {
                        "type": "TextBlock",
                        "text": "Network Activity",
                        "weight": "bolder",
                        "spacing": "medium",
                    },
                    {
                        "type": "FactSet",
                        "facts": network_facts,
                    },
                ],
            })

        # Add AI analysis if present
        if card.ai_summary:
            body.append({
                "type": "Container",
                "style": "emphasis",
                "items": [
                    {
                        "type": "TextBlock",
                        "text": "AI Analysis",
                        "weight": "bolder",
                        "spacing": "medium",
                    },
                    {
                        "type": "TextBlock",
                        "text": card.ai_summary,
                        "wrap": True,
                    },
                ],
            })

            # Add recommendations
            if card.ai_recommendations:
                rec_text = "\n".join([f"• {r}" for r in card.ai_recommendations[:5]])
                body.append({
                    "type": "TextBlock",
                    "text": f"**Recommendations:**\n{rec_text}",
                    "wrap": True,
                    "spacing": "small",
                })

        # Add threat intel summary if present
        if card.threat_intel_summary:
            body.append({
                "type": "TextBlock",
                "text": f"**Threat Intel:** {card.threat_intel_summary}",
                "wrap": True,
                "spacing": "medium",
                "isSubtle": True,
            })

        # Add ticket link if present
        if card.ticket_url:
            body.append({
                "type": "TextBlock",
                "text": f"[View Ticket]({card.ticket_url})",
                "spacing": "medium",
            })

        # Add timestamp
        body.append({
            "type": "TextBlock",
            "text": f"Detected: {card.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "spacing": "medium",
            "isSubtle": True,
            "size": "small",
        })

        # Build action buttons
        actions = []
        callback_base = card.action_callback_url or self.action_callback_url

        if card.show_resolve_button:
            actions.append({
                "type": "Action.Submit",
                "title": "Resolve",
                "style": "positive",
                "data": {
                    "action": "resolve",
                    "alert_id": card.source_alert_id,
                    "source": card.source,
                    "hostname": card.hostname,
                },
            })

        if card.show_contain_button:
            actions.append({
                "type": "Action.Submit",
                "title": "Contain Endpoint",
                "style": "destructive",
                "data": {
                    "action": "contain",
                    "alert_id": card.source_alert_id,
                    "source": card.source,
                    "hostname": card.hostname,
                },
            })

        if card.show_escalate_button:
            actions.append({
                "type": "Action.Submit",
                "title": "Escalate",
                "data": {
                    "action": "escalate",
                    "alert_id": card.source_alert_id,
                    "source": card.source,
                    "hostname": card.hostname,
                    "ticket_id": card.ticket_id,
                },
            })

        # Add view in EDR action
        actions.append({
            "type": "Action.OpenUrl",
            "title": f"View in {card.source.title()}",
            "url": f"https://{card.source}.example.com/alerts/{card.source_alert_id}",
        })

        return {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": body,
            "actions": actions,
        }

    def _build_webhook_message_card(self, card: AlertCard) -> dict[str, Any]:
        """
        Build a MessageCard for webhook delivery.

        Args:
            card: The AlertCard to convert.

        Returns:
            MessageCard JSON structure for webhook.
        """
        severity_colors = {
            "critical": "FF0000",
            "high": "FFA500",
            "medium": "FFFF00",
            "low": "00FF00",
            "info": "0076D7",
        }
        theme_color = severity_colors.get(card.severity.lower(), "0076D7")

        facts = [
            {"name": "Hostname", "value": card.hostname or "N/A"},
            {"name": "IP Address", "value": card.endpoint_ip or "N/A"},
            {"name": "User", "value": card.endpoint_user or "N/A"},
            {"name": "Threat", "value": card.threat_name or "N/A"},
            {"name": "Severity", "value": card.severity.upper()},
        ]

        if card.file_hash:
            facts.append({"name": "File Hash", "value": card.file_hash[:16] + "..."})

        if card.ticket_id:
            facts.append({"name": "Ticket", "value": card.ticket_id})

        sections = [
            {
                "activityTitle": card.title,
                "activitySubtitle": f"Source: {card.source.upper()} | Alert ID: {card.source_alert_id}",
                "facts": facts,
                "markdown": True,
            }
        ]

        if card.description:
            sections.append({
                "text": card.description[:500] + ("..." if len(card.description) > 500 else ""),
                "markdown": True,
            })

        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": theme_color,
            "summary": card.title,
            "sections": sections,
        }

    async def send_alert(
        self,
        channel_id: str,
        card: AlertCard,
    ) -> MessageResult:
        """
        Send an alert card to a Teams channel.

        Uses webhook if configured, otherwise falls back to Bot Framework.

        Args:
            channel_id: The Teams conversation/channel ID (ignored for webhook).
            card: The AlertCard to render and send.

        Returns:
            MessageResult with sent message details.
        """
        # Use webhook if available (simpler, no bot required)
        if self.webhook_url:
            return await self._send_via_webhook(card)

        # Fall back to Bot Framework
        return await self._send_via_bot(channel_id, card)

    async def _send_via_webhook(self, card: AlertCard) -> MessageResult:
        """Send alert via incoming webhook."""
        try:
            message_card = self._build_webhook_message_card(card)

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(self.webhook_url, json=message_card)
                response.raise_for_status()

            logger.info(
                "Sent Teams alert via webhook",
                alert_id=card.source_alert_id,
            )

            return MessageResult(
                message_id=card.source_alert_id,  # Webhook doesn't return message ID
                channel_id="webhook",
                success=True,
                action="sent",
                sent_at=datetime.utcnow(),
            )

        except Exception as e:
            logger.error(
                "Failed to send Teams alert via webhook",
                error=str(e),
            )
            return MessageResult(
                message_id="",
                channel_id="webhook",
                success=False,
                error=str(e),
            )

    async def _send_via_bot(self, channel_id: str, card: AlertCard) -> MessageResult:
        """Send alert via Bot Framework."""
        try:
            client = await self._get_client()

            adaptive_card = self._build_adaptive_card(card)

            # Build the activity
            activity = {
                "type": "message",
                "attachments": [
                    {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": adaptive_card,
                    }
                ],
            }

            # Send to conversation
            url = f"{self.service_url}/v3/conversations/{channel_id}/activities"
            response = await client.post(url, json=activity)
            response.raise_for_status()

            data = response.json()
            message_id = data.get("id", "")

            logger.info(
                "Sent Teams alert card via bot",
                channel_id=channel_id,
                message_id=message_id,
                alert_id=card.source_alert_id,
            )

            return MessageResult(
                message_id=message_id,
                channel_id=channel_id,
                success=True,
                action="sent",
                sent_at=datetime.utcnow(),
                raw_response=data,
            )

        except Exception as e:
            logger.error(
                "Failed to send Teams alert via bot",
                channel_id=channel_id,
                error=str(e),
            )
            return MessageResult(
                message_id="",
                channel_id=channel_id,
                success=False,
                error=str(e),
            )

    async def update_message(
        self,
        channel_id: str,
        message_id: str,
        card: AlertCard,
    ) -> MessageResult:
        """
        Update an existing alert message.

        Args:
            channel_id: The Teams conversation/channel ID.
            message_id: The message ID to update.
            card: The updated AlertCard.

        Returns:
            MessageResult with update details.
        """
        try:
            client = await self._get_client()

            adaptive_card = self._build_adaptive_card(card)

            activity = {
                "type": "message",
                "id": message_id,
                "attachments": [
                    {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": adaptive_card,
                    }
                ],
            }

            url = f"{self.service_url}/v3/conversations/{channel_id}/activities/{message_id}"
            response = await client.put(url, json=activity)
            response.raise_for_status()

            data = response.json()

            logger.info(
                "Updated Teams alert card",
                channel_id=channel_id,
                message_id=message_id,
            )

            return MessageResult(
                message_id=message_id,
                channel_id=channel_id,
                success=True,
                action="updated",
                raw_response=data,
            )

        except Exception as e:
            logger.error(
                "Failed to update Teams message",
                channel_id=channel_id,
                message_id=message_id,
                error=str(e),
            )
            return MessageResult(
                message_id=message_id,
                channel_id=channel_id,
                success=False,
                error=str(e),
            )

    async def send_text_message(
        self,
        channel_id: str,
        text: str,
        thread_id: Optional[str] = None,
    ) -> MessageResult:
        """
        Send a plain text message to Teams.

        Args:
            channel_id: The Teams conversation/channel ID.
            text: The message text (supports markdown).
            thread_id: Optional message ID to reply to.

        Returns:
            MessageResult with sent message details.
        """
        try:
            client = await self._get_client()

            activity = {
                "type": "message",
                "text": text,
                "textFormat": "markdown",
            }

            if thread_id:
                activity["replyToId"] = thread_id

            url = f"{self.service_url}/v3/conversations/{channel_id}/activities"
            response = await client.post(url, json=activity)
            response.raise_for_status()

            data = response.json()
            message_id = data.get("id", "")

            logger.info(
                "Sent Teams text message",
                channel_id=channel_id,
                message_id=message_id,
            )

            return MessageResult(
                message_id=message_id,
                channel_id=channel_id,
                thread_id=thread_id or "",
                success=True,
                action="sent",
                sent_at=datetime.utcnow(),
                raw_response=data,
            )

        except Exception as e:
            logger.error(
                "Failed to send Teams message",
                channel_id=channel_id,
                error=str(e),
            )
            return MessageResult(
                message_id="",
                channel_id=channel_id,
                success=False,
                error=str(e),
            )

    async def handle_action_callback(
        self,
        activity: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Handle an action button callback from Teams.

        This is called when a user clicks a button on an Adaptive Card.

        Args:
            activity: The Bot Framework activity containing the action.

        Returns:
            Response to send back to Teams.
        """
        action_data = activity.get("value", {})
        action_type = action_data.get("action", "")
        alert_id = action_data.get("alert_id", "")
        source = action_data.get("source", "")
        hostname = action_data.get("hostname", "")

        # Get user info
        from_user = activity.get("from", {})
        user_name = from_user.get("name", "Unknown User")
        user_id = from_user.get("id", "")

        logger.info(
            "Received Teams action callback",
            action=action_type,
            alert_id=alert_id,
            user=user_name,
        )

        # Return action details for processing by the caller
        return {
            "action": action_type,
            "alert_id": alert_id,
            "source": source,
            "hostname": hostname,
            "performed_by": user_name,
            "user_id": user_id,
            "conversation_id": activity.get("conversation", {}).get("id", ""),
            "activity_id": activity.get("id", ""),
            "raw_activity": activity,
        }

    async def send_action_confirmation(
        self,
        channel_id: str,
        reply_to_id: str,
        action: str,
        hostname: str,
        performed_by: str,
        success: bool = True,
    ) -> MessageResult:
        """
        Send a confirmation message after an action is performed.

        Args:
            channel_id: The conversation ID.
            reply_to_id: The message ID to reply to.
            action: The action that was performed.
            hostname: The hostname involved.
            performed_by: Who performed the action.
            success: Whether the action succeeded.

        Returns:
            MessageResult.
        """
        if success:
            if action == "resolve":
                text = f"**Alert Resolved**\n\n{hostname} - Resolved by {performed_by}"
            elif action == "contain":
                text = f"**Endpoint Contained**\n\n{hostname} has been network isolated by {performed_by}"
            elif action == "escalate":
                text = f"**Alert Escalated**\n\nEscalated to senior engineer by {performed_by}"
            else:
                text = f"**Action Completed**: {action} on {hostname} by {performed_by}"
        else:
            text = f"**Action Failed**: {action} on {hostname}\n\nPlease try again or contact support."

        return await self.send_text_message(channel_id, text, reply_to_id)

    async def test_connectivity(self) -> bool:
        """
        Test connectivity to Teams Bot Framework.

        Returns:
            True if connection is successful.
        """
        try:
            # Try to get an access token
            await self._get_access_token()

            logger.info("Teams Bot connectivity test passed")
            return True

        except Exception as e:
            logger.error("Teams Bot connectivity test failed", error=str(e))
            raise

    async def close(self) -> None:
        """Clean up HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
