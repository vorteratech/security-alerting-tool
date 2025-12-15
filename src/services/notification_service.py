"""
Notification Service.

Handles sending notifications to chat platforms (Teams, Slack, etc.).
"""

import json
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..adapters.edr.base import Alert
from ..adapters.chat import TeamsAdapter
from ..adapters.chat.base import BaseChatAdapter, MessageResult, AlertCard
from ..config.logging import get_logger
from ..config.settings import Settings
from ..database.models import IntegrationSetting
from ..security.encryption import create_encryption_service
from .alert_formatter import AlertFormatterService

logger = get_logger(__name__)


class NotificationService:
    """
    Service for sending notifications to chat platforms.

    Handles:
    - Alert notifications to configured channels
    - Update notifications (resolution, containment, escalation)
    - Multi-platform support (Teams, Slack in future)
    """

    def __init__(
        self,
        settings: Settings,
        db_session: AsyncSession,
        formatter: Optional[AlertFormatterService] = None,
    ):
        """
        Initialize the notification service.

        Args:
            settings: Application settings.
            db_session: Database session for loading integrations.
            formatter: Optional alert formatter.
        """
        self.settings = settings
        self.db = db_session
        self.formatter = formatter or AlertFormatterService(
            action_callback_url=settings.action_callback_base_url
        )
        self._adapters: dict[str, BaseChatAdapter] = {}
        self._encryption = None
        self._primary_provider: Optional[str] = None
        self._default_channel: Optional[str] = None

    async def _get_encryption(self):
        """Get encryption service."""
        if self._encryption is None:
            self._encryption = create_encryption_service(
                self.settings.master_encryption_key
            )
        return self._encryption

    async def _load_chat_integrations(self) -> list[IntegrationSetting]:
        """Load all enabled chat integrations."""
        from sqlalchemy import select

        query = select(IntegrationSetting).where(
            IntegrationSetting.integration_type == "chat",
            IntegrationSetting.enabled == True,
        ).order_by(
            IntegrationSetting.is_primary.desc()
        )
        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def _get_adapter(self, provider: str) -> Optional[BaseChatAdapter]:
        """Get or create chat adapter for a provider."""
        if provider in self._adapters:
            return self._adapters[provider]

        from sqlalchemy import select, and_

        query = select(IntegrationSetting).where(
            and_(
                IntegrationSetting.integration_type == "chat",
                IntegrationSetting.provider == provider,
                IntegrationSetting.enabled == True,
            )
        )
        result = await self.db.execute(query)
        integration = result.scalar_one_or_none()

        if not integration:
            logger.warning(f"No enabled chat integration found: {provider}")
            return None

        encryption = await self._get_encryption()
        config = json.loads(integration.config_json) if integration.config_json else {}

        # Decrypt credentials
        app_id = ""
        app_password = ""
        if integration.api_key_encrypted:
            app_id = encryption.decrypt(integration.api_key_encrypted)
        if integration.api_secret_encrypted:
            app_password = encryption.decrypt(integration.api_secret_encrypted)

        # Create adapter based on provider
        if provider == "teams":
            adapter = TeamsAdapter(
                app_id=app_id,
                app_password=app_password,
                tenant_id=config.get("tenant_id", ""),
                service_url=config.get("service_url", ""),
                default_channel_id=config.get("default_channel_id", ""),
                action_callback_url=self.settings.action_callback_base_url,
            )
            self._default_channel = config.get("default_channel_id", "")
        else:
            logger.error(f"Unknown chat provider: {provider}")
            return None

        self._adapters[provider] = adapter

        if integration.is_primary:
            self._primary_provider = provider

        return adapter

    async def get_primary_adapter(self) -> Optional[BaseChatAdapter]:
        """Get the primary chat adapter."""
        integrations = await self._load_chat_integrations()

        if not integrations:
            return None

        primary = integrations[0]
        return await self._get_adapter(primary.provider)

    async def send_alert_notification(
        self,
        alert: Alert,
        ai_analysis: Optional[dict[str, Any]] = None,
        enrichment: Optional[dict[str, Any]] = None,
        ticket_id: str = "",
        ticket_url: str = "",
        channel_id: Optional[str] = None,
    ) -> Optional[MessageResult]:
        """
        Send an alert notification to chat.

        Args:
            alert: The alert to notify about.
            ai_analysis: Optional AI analysis.
            enrichment: Optional threat intel.
            ticket_id: Optional ticket ID.
            ticket_url: Optional ticket URL.
            channel_id: Optional channel ID (uses default if not specified).

        Returns:
            MessageResult if successful.
        """
        adapter = await self.get_primary_adapter()
        if not adapter:
            logger.warning("No chat adapter available for notification")
            return None

        # Format the alert card
        card = self.formatter._format_card(
            alert=alert,
            ai_analysis=ai_analysis,
            enrichment=enrichment,
            ticket_id=ticket_id,
            ticket_url=ticket_url,
        )

        # Determine channel
        target_channel = channel_id or self._default_channel
        if not target_channel:
            logger.error("No channel ID specified and no default channel configured")
            return None

        try:
            result = await adapter.send_alert(target_channel, card)

            if result.success:
                logger.info(
                    "Sent alert notification",
                    provider=adapter.provider_name,
                    channel_id=target_channel,
                    message_id=result.message_id,
                    alert_id=alert.source_alert_id,
                )
            else:
                logger.error(
                    "Failed to send alert notification",
                    provider=adapter.provider_name,
                    error=result.error,
                )

            return result

        except Exception as e:
            logger.error(
                "Exception sending alert notification",
                provider=adapter.provider_name,
                error=str(e),
            )
            return MessageResult(
                message_id="",
                channel_id=target_channel,
                success=False,
                error=str(e),
            )

    async def send_resolution_notification(
        self,
        alert: Alert,
        resolved_by: str,
        channel_id: Optional[str] = None,
        thread_id: Optional[str] = None,
    ) -> Optional[MessageResult]:
        """
        Send a resolution notification.

        Args:
            alert: The resolved alert.
            resolved_by: Who resolved the alert.
            channel_id: Optional channel ID.
            thread_id: Optional thread to reply to.

        Returns:
            MessageResult if successful.
        """
        adapter = await self.get_primary_adapter()
        if not adapter:
            return None

        target_channel = channel_id or self._default_channel
        if not target_channel:
            return None

        try:
            return await adapter.send_resolution_notification(
                channel_id=target_channel,
                alert=alert,
                resolved_by=resolved_by,
                thread_id=thread_id,
            )
        except Exception as e:
            logger.error(
                "Failed to send resolution notification",
                error=str(e),
            )
            return None

    async def send_containment_notification(
        self,
        alert: Optional[Alert],
        contained_by: str,
        success: bool,
        channel_id: Optional[str] = None,
        thread_id: Optional[str] = None,
        hostname: str = "",
    ) -> Optional[MessageResult]:
        """
        Send a containment notification.

        Args:
            alert: The alert for contained endpoint (optional).
            contained_by: Who triggered containment.
            success: Whether containment succeeded.
            channel_id: Optional channel ID.
            thread_id: Optional thread to reply to.
            hostname: Hostname if alert not provided.

        Returns:
            MessageResult if successful.
        """
        adapter = await self.get_primary_adapter()
        if not adapter:
            return None

        target_channel = channel_id or self._default_channel
        if not target_channel:
            return None

        host = alert.hostname if alert else hostname
        status_text = "successfully isolated" if success else "FAILED to isolate"
        text = (
            f"**CONTAINMENT {'SUCCESS' if success else 'FAILED'}**\n\n"
            f"Endpoint **{host}** was {status_text}\n"
            f"Initiated by: {contained_by}"
        )

        if not success:
            text += "\n\n**MANUAL INTERVENTION REQUIRED**"

        try:
            return await adapter.send_text_message(
                channel_id=target_channel,
                text=text,
                thread_id=thread_id,
            )
        except Exception as e:
            logger.error(
                "Failed to send containment notification",
                error=str(e),
            )
            return None

    async def send_escalation_notification(
        self,
        alert: Alert,
        escalated_by: str,
        reason: str = "",
        channel_id: Optional[str] = None,
    ) -> Optional[MessageResult]:
        """
        Send an escalation notification.

        Args:
            alert: The escalated alert.
            escalated_by: Who escalated.
            reason: Optional reason.
            channel_id: Optional channel ID.

        Returns:
            MessageResult if successful.
        """
        adapter = await self.get_primary_adapter()
        if not adapter:
            return None

        target_channel = channel_id or self._default_channel
        if not target_channel:
            return None

        try:
            return await adapter.send_escalation_notification(
                channel_id=target_channel,
                alert=alert,
                escalated_by=escalated_by,
                reason=reason,
            )
        except Exception as e:
            logger.error(
                "Failed to send escalation notification",
                error=str(e),
            )
            return None

    async def update_alert_message(
        self,
        channel_id: str,
        message_id: str,
        alert: Alert,
        ai_analysis: Optional[dict[str, Any]] = None,
        enrichment: Optional[dict[str, Any]] = None,
        ticket_id: str = "",
        ticket_url: str = "",
        status_update: str = "",
    ) -> Optional[MessageResult]:
        """
        Update an existing alert message.

        Args:
            channel_id: The channel containing the message.
            message_id: The message ID to update.
            alert: The alert data.
            ai_analysis: Optional AI analysis.
            enrichment: Optional threat intel.
            ticket_id: Optional ticket ID.
            ticket_url: Optional ticket URL.
            status_update: Optional status update text.

        Returns:
            MessageResult if successful.
        """
        adapter = await self.get_primary_adapter()
        if not adapter:
            return None

        # Format updated card
        card = self.formatter._format_card(
            alert=alert,
            ai_analysis=ai_analysis,
            enrichment=enrichment,
            ticket_id=ticket_id,
            ticket_url=ticket_url,
        )

        try:
            return await adapter.update_message(channel_id, message_id, card)
        except Exception as e:
            logger.error(
                "Failed to update alert message",
                message_id=message_id,
                error=str(e),
            )
            return None

    async def send_text_message(
        self,
        channel_id: str,
        text: str,
        thread_id: Optional[str] = None,
    ) -> Optional[MessageResult]:
        """
        Send a plain text message.

        Args:
            channel_id: The channel ID.
            text: The message text.
            thread_id: Optional thread to reply to.

        Returns:
            MessageResult if successful.
        """
        adapter = await self.get_primary_adapter()
        if not adapter:
            return None

        target_channel = channel_id or self._default_channel
        if not target_channel:
            return None

        try:
            return await adapter.send_text_message(target_channel, text, thread_id)
        except Exception as e:
            logger.error(
                "Failed to send text message",
                error=str(e),
            )
            return None

    async def test_connectivity(self, provider: Optional[str] = None) -> bool:
        """
        Test chat connectivity.

        Args:
            provider: Optional specific provider to test.

        Returns:
            True if connection successful.
        """
        if provider:
            adapter = await self._get_adapter(provider)
        else:
            adapter = await self.get_primary_adapter()

        if not adapter:
            return False

        return await adapter.test_connectivity()

    async def close(self) -> None:
        """Clean up all adapters."""
        for adapter in self._adapters.values():
            await adapter.close()
        self._adapters.clear()
