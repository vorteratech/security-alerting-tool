"""
PSA Integration Service.

Handles ticket creation and management across PSA platforms.
"""

import json
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..adapters.edr.base import Alert
from ..adapters.psa import SuperOpsAdapter
from ..adapters.psa.base import BasePSAAdapter, TicketResult, TicketNote, TicketPriority, TicketStatus
from ..config.logging import get_logger
from ..config.settings import Settings
from ..database.models import IntegrationSetting
from ..security.encryption import create_encryption_service
from .alert_formatter import AlertFormatterService

logger = get_logger(__name__)


class PSAService:
    """
    Service for managing PSA integrations.

    Handles:
    - Ticket creation from alerts
    - Ticket updates and notes
    - Ticket closure
    - Multi-PSA support (primary + fallback)
    """

    def __init__(
        self,
        settings: Settings,
        db_session: AsyncSession,
        formatter: Optional[AlertFormatterService] = None,
    ):
        """
        Initialize the PSA service.

        Args:
            settings: Application settings.
            db_session: Database session for loading integrations.
            formatter: Optional alert formatter (created if not provided).
        """
        self.settings = settings
        self.db = db_session
        self.formatter = formatter or AlertFormatterService()
        self._adapters: dict[str, BasePSAAdapter] = {}
        self._encryption = None
        self._primary_provider: Optional[str] = None

    async def _get_encryption(self):
        """Get encryption service."""
        if self._encryption is None:
            self._encryption = create_encryption_service(
                self.settings.master_encryption_key
            )
        return self._encryption

    async def _load_psa_integrations(self) -> list[IntegrationSetting]:
        """Load all enabled PSA integrations."""
        from sqlalchemy import select

        query = select(IntegrationSetting).where(
            IntegrationSetting.integration_type == "psa",
            IntegrationSetting.enabled == True,
        ).order_by(
            IntegrationSetting.is_primary.desc()  # Primary first
        )
        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def _get_adapter(self, provider: str) -> Optional[BasePSAAdapter]:
        """Get or create PSA adapter for a provider."""
        if provider in self._adapters:
            return self._adapters[provider]

        from sqlalchemy import select, and_

        query = select(IntegrationSetting).where(
            and_(
                IntegrationSetting.integration_type == "psa",
                IntegrationSetting.provider == provider,
                IntegrationSetting.enabled == True,
            )
        )
        result = await self.db.execute(query)
        integration = result.scalar_one_or_none()

        if not integration:
            logger.warning(f"No enabled PSA integration found: {provider}")
            return None

        encryption = await self._get_encryption()
        config = json.loads(integration.config_json) if integration.config_json else {}

        # Decrypt API key
        api_key = ""
        if integration.api_key_encrypted:
            api_key = encryption.decrypt(integration.api_key_encrypted)

        # Create adapter based on provider
        if provider == "superops":
            adapter = SuperOpsAdapter(
                api_key=api_key,
                api_url=config.get("api_url", "https://api.superops.ai"),
                default_client_id=config.get("default_client_id", ""),
                default_assignee=config.get("default_assignee", ""),
                ticket_type=config.get("ticket_type", "incident"),
            )
        else:
            logger.error(f"Unknown PSA provider: {provider}")
            return None

        self._adapters[provider] = adapter

        if integration.is_primary:
            self._primary_provider = provider

        return adapter

    async def get_primary_adapter(self) -> Optional[BasePSAAdapter]:
        """Get the primary PSA adapter."""
        integrations = await self._load_psa_integrations()

        if not integrations:
            return None

        # Use first (primary) integration
        primary = integrations[0]
        return await self._get_adapter(primary.provider)

    async def create_ticket_from_alert(
        self,
        alert: Alert,
        ai_analysis: Optional[dict[str, Any]] = None,
        enrichment: Optional[dict[str, Any]] = None,
        client_id: Optional[str] = None,
    ) -> Optional[TicketResult]:
        """
        Create a ticket from an alert.

        Args:
            alert: The alert to create a ticket for.
            ai_analysis: Optional AI analysis data.
            enrichment: Optional threat intel data.
            client_id: Optional PSA client ID.

        Returns:
            TicketResult if successful, None otherwise.
        """
        adapter = await self.get_primary_adapter()
        if not adapter:
            logger.warning("No PSA adapter available for ticket creation")
            return None

        # Format the alert for the ticket
        formatted = self.formatter.format_alert(
            alert=alert,
            ai_analysis=ai_analysis,
            enrichment=enrichment,
        )

        try:
            result = await adapter.create_ticket(
                alert=alert,
                title=formatted.ticket.title,
                description=formatted.ticket.description,
                priority=formatted.ticket.priority,
                client_id=client_id,
            )

            if result.success:
                logger.info(
                    "Created PSA ticket",
                    provider=adapter.provider_name,
                    ticket_id=result.ticket_id,
                    ticket_number=result.ticket_number,
                    alert_id=alert.source_alert_id,
                )
            else:
                logger.error(
                    "Failed to create PSA ticket",
                    provider=adapter.provider_name,
                    error=result.error,
                )

            return result

        except Exception as e:
            logger.error(
                "Exception creating PSA ticket",
                provider=adapter.provider_name,
                error=str(e),
            )
            return TicketResult(
                ticket_id="",
                success=False,
                error=str(e),
            )

    async def add_note_to_ticket(
        self,
        ticket_id: str,
        content: str,
        is_internal: bool = True,
        author: str = "Security Alert System",
        provider: Optional[str] = None,
    ) -> bool:
        """
        Add a note to an existing ticket.

        Args:
            ticket_id: The ticket ID.
            content: The note content.
            is_internal: Whether this is an internal note.
            author: Note author name.
            provider: Optional specific provider (uses primary if not specified).

        Returns:
            True if successful.
        """
        if provider:
            adapter = await self._get_adapter(provider)
        else:
            adapter = await self.get_primary_adapter()

        if not adapter:
            logger.warning("No PSA adapter available for adding note")
            return False

        note = TicketNote(
            content=content,
            is_internal=is_internal,
            author=author,
        )

        try:
            return await adapter.add_note(ticket_id, note)
        except Exception as e:
            logger.error(
                "Failed to add note to ticket",
                ticket_id=ticket_id,
                error=str(e),
            )
            return False

    async def close_ticket(
        self,
        ticket_id: str,
        resolution_note: str = "",
        provider: Optional[str] = None,
    ) -> Optional[TicketResult]:
        """
        Close a ticket.

        Args:
            ticket_id: The ticket ID.
            resolution_note: Optional resolution note.
            provider: Optional specific provider.

        Returns:
            TicketResult if successful.
        """
        if provider:
            adapter = await self._get_adapter(provider)
        else:
            adapter = await self.get_primary_adapter()

        if not adapter:
            logger.warning("No PSA adapter available for closing ticket")
            return None

        try:
            return await adapter.close_ticket(ticket_id, resolution_note)
        except Exception as e:
            logger.error(
                "Failed to close ticket",
                ticket_id=ticket_id,
                error=str(e),
            )
            return None

    async def update_ticket(
        self,
        ticket_id: str,
        status: Optional[TicketStatus] = None,
        priority: Optional[TicketPriority] = None,
        assigned_to: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> Optional[TicketResult]:
        """
        Update a ticket.

        Args:
            ticket_id: The ticket ID.
            status: Optional new status.
            priority: Optional new priority.
            assigned_to: Optional new assignee.
            provider: Optional specific provider.

        Returns:
            TicketResult if successful.
        """
        if provider:
            adapter = await self._get_adapter(provider)
        else:
            adapter = await self.get_primary_adapter()

        if not adapter:
            logger.warning("No PSA adapter available for updating ticket")
            return None

        try:
            return await adapter.update_ticket(
                ticket_id=ticket_id,
                status=status,
                priority=priority,
                assigned_to=assigned_to,
            )
        except Exception as e:
            logger.error(
                "Failed to update ticket",
                ticket_id=ticket_id,
                error=str(e),
            )
            return None

    async def get_ticket(
        self,
        ticket_id: str,
        provider: Optional[str] = None,
    ) -> Optional[TicketResult]:
        """
        Get ticket details.

        Args:
            ticket_id: The ticket ID.
            provider: Optional specific provider.

        Returns:
            TicketResult with ticket details.
        """
        if provider:
            adapter = await self._get_adapter(provider)
        else:
            adapter = await self.get_primary_adapter()

        if not adapter:
            return None

        try:
            return await adapter.get_ticket(ticket_id)
        except Exception as e:
            logger.error(
                "Failed to get ticket",
                ticket_id=ticket_id,
                error=str(e),
            )
            return None

    async def test_connectivity(self, provider: Optional[str] = None) -> bool:
        """
        Test PSA connectivity.

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
