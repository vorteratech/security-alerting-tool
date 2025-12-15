"""
SuperOps PSA adapter.

Handles ticket creation and management in SuperOps.
"""

from datetime import datetime
from typing import Any, Optional

import httpx

from ...config.logging import get_logger
from ..edr.base import Alert
from .base import BasePSAAdapter, TicketResult, TicketNote, TicketPriority, TicketStatus

logger = get_logger(__name__)


class SuperOpsAdapter(BasePSAAdapter):
    """
    SuperOps PSA API adapter.

    Supports:
    - Ticket creation
    - Ticket updates
    - Adding notes
    - Ticket closure
    """

    def __init__(self, api_key: str, api_url: str, **kwargs):
        """
        Initialize the SuperOps adapter.

        Args:
            api_key: SuperOps API key.
            api_url: SuperOps API URL (e.g., https://api.superops.ai).
            **kwargs: Additional config including:
                - default_client_id: Default client for tickets
                - default_assignee: Default technician to assign
                - ticket_type: Type of ticket to create
        """
        super().__init__(api_key, api_url, **kwargs)
        self.default_client_id = kwargs.get("default_client_id", "")
        self.default_assignee = kwargs.get("default_assignee", "")
        self.ticket_type = kwargs.get("ticket_type", "incident")
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def provider_name(self) -> str:
        return "superops"

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.api_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )
        return self._client

    def _map_priority(self, priority: TicketPriority) -> str:
        """Map internal priority to SuperOps priority."""
        mapping = {
            TicketPriority.CRITICAL: "critical",
            TicketPriority.HIGH: "high",
            TicketPriority.MEDIUM: "medium",
            TicketPriority.LOW: "low",
        }
        return mapping.get(priority, "medium")

    def _map_severity_to_priority(self, severity: str) -> TicketPriority:
        """Map alert severity to ticket priority."""
        mapping = {
            "critical": TicketPriority.CRITICAL,
            "high": TicketPriority.HIGH,
            "medium": TicketPriority.MEDIUM,
            "low": TicketPriority.LOW,
            "info": TicketPriority.LOW,
        }
        return mapping.get(severity.lower(), TicketPriority.MEDIUM)

    async def create_ticket(
        self,
        alert: Alert,
        title: str,
        description: str,
        priority: TicketPriority = TicketPriority.MEDIUM,
        client_id: Optional[str] = None,
    ) -> TicketResult:
        """
        Create a new ticket in SuperOps.

        Args:
            alert: The alert to create a ticket for.
            title: Ticket title.
            description: Ticket description.
            priority: Ticket priority.
            client_id: Optional client ID (uses default if not provided).

        Returns:
            TicketResult with created ticket details.
        """
        try:
            client = await self._get_client()

            # Build ticket payload
            payload = {
                "subject": title,
                "description": description,
                "priority": self._map_priority(priority),
                "type": self.ticket_type,
                "source": "api",
                "tags": ["security-alert", f"edr-{alert.source}"],
            }

            # Add client if specified
            if client_id or self.default_client_id:
                payload["client_id"] = client_id or self.default_client_id

            # Add assignee if configured
            if self.default_assignee:
                payload["assignee"] = self.default_assignee

            # Add custom fields for alert tracking
            payload["custom_fields"] = {
                "edr_source": alert.source,
                "edr_alert_id": alert.source_alert_id,
                "hostname": alert.hostname,
                "threat_name": alert.threat_name,
            }

            response = await client.post("/v1/tickets", json=payload)
            response.raise_for_status()

            data = response.json()
            ticket_data = data.get("data", data)

            ticket_id = str(ticket_data.get("id", ""))
            ticket_number = ticket_data.get("ticket_number", ticket_data.get("number", ""))

            logger.info(
                "Created SuperOps ticket",
                ticket_id=ticket_id,
                ticket_number=ticket_number,
                alert_id=alert.source_alert_id,
            )

            return TicketResult(
                ticket_id=ticket_id,
                ticket_number=str(ticket_number),
                ticket_url=f"{self.api_url.replace('/api', '')}/tickets/{ticket_id}",
                success=True,
                action="created",
                title=title,
                priority=self._map_priority(priority),
                status="new",
                client_name=alert.client_name,
                created_at=datetime.utcnow(),
                raw_response=data,
            )

        except httpx.HTTPStatusError as e:
            logger.error(
                "Failed to create SuperOps ticket",
                status_code=e.response.status_code,
                error=str(e),
            )
            return TicketResult(
                ticket_id="",
                success=False,
                error=f"HTTP {e.response.status_code}: {str(e)}",
            )
        except Exception as e:
            logger.error("Failed to create SuperOps ticket", error=str(e))
            return TicketResult(
                ticket_id="",
                success=False,
                error=str(e),
            )

    async def update_ticket(
        self,
        ticket_id: str,
        status: Optional[TicketStatus] = None,
        priority: Optional[TicketPriority] = None,
        assigned_to: Optional[str] = None,
    ) -> TicketResult:
        """
        Update an existing ticket.

        Args:
            ticket_id: The ticket ID.
            status: New status.
            priority: New priority.
            assigned_to: New assignee.

        Returns:
            TicketResult with updated ticket.
        """
        try:
            client = await self._get_client()

            payload = {}
            if status:
                status_map = {
                    TicketStatus.NEW: "new",
                    TicketStatus.OPEN: "open",
                    TicketStatus.IN_PROGRESS: "in_progress",
                    TicketStatus.PENDING: "pending",
                    TicketStatus.RESOLVED: "resolved",
                    TicketStatus.CLOSED: "closed",
                }
                payload["status"] = status_map.get(status, "open")

            if priority:
                payload["priority"] = self._map_priority(priority)

            if assigned_to:
                payload["assignee"] = assigned_to

            if not payload:
                return TicketResult(
                    ticket_id=ticket_id,
                    success=True,
                    action="no_changes",
                )

            response = await client.patch(f"/v1/tickets/{ticket_id}", json=payload)
            response.raise_for_status()

            data = response.json()

            logger.info("Updated SuperOps ticket", ticket_id=ticket_id)

            return TicketResult(
                ticket_id=ticket_id,
                success=True,
                action="updated",
                updated_at=datetime.utcnow(),
                raw_response=data,
            )

        except Exception as e:
            logger.error("Failed to update SuperOps ticket", ticket_id=ticket_id, error=str(e))
            return TicketResult(
                ticket_id=ticket_id,
                success=False,
                error=str(e),
            )

    async def add_note(
        self,
        ticket_id: str,
        note: TicketNote,
    ) -> bool:
        """
        Add a note to a ticket.

        Args:
            ticket_id: The ticket ID.
            note: The note to add.

        Returns:
            True if successful.
        """
        try:
            client = await self._get_client()

            payload = {
                "content": note.content,
                "is_private": note.is_internal,
                "author": note.author,
            }

            response = await client.post(f"/v1/tickets/{ticket_id}/notes", json=payload)
            response.raise_for_status()

            logger.info("Added note to SuperOps ticket", ticket_id=ticket_id)
            return True

        except Exception as e:
            logger.error("Failed to add note to ticket", ticket_id=ticket_id, error=str(e))
            return False

    async def close_ticket(
        self,
        ticket_id: str,
        resolution_note: str = "",
    ) -> TicketResult:
        """
        Close a ticket.

        Args:
            ticket_id: The ticket ID.
            resolution_note: Optional resolution note.

        Returns:
            TicketResult with closed ticket.
        """
        try:
            # Add resolution note if provided
            if resolution_note:
                await self.add_note(
                    ticket_id,
                    TicketNote(
                        content=f"Resolution: {resolution_note}",
                        is_internal=False,
                    ),
                )

            # Update status to closed
            return await self.update_ticket(ticket_id, status=TicketStatus.CLOSED)

        except Exception as e:
            logger.error("Failed to close ticket", ticket_id=ticket_id, error=str(e))
            return TicketResult(
                ticket_id=ticket_id,
                success=False,
                error=str(e),
            )

    async def get_ticket(self, ticket_id: str) -> Optional[TicketResult]:
        """
        Get ticket details.

        Args:
            ticket_id: The ticket ID.

        Returns:
            TicketResult with ticket details, or None if not found.
        """
        try:
            client = await self._get_client()

            response = await client.get(f"/v1/tickets/{ticket_id}")

            if response.status_code == 404:
                return None

            response.raise_for_status()
            data = response.json()
            ticket_data = data.get("data", data)

            return TicketResult(
                ticket_id=ticket_id,
                ticket_number=str(ticket_data.get("ticket_number", "")),
                success=True,
                title=ticket_data.get("subject", ""),
                priority=ticket_data.get("priority", ""),
                status=ticket_data.get("status", ""),
                assigned_to=ticket_data.get("assignee", ""),
                raw_response=data,
            )

        except Exception as e:
            logger.error("Failed to get ticket", ticket_id=ticket_id, error=str(e))
            return None

    async def test_connectivity(self) -> bool:
        """
        Test API connectivity to SuperOps.

        Returns:
            True if connection is successful.
        """
        try:
            client = await self._get_client()

            # Try to list tickets (limit 1) to test auth
            response = await client.get("/v1/tickets", params={"limit": 1})
            response.raise_for_status()

            logger.info("SuperOps connectivity test passed")
            return True

        except Exception as e:
            logger.error("SuperOps connectivity test failed", error=str(e))
            raise

    async def close(self) -> None:
        """Clean up HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
