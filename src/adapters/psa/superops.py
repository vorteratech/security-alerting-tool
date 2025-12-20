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
    SuperOps PSA API adapter using GraphQL.

    Supports:
    - Ticket creation
    - Ticket updates
    - Adding notes
    - Ticket closure
    """

    # GraphQL endpoint
    GRAPHQL_URL = "https://api.superops.ai/msp"

    def __init__(self, api_key: str, api_url: str, **kwargs):
        """
        Initialize the SuperOps adapter.

        Args:
            api_key: SuperOps API key.
            api_url: SuperOps API URL (not used - GraphQL endpoint is fixed).
            **kwargs: Additional config including:
                - subdomain: Customer subdomain (required)
                - default_client_id: Default client for tickets
        """
        super().__init__(api_key, api_url, **kwargs)
        self.subdomain = kwargs.get("subdomain", "")
        self.default_client_id = kwargs.get("default_client_id", "")
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def provider_name(self) -> str:
        return "superops"

    def _get_headers(self) -> dict[str, str]:
        """Get headers for GraphQL requests."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "CustomerSubDomain": self.subdomain,
        }

    def _map_priority(self, priority: TicketPriority) -> str:
        """Map internal priority to SuperOps priority."""
        mapping = {
            TicketPriority.CRITICAL: "CRITICAL",
            TicketPriority.HIGH: "HIGH",
            TicketPriority.MEDIUM: "MEDIUM",
            TicketPriority.LOW: "LOW",
        }
        return mapping.get(priority, "MEDIUM")

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
        Create a new ticket in SuperOps via GraphQL.

        Args:
            alert: The alert to create a ticket for.
            title: Ticket title.
            description: Ticket description.
            priority: Ticket priority.
            client_id: Optional client ID (uses default if not provided).

        Returns:
            TicketResult with created ticket details.
        """
        if not self.subdomain:
            return TicketResult(
                ticket_id="",
                success=False,
                error="SuperOps subdomain not configured",
            )

        target_client_id = client_id or self.default_client_id
        if not target_client_id:
            return TicketResult(
                ticket_id="",
                success=False,
                error="No client ID configured for SuperOps tickets",
            )

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
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
                            "subject": title,
                            "description": description,
                            "priority": self._map_priority(priority),
                            "source": "INTEGRATION",
                            "requestType": "INCIDENT",
                            "client": {
                                "accountId": target_client_id
                            }
                        }
                    }
                }

                response = await client.post(
                    self.GRAPHQL_URL,
                    headers=self._get_headers(),
                    json=graphql_mutation,
                )

                if response.status_code != 200:
                    return TicketResult(
                        ticket_id="",
                        success=False,
                        error=f"SuperOps API error ({response.status_code}): {response.text[:200]}",
                    )

                data = response.json()

                # Check for GraphQL errors
                if "errors" in data:
                    first_error = data["errors"][0]
                    error_msg = first_error.get("message") or str(first_error)
                    return TicketResult(
                        ticket_id="",
                        success=False,
                        error=f"SuperOps GraphQL error: {error_msg}",
                    )

                # Extract ticket info
                ticket = data.get("data", {}).get("createTicket", {})
                ticket_id = ticket.get("ticketId", "")
                display_id = ticket.get("displayId", "")

                logger.info(
                    "Created SuperOps ticket",
                    ticket_id=ticket_id,
                    display_id=display_id,
                    alert_id=alert.source_alert_id,
                )

                return TicketResult(
                    ticket_id=ticket_id,
                    ticket_number=str(display_id),
                    ticket_url=f"https://{self.subdomain}.superops.ai/#/tickets/{ticket_id}/ticket",
                    success=True,
                    action="created",
                    title=title,
                    priority=self._map_priority(priority),
                    status="new",
                    client_name=alert.client_name,
                    created_at=datetime.utcnow(),
                    raw_response=data,
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
        """Update ticket - not yet implemented for GraphQL."""
        logger.warning("update_ticket not yet implemented for SuperOps GraphQL")
        return TicketResult(
            ticket_id=ticket_id,
            success=False,
            error="Not implemented",
        )

    async def add_note(
        self,
        ticket_id: str,
        note: TicketNote,
    ) -> bool:
        """Add note - not yet implemented for GraphQL."""
        logger.warning("add_note not yet implemented for SuperOps GraphQL")
        return False

    async def close_ticket(
        self,
        ticket_id: str,
        resolution_note: str = "",
    ) -> TicketResult:
        """Close ticket - not yet implemented for GraphQL."""
        logger.warning("close_ticket not yet implemented for SuperOps GraphQL")
        return TicketResult(
            ticket_id=ticket_id,
            success=False,
            error="Not implemented",
        )

    async def get_ticket(self, ticket_id: str) -> Optional[TicketResult]:
        """Get ticket - not yet implemented for GraphQL."""
        logger.warning("get_ticket not yet implemented for SuperOps GraphQL")
        return None

    async def test_connectivity(self) -> bool:
        """Test API connectivity to SuperOps via GraphQL."""
        if not self.subdomain:
            raise ValueError("SuperOps subdomain not configured")

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
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
                    self.GRAPHQL_URL,
                    headers=self._get_headers(),
                    json=graphql_query,
                )
                response.raise_for_status()

                data = response.json()
                if "errors" in data:
                    raise ValueError(f"GraphQL error: {data['errors']}")

                logger.info("SuperOps connectivity test passed")
                return True

        except Exception as e:
            logger.error("SuperOps connectivity test failed", error=str(e))
            raise

    async def close(self) -> None:
        """Clean up resources."""
        pass  # No persistent client to close
