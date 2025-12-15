"""
Base PSA (Professional Services Automation) adapter interface.

Defines the abstract interface for PSA/ticketing integrations
(SuperOps, ConnectWise, Autotask, etc.).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from ..edr.base import Alert


class TicketPriority(Enum):
    """Standard ticket priority levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TicketStatus(Enum):
    """Standard ticket status values."""

    NEW = "new"
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING = "pending"
    RESOLVED = "resolved"
    CLOSED = "closed"


@dataclass
class TicketResult:
    """
    Result of ticket creation or update.

    Contains ticket details and metadata from the PSA.
    """

    # Ticket identification
    ticket_id: str  # ID in the PSA system
    ticket_number: str = ""  # Human-readable ticket number
    ticket_url: str = ""  # URL to view ticket in PSA

    # Status
    success: bool = True
    action: str = "created"  # created, updated, closed

    # Ticket details
    title: str = ""
    priority: str = "medium"
    status: str = "new"
    assigned_to: str = ""
    client_name: str = ""

    # Timestamps
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    # Metadata
    raw_response: Optional[dict[str, Any]] = None

    # Error handling
    error: Optional[str] = None


@dataclass
class TicketNote:
    """A note/comment to add to a ticket."""

    content: str
    is_internal: bool = True  # Internal vs client-visible note
    author: str = "Security Alerting Tool"
    timestamp: datetime = field(default_factory=datetime.utcnow)


class BasePSAAdapter(ABC):
    """
    Abstract base class for PSA/ticketing adapters.

    Implement this interface for each PSA platform
    (SuperOps, ConnectWise, Autotask, etc.).
    """

    def __init__(self, api_key: str, api_url: str, **kwargs):
        """
        Initialize the PSA adapter.

        Args:
            api_key: API key for authentication.
            api_url: Base URL for the PSA API.
            **kwargs: Additional provider-specific configuration.
        """
        self.api_key = api_key
        self.api_url = api_url.rstrip("/")
        self.config = kwargs

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name (e.g., 'superops', 'connectwise')."""
        pass

    @abstractmethod
    async def create_ticket(
        self,
        alert: Alert,
        title: str,
        description: str,
        priority: TicketPriority = TicketPriority.MEDIUM,
        client_id: Optional[str] = None,
    ) -> TicketResult:
        """
        Create a new ticket from an alert.

        Args:
            alert: The alert to create a ticket for.
            title: Ticket title.
            description: Ticket description/body.
            priority: Ticket priority.
            client_id: Optional client ID in the PSA (for mapping).

        Returns:
            TicketResult with created ticket details.
        """
        pass

    @abstractmethod
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
            ticket_id: The ticket ID in the PSA.
            status: New status (optional).
            priority: New priority (optional).
            assigned_to: New assignee (optional).

        Returns:
            TicketResult with updated ticket details.
        """
        pass

    @abstractmethod
    async def add_note(
        self,
        ticket_id: str,
        note: TicketNote,
    ) -> bool:
        """
        Add a note/comment to a ticket.

        Args:
            ticket_id: The ticket ID in the PSA.
            note: The note to add.

        Returns:
            True if successful.
        """
        pass

    @abstractmethod
    async def close_ticket(
        self,
        ticket_id: str,
        resolution_note: str = "",
    ) -> TicketResult:
        """
        Close a ticket.

        Args:
            ticket_id: The ticket ID in the PSA.
            resolution_note: Optional resolution note.

        Returns:
            TicketResult with closed ticket details.
        """
        pass

    @abstractmethod
    async def get_ticket(self, ticket_id: str) -> Optional[TicketResult]:
        """
        Get ticket details.

        Args:
            ticket_id: The ticket ID in the PSA.

        Returns:
            TicketResult with ticket details, or None if not found.
        """
        pass

    async def escalate_ticket(
        self,
        ticket_id: str,
        escalation_note: str = "Escalated by Security Alerting Tool",
    ) -> TicketResult:
        """
        Escalate a ticket to critical priority.

        Args:
            ticket_id: The ticket ID in the PSA.
            escalation_note: Note explaining the escalation.

        Returns:
            TicketResult with updated ticket details.
        """
        # Default implementation - update priority and add note
        await self.add_note(
            ticket_id,
            TicketNote(content=escalation_note, is_internal=True),
        )
        return await self.update_ticket(
            ticket_id,
            priority=TicketPriority.CRITICAL,
        )

    def format_alert_description(
        self,
        alert: Alert,
        ai_analysis: Optional[str] = None,
        enrichment_summary: Optional[str] = None,
    ) -> str:
        """
        Format an alert into a ticket description.

        Args:
            alert: The alert to format.
            ai_analysis: Optional AI analysis text.
            enrichment_summary: Optional threat intel summary.

        Returns:
            Formatted description string.
        """
        lines = [
            f"# Security Alert - {alert.threat_name or 'Detection'}",
            "",
            "## Endpoint Information",
            f"- **Hostname:** {alert.hostname}",
            f"- **IP Address:** {alert.endpoint_ip}",
            f"- **Operating System:** {alert.endpoint_os}",
            f"- **User:** {alert.endpoint_user}",
            f"- **Client/Site:** {alert.client_name or alert.site_name}",
            "",
            "## Alert Details",
            f"- **Source:** {alert.source.upper()}",
            f"- **Alert ID:** {alert.source_alert_id}",
            f"- **Severity:** {alert.severity.upper()}",
            f"- **Classification:** {alert.threat_classification}",
            f"- **Timestamp:** {alert.timestamp.isoformat()}",
            "",
        ]

        if alert.file_path or alert.file_hash_sha256:
            lines.extend([
                "## File Information",
                f"- **File Path:** {alert.file_path}",
                f"- **SHA256:** {alert.file_hash_sha256}",
                f"- **SHA1:** {alert.file_hash_sha1}",
                f"- **MD5:** {alert.file_hash_md5}",
                "",
            ])

        if alert.process_name or alert.command_line:
            lines.extend([
                "## Process Information",
                f"- **Process:** {alert.process_name}",
                f"- **Command Line:** `{alert.command_line}`",
                f"- **Parent Process:** {alert.parent_process_name}",
                "",
            ])

        if alert.remote_ip or alert.remote_domain:
            lines.extend([
                "## Network Indicators",
                f"- **Remote IP:** {alert.remote_ip}",
                f"- **Remote Domain:** {alert.remote_domain}",
                f"- **Remote Port:** {alert.remote_port}",
                "",
            ])

        if enrichment_summary:
            lines.extend([
                "## Threat Intelligence",
                enrichment_summary,
                "",
            ])

        if ai_analysis:
            lines.extend([
                "## AI Analysis",
                ai_analysis,
                "",
            ])

        return "\n".join(lines)

    @abstractmethod
    async def test_connectivity(self) -> bool:
        """
        Test API connectivity and authentication.

        Returns:
            True if connection is successful.

        Raises:
            Exception: If connection fails.
        """
        pass

    async def close(self) -> None:
        """Clean up any resources (e.g., HTTP client sessions)."""
        pass
