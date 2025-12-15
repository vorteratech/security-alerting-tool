"""
Base chat platform adapter interface.

Defines the abstract interface for chat platform integrations
(Microsoft Teams, Slack, etc.).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from ..edr.base import Alert


class MessageType(Enum):
    """Types of chat messages."""

    ALERT = "alert"  # Security alert notification
    UPDATE = "update"  # Update to existing alert
    ESCALATION = "escalation"  # Escalation notification
    RESOLUTION = "resolution"  # Alert resolved notification
    INFO = "info"  # Informational message


class ActionButton(Enum):
    """Standard action buttons for alert messages."""

    RESOLVE = "resolve"
    CONTAIN = "contain"
    ESCALATE = "escalate"


@dataclass
class MessageResult:
    """
    Result of sending a chat message.

    Contains message details and metadata from the chat platform.
    """

    # Message identification
    message_id: str  # ID in the chat platform
    channel_id: str = ""  # Channel/conversation ID
    thread_id: str = ""  # Thread ID (if threaded)

    # Status
    success: bool = True
    action: str = "sent"  # sent, updated, deleted

    # Timestamps
    sent_at: Optional[datetime] = None

    # Metadata
    raw_response: Optional[dict[str, Any]] = None

    # Error handling
    error: Optional[str] = None


@dataclass
class AlertCard:
    """
    Data structure for rendering an alert as a rich card.

    Used to create adaptive cards (Teams) or block kit (Slack).
    """

    # Alert identification
    alert_id: str
    source: str  # sentinelone, crowdstrike
    source_alert_id: str

    # Header
    title: str
    severity: str
    timestamp: datetime

    # Endpoint info
    hostname: str
    endpoint_ip: str
    endpoint_user: str
    endpoint_os: str
    client_name: str

    # Threat info
    threat_name: str
    threat_classification: str
    file_path: str = ""
    file_hash: str = ""
    command_line: str = ""

    # Network info
    remote_ip: str = ""
    remote_domain: str = ""

    # Analysis
    ai_summary: str = ""
    ai_recommendations: list[str] = field(default_factory=list)
    threat_intel_summary: str = ""

    # Ticket info
    ticket_id: str = ""
    ticket_url: str = ""

    # Actions
    show_resolve_button: bool = True
    show_contain_button: bool = True
    show_escalate_button: bool = True

    # Callback URL for action buttons
    action_callback_url: str = ""

    @classmethod
    def from_alert(
        cls,
        alert: Alert,
        ai_analysis: Optional[dict[str, Any]] = None,
        enrichment: Optional[dict[str, Any]] = None,
        ticket_id: str = "",
        ticket_url: str = "",
        action_callback_url: str = "",
    ) -> "AlertCard":
        """
        Create an AlertCard from an Alert object.

        Args:
            alert: The alert to convert.
            ai_analysis: Optional AI analysis data.
            enrichment: Optional threat intel enrichment data.
            ticket_id: Optional ticket ID.
            ticket_url: Optional ticket URL.
            action_callback_url: Base URL for action callbacks.

        Returns:
            AlertCard instance.
        """
        ai_summary = ""
        ai_recommendations = []
        if ai_analysis:
            ai_summary = ai_analysis.get("summary", "")
            ai_recommendations = ai_analysis.get("recommended_actions", [])

        threat_intel_summary = ""
        if enrichment:
            summaries = []
            for provider, data in enrichment.get("results", {}).items():
                summaries.append(f"{provider}: {data.get('summary', 'No data')}")
            threat_intel_summary = " | ".join(summaries)

        return cls(
            alert_id=alert.id,
            source=alert.source,
            source_alert_id=alert.source_alert_id,
            title=f"Security Alert - {alert.threat_name or 'Detection'}",
            severity=alert.severity,
            timestamp=alert.timestamp,
            hostname=alert.hostname,
            endpoint_ip=alert.endpoint_ip,
            endpoint_user=alert.endpoint_user,
            endpoint_os=alert.endpoint_os,
            client_name=alert.client_name or alert.site_name,
            threat_name=alert.threat_name,
            threat_classification=alert.threat_classification,
            file_path=alert.file_path,
            file_hash=alert.file_hash_sha256,
            command_line=alert.command_line,
            remote_ip=alert.remote_ip,
            remote_domain=alert.remote_domain,
            ai_summary=ai_summary,
            ai_recommendations=ai_recommendations,
            threat_intel_summary=threat_intel_summary,
            ticket_id=ticket_id,
            ticket_url=ticket_url,
            action_callback_url=action_callback_url,
        )


class BaseChatAdapter(ABC):
    """
    Abstract base class for chat platform adapters.

    Implement this interface for each chat platform
    (Microsoft Teams, Slack, etc.).
    """

    def __init__(self, **kwargs):
        """
        Initialize the chat adapter.

        Args:
            **kwargs: Provider-specific configuration.
        """
        self.config = kwargs

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name (e.g., 'teams', 'slack')."""
        pass

    @abstractmethod
    async def send_alert(
        self,
        channel_id: str,
        card: AlertCard,
    ) -> MessageResult:
        """
        Send an alert card to a channel.

        Args:
            channel_id: The channel/conversation ID to send to.
            card: The AlertCard to render and send.

        Returns:
            MessageResult with sent message details.
        """
        pass

    @abstractmethod
    async def update_message(
        self,
        channel_id: str,
        message_id: str,
        card: AlertCard,
    ) -> MessageResult:
        """
        Update an existing alert message.

        Args:
            channel_id: The channel/conversation ID.
            message_id: The message ID to update.
            card: The updated AlertCard.

        Returns:
            MessageResult with update details.
        """
        pass

    @abstractmethod
    async def send_text_message(
        self,
        channel_id: str,
        text: str,
        thread_id: Optional[str] = None,
    ) -> MessageResult:
        """
        Send a plain text message.

        Args:
            channel_id: The channel/conversation ID.
            text: The message text.
            thread_id: Optional thread ID to reply to.

        Returns:
            MessageResult with sent message details.
        """
        pass

    async def send_escalation_notification(
        self,
        channel_id: str,
        alert: Alert,
        escalated_by: str,
        reason: str = "",
    ) -> MessageResult:
        """
        Send an escalation notification.

        Args:
            channel_id: The channel to notify.
            alert: The escalated alert.
            escalated_by: Who escalated the alert.
            reason: Optional reason for escalation.

        Returns:
            MessageResult with sent message details.
        """
        text = (
            f"**ESCALATION** - Alert escalated to senior engineer\n\n"
            f"**Alert:** {alert.threat_name} on {alert.hostname}\n"
            f"**Client:** {alert.client_name or alert.site_name}\n"
            f"**Escalated by:** {escalated_by}\n"
        )
        if reason:
            text += f"**Reason:** {reason}\n"

        return await self.send_text_message(channel_id, text)

    async def send_resolution_notification(
        self,
        channel_id: str,
        alert: Alert,
        resolved_by: str,
        thread_id: Optional[str] = None,
    ) -> MessageResult:
        """
        Send a resolution notification.

        Args:
            channel_id: The channel to notify.
            alert: The resolved alert.
            resolved_by: Who resolved the alert.
            thread_id: Optional thread to reply to.

        Returns:
            MessageResult with sent message details.
        """
        text = (
            f"**RESOLVED** - Alert resolved\n\n"
            f"**Alert:** {alert.threat_name} on {alert.hostname}\n"
            f"**Resolved by:** {resolved_by}"
        )
        return await self.send_text_message(channel_id, text, thread_id)

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
