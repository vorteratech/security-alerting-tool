"""
Alert Formatting Service.

Provides consistent formatting of alerts for different output channels:
- PSA tickets (SuperOps, etc.)
- Chat platforms (Teams, Slack)
- Email notifications
"""

from dataclasses import dataclass
from typing import Any, Optional

from ..adapters.edr.base import Alert
from ..adapters.chat.base import AlertCard
from ..adapters.psa.base import TicketPriority
from ..config.logging import get_logger

logger = get_logger(__name__)


@dataclass
class FormattedTicket:
    """Formatted ticket content for PSA creation."""

    title: str
    description: str
    priority: TicketPriority
    tags: list[str]


@dataclass
class FormattedAlert:
    """Complete formatted alert for all channels."""

    ticket: FormattedTicket
    card: AlertCard
    summary_text: str  # Plain text summary for simple notifications


class AlertFormatterService:
    """
    Service for formatting alerts for various output channels.

    Provides consistent, professional formatting of security alerts
    for tickets, chat cards, and notifications.
    """

    # Severity to priority mapping
    SEVERITY_TO_PRIORITY = {
        "critical": TicketPriority.CRITICAL,
        "high": TicketPriority.HIGH,
        "medium": TicketPriority.MEDIUM,
        "low": TicketPriority.LOW,
        "info": TicketPriority.LOW,
    }

    def __init__(self, action_callback_url: str = ""):
        """
        Initialize the formatter service.

        Args:
            action_callback_url: Base URL for action callbacks in chat cards.
        """
        self.action_callback_url = action_callback_url

    def format_alert(
        self,
        alert: Alert,
        ai_analysis: Optional[dict[str, Any]] = None,
        enrichment: Optional[dict[str, Any]] = None,
        ticket_id: str = "",
        ticket_url: str = "",
    ) -> FormattedAlert:
        """
        Format an alert for all output channels.

        Args:
            alert: The alert to format.
            ai_analysis: Optional AI analysis results.
            enrichment: Optional threat intel enrichment.
            ticket_id: Optional ticket ID if already created.
            ticket_url: Optional ticket URL.

        Returns:
            FormattedAlert with ticket, card, and text versions.
        """
        ticket = self._format_ticket(alert, ai_analysis, enrichment)
        card = self._format_card(
            alert, ai_analysis, enrichment, ticket_id, ticket_url
        )
        summary = self._format_summary_text(alert, ai_analysis)

        return FormattedAlert(
            ticket=ticket,
            card=card,
            summary_text=summary,
        )

    def _format_ticket(
        self,
        alert: Alert,
        ai_analysis: Optional[dict[str, Any]] = None,
        enrichment: Optional[dict[str, Any]] = None,
    ) -> FormattedTicket:
        """
        Format alert as a PSA ticket.

        Args:
            alert: The alert to format.
            ai_analysis: Optional AI analysis.
            enrichment: Optional threat intel.

        Returns:
            FormattedTicket ready for PSA creation.
        """
        # Build title
        severity_prefix = f"[{alert.severity.upper()}]"
        threat_name = alert.threat_name or "Security Detection"
        hostname = alert.hostname or "Unknown Host"
        title = f"{severity_prefix} {threat_name} on {hostname}"

        # Build description
        description_parts = []

        # Header
        description_parts.append("=" * 60)
        description_parts.append("SECURITY ALERT - AUTOMATED DETECTION")
        description_parts.append("=" * 60)
        description_parts.append("")

        # Alert Details
        description_parts.append("## Alert Details")
        description_parts.append(f"- **Source:** {alert.source.upper()}")
        description_parts.append(f"- **Alert ID:** {alert.source_alert_id}")
        description_parts.append(f"- **Severity:** {alert.severity.upper()}")
        description_parts.append(f"- **Classification:** {alert.threat_classification or 'N/A'}")
        description_parts.append(f"- **Detected At:** {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        description_parts.append("")

        # Endpoint Information
        description_parts.append("## Endpoint Information")
        description_parts.append(f"- **Hostname:** {alert.hostname or 'N/A'}")
        description_parts.append(f"- **IP Address:** {alert.endpoint_ip or 'N/A'}")
        description_parts.append(f"- **User:** {alert.endpoint_user or 'N/A'}")
        description_parts.append(f"- **Operating System:** {alert.endpoint_os or 'N/A'}")
        description_parts.append(f"- **Client/Site:** {alert.client_name or alert.site_name or 'N/A'}")
        description_parts.append("")

        # Threat Details
        description_parts.append("## Threat Details")
        description_parts.append(f"- **Threat Name:** {alert.threat_name or 'N/A'}")

        if alert.file_path:
            description_parts.append(f"- **File Path:** {alert.file_path}")

        if alert.file_hash_sha256:
            description_parts.append(f"- **SHA256 Hash:** {alert.file_hash_sha256}")

        if alert.command_line:
            cmd_display = alert.command_line[:500]
            if len(alert.command_line) > 500:
                cmd_display += "..."
            description_parts.append(f"- **Command Line:** `{cmd_display}`")

        if alert.process_name:
            description_parts.append(f"- **Process:** {alert.process_name}")

        if alert.parent_process_name:
            description_parts.append(f"- **Parent Process:** {alert.parent_process_name}")
        description_parts.append("")

        # Network Activity (if present)
        if alert.remote_ip or alert.remote_domain:
            description_parts.append("## Network Activity")
            if alert.remote_ip:
                description_parts.append(f"- **Remote IP:** {alert.remote_ip}")
            if alert.remote_domain:
                description_parts.append(f"- **Domain:** {alert.remote_domain}")
            description_parts.append("")

        # AI Analysis (if present)
        if ai_analysis:
            description_parts.append("## AI Analysis")
            if ai_analysis.get("summary"):
                description_parts.append(f"**Summary:** {ai_analysis['summary']}")
                description_parts.append("")

            if ai_analysis.get("severity_assessment"):
                description_parts.append(f"**AI Severity Assessment:** {ai_analysis['severity_assessment'].upper()}")
                confidence = ai_analysis.get("confidence", 0)
                description_parts.append(f"**Confidence:** {confidence}%")
                description_parts.append("")

            if ai_analysis.get("immediate_actions"):
                description_parts.append("**Immediate Actions Required:**")
                for i, action in enumerate(ai_analysis["immediate_actions"][:5], 1):
                    description_parts.append(f"{i}. {action}")
                description_parts.append("")

            if ai_analysis.get("recommended_actions"):
                description_parts.append("**Recommended Actions:**")
                for i, action in enumerate(ai_analysis["recommended_actions"][:5], 1):
                    description_parts.append(f"{i}. {action}")
                description_parts.append("")

            if ai_analysis.get("investigation_steps"):
                description_parts.append("**Investigation Steps:**")
                for i, step in enumerate(ai_analysis["investigation_steps"][:5], 1):
                    description_parts.append(f"{i}. {step}")
                description_parts.append("")

        # Threat Intelligence (if present)
        if enrichment and enrichment.get("results"):
            description_parts.append("## Threat Intelligence")

            for provider, data in enrichment["results"].items():
                description_parts.append(f"### {provider.title()}")
                if data.get("is_malicious"):
                    description_parts.append(f"**Status:** MALICIOUS")
                if data.get("severity"):
                    description_parts.append(f"**Severity:** {data['severity'].upper()}")
                if data.get("summary"):
                    description_parts.append(f"**Details:** {data['summary']}")
                if data.get("tags"):
                    description_parts.append(f"**Tags:** {', '.join(data['tags'][:10])}")
                description_parts.append("")

        # Raw Data Reference
        description_parts.append("## Raw Data")
        description_parts.append(f"- **EDR Alert ID:** {alert.source_alert_id}")
        if alert.agent_id:
            description_parts.append(f"- **Agent ID:** {alert.agent_id}")
        description_parts.append("")

        # Footer
        description_parts.append("-" * 60)
        description_parts.append("This ticket was automatically created by the Security Alerting System.")
        description_parts.append("Please investigate and take appropriate action.")

        description = "\n".join(description_parts)

        # Determine priority
        priority = self.SEVERITY_TO_PRIORITY.get(
            alert.severity.lower(),
            TicketPriority.MEDIUM
        )

        # If AI analysis suggests higher severity, consider escalating
        if ai_analysis and ai_analysis.get("severity_assessment"):
            ai_severity = ai_analysis["severity_assessment"].lower()
            ai_priority = self.SEVERITY_TO_PRIORITY.get(ai_severity)
            if ai_priority and ai_priority.value < priority.value:
                # AI suggests higher priority
                priority = ai_priority

        # Build tags
        tags = [
            "security-alert",
            f"edr-{alert.source}",
            f"severity-{alert.severity.lower()}",
        ]
        if alert.threat_classification:
            tags.append(alert.threat_classification.lower().replace(" ", "-"))

        return FormattedTicket(
            title=title,
            description=description,
            priority=priority,
            tags=tags,
        )

    def _format_card(
        self,
        alert: Alert,
        ai_analysis: Optional[dict[str, Any]] = None,
        enrichment: Optional[dict[str, Any]] = None,
        ticket_id: str = "",
        ticket_url: str = "",
    ) -> AlertCard:
        """
        Format alert as a chat card.

        Args:
            alert: The alert to format.
            ai_analysis: Optional AI analysis.
            enrichment: Optional threat intel.
            ticket_id: Optional ticket ID.
            ticket_url: Optional ticket URL.

        Returns:
            AlertCard for chat platforms.
        """
        return AlertCard.from_alert(
            alert=alert,
            ai_analysis=ai_analysis,
            enrichment=enrichment,
            ticket_id=ticket_id,
            ticket_url=ticket_url,
            action_callback_url=self.action_callback_url,
        )

    def _format_summary_text(
        self,
        alert: Alert,
        ai_analysis: Optional[dict[str, Any]] = None,
    ) -> str:
        """
        Format a plain text summary of the alert.

        Args:
            alert: The alert to summarize.
            ai_analysis: Optional AI analysis.

        Returns:
            Plain text summary string.
        """
        lines = [
            f"[{alert.severity.upper()}] {alert.threat_name or 'Security Detection'}",
            f"Host: {alert.hostname} ({alert.endpoint_ip or 'N/A'})",
            f"Client: {alert.client_name or alert.site_name or 'N/A'}",
            f"Source: {alert.source.upper()}",
        ]

        if ai_analysis and ai_analysis.get("summary"):
            lines.append(f"Analysis: {ai_analysis['summary']}")

        return " | ".join(lines)

    def format_resolution_note(
        self,
        alert: Alert,
        resolved_by: str,
        resolution_type: str = "resolved",
        comment: str = "",
    ) -> str:
        """
        Format a resolution note for ticket closure.

        Args:
            alert: The resolved alert.
            resolved_by: Who resolved the alert.
            resolution_type: Type of resolution.
            comment: Optional resolution comment.

        Returns:
            Formatted resolution note.
        """
        lines = [
            f"Alert resolved by {resolved_by}",
            f"Resolution type: {resolution_type}",
            f"Hostname: {alert.hostname}",
            f"Alert ID: {alert.source_alert_id}",
        ]

        if comment:
            lines.append(f"Notes: {comment}")

        lines.append(f"Resolved via Security Alerting System")

        return "\n".join(lines)

    def format_containment_note(
        self,
        alert: Alert,
        contained_by: str,
        success: bool = True,
    ) -> str:
        """
        Format a containment note for ticket update.

        Args:
            alert: The alert for contained endpoint.
            contained_by: Who triggered containment.
            success: Whether containment succeeded.

        Returns:
            Formatted containment note.
        """
        status = "successfully isolated" if success else "FAILED to isolate"
        lines = [
            f"Endpoint {status}",
            f"Hostname: {alert.hostname}",
            f"Contained by: {contained_by}",
            f"Agent ID: {alert.agent_id or 'N/A'}",
        ]

        if not success:
            lines.append("MANUAL INTERVENTION REQUIRED")

        return "\n".join(lines)

    def format_escalation_note(
        self,
        alert: Alert,
        escalated_by: str,
        reason: str = "",
    ) -> str:
        """
        Format an escalation note.

        Args:
            alert: The escalated alert.
            escalated_by: Who escalated.
            reason: Reason for escalation.

        Returns:
            Formatted escalation note.
        """
        lines = [
            "ALERT ESCALATED",
            f"Escalated by: {escalated_by}",
            f"Alert: {alert.threat_name} on {alert.hostname}",
        ]

        if reason:
            lines.append(f"Reason: {reason}")

        lines.append("Awaiting senior engineer review")

        return "\n".join(lines)
