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

    def __init__(
        self,
        action_callback_url: str = "",
        edr_console_urls: Optional[dict[str, str]] = None,
    ):
        """
        Initialize the formatter service.

        Args:
            action_callback_url: Base URL for action callbacks in chat cards.
            edr_console_urls: Dict mapping EDR source to console base URL.
                e.g., {"sentinelone": "https://usea1.sentinelone.net"}
        """
        self.action_callback_url = action_callback_url
        self.edr_console_urls = edr_console_urls or {}

    def _build_edr_alert_url(self, alert: Alert) -> Optional[str]:
        """
        Build a URL to view the alert in the EDR console.

        Args:
            alert: The alert with source and ID info.

        Returns:
            URL string or None if console URL not configured.
        """
        base_url = self.edr_console_urls.get(alert.source.lower(), "")
        if not base_url:
            return None

        base_url = base_url.rstrip("/")

        if alert.source.lower() == "sentinelone":
            # SentinelOne threat URL format
            return f"{base_url}/threats/{alert.source_alert_id}"
        elif alert.source.lower() == "crowdstrike":
            # CrowdStrike detection URL format
            return f"{base_url}/activity/detections/detail/{alert.source_alert_id}"

        return None

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
        Format alert as a PSA ticket with HTML formatting.

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

        # Build description with HTML formatting
        lines = []

        # EDR Alert Link (if we have the console URL)
        edr_url = self._build_edr_alert_url(alert)
        if edr_url:
            lines.append(f'<p><b>🔗 <a href="{edr_url}">View Alert in {alert.source.upper()}</a></b></p>')
            lines.append("<hr>")

        # Alert Overview
        lines.append("<h3>📋 Alert Overview</h3>")
        lines.append('<table style="border-collapse: collapse;">')
        lines.append(f'<tr><td style="padding-right: 20px;"><b>Severity</b></td><td><b>{alert.severity.upper()}</b></td></tr>')
        lines.append(f'<tr><td style="padding-right: 20px;"><b>Threat</b></td><td>{alert.threat_name or "Detection"}</td></tr>')
        lines.append(f'<tr><td style="padding-right: 20px;"><b>Classification</b></td><td>{alert.threat_classification or "N/A"}</td></tr>')
        lines.append(f'<tr><td style="padding-right: 20px;"><b>Source</b></td><td>{alert.source.upper()}</td></tr>')
        lines.append(f'<tr><td style="padding-right: 20px;"><b>Detected</b></td><td>{alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")}</td></tr>')
        lines.append("</table>")

        # Endpoint Information
        lines.append("<h3>💻 Endpoint Information</h3>")
        lines.append('<table style="border-collapse: collapse;">')
        lines.append(f'<tr><td style="padding-right: 20px;"><b>Hostname</b></td><td>{alert.hostname or "N/A"}</td></tr>')
        lines.append(f'<tr><td style="padding-right: 20px;"><b>IP Address</b></td><td>{alert.endpoint_ip or "N/A"}</td></tr>')
        lines.append(f'<tr><td style="padding-right: 20px;"><b>User</b></td><td>{alert.endpoint_user or "N/A"}</td></tr>')
        lines.append(f'<tr><td style="padding-right: 20px;"><b>OS</b></td><td>{alert.endpoint_os or "N/A"}</td></tr>')
        lines.append(f'<tr><td style="padding-right: 20px;"><b>Client/Site</b></td><td>{alert.client_name or alert.site_name or "N/A"}</td></tr>')
        lines.append("</table>")

        # Threat Details
        lines.append("<h3>🎯 Threat Details</h3>")
        lines.append('<table style="border-collapse: collapse;">')
        if alert.file_path:
            lines.append(f'<tr><td style="padding-right: 20px;"><b>File Path</b></td><td><code>{alert.file_path}</code></td></tr>')
        if alert.file_hash_sha256:
            lines.append(f'<tr><td style="padding-right: 20px;"><b>SHA256</b></td><td><code>{alert.file_hash_sha256}</code></td></tr>')
        if alert.process_name:
            lines.append(f'<tr><td style="padding-right: 20px;"><b>Process</b></td><td>{alert.process_name}</td></tr>')
        if alert.parent_process_name:
            lines.append(f'<tr><td style="padding-right: 20px;"><b>Parent Process</b></td><td>{alert.parent_process_name}</td></tr>')
        lines.append("</table>")

        if alert.command_line:
            cmd_display = alert.command_line[:500] + ("..." if len(alert.command_line) > 500 else "")
            lines.append(f"<p><b>Command Line:</b></p><pre>{cmd_display}</pre>")

        # Network Activity (if present)
        if alert.remote_ip or alert.remote_domain:
            lines.append("<h3>🌐 Network Indicators</h3>")
            lines.append('<table style="border-collapse: collapse;">')
            if alert.remote_ip:
                lines.append(f'<tr><td style="padding-right: 20px;"><b>Remote IP</b></td><td><code>{alert.remote_ip}</code></td></tr>')
            if alert.remote_domain:
                lines.append(f'<tr><td style="padding-right: 20px;"><b>Domain</b></td><td><code>{alert.remote_domain}</code></td></tr>')
            lines.append("</table>")

        # AI Analysis (if present)
        if ai_analysis:
            lines.append("<h3>🤖 AI Analysis</h3>")
            if ai_analysis.get("summary"):
                lines.append(f"<p>{ai_analysis['summary']}</p>")

            if ai_analysis.get("severity_assessment"):
                lines.append(f"<p><b>AI Severity:</b> {ai_analysis['severity_assessment'].upper()} ")
                confidence = ai_analysis.get("confidence", 0)
                lines.append(f"(<b>Confidence:</b> {confidence}%)</p>")

            if ai_analysis.get("immediate_actions"):
                lines.append("<p><b>⚠️ Immediate Actions:</b></p><ol>")
                for action in ai_analysis["immediate_actions"][:5]:
                    lines.append(f"<li>{action}</li>")
                lines.append("</ol>")

            if ai_analysis.get("recommended_actions"):
                lines.append("<p><b>📋 Recommended Actions:</b></p><ol>")
                for action in ai_analysis["recommended_actions"][:5]:
                    lines.append(f"<li>{action}</li>")
                lines.append("</ol>")

        # Threat Intelligence (if present)
        if enrichment and enrichment.get("results"):
            lines.append("<h3>🔍 Threat Intelligence</h3>")
            for provider, data in enrichment["results"].items():
                lines.append(f"<p><b>{provider.title()}:</b> ")
                if data.get("is_malicious"):
                    lines.append("<span style='color:red'><b>MALICIOUS</b></span> ")
                if data.get("summary"):
                    lines.append(f"{data['summary']}")
                lines.append("</p>")

        # Footer
        lines.append("<hr>")
        lines.append(f"<p><small>Alert ID: {alert.source_alert_id} | Agent: {alert.agent_id or 'N/A'}</small></p>")
        lines.append("<p><small><i>Auto-generated by Security Alerting System</i></small></p>")

        description = "\n".join(lines)

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
