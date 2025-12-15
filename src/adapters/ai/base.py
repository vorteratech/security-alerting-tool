"""
Base AI adapter interface.

Defines the abstract interface for AI provider integrations
(Claude, OpenAI, Gemini, etc.).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from ..edr.base import Alert


@dataclass
class AIAnalysisResult:
    """
    Result of AI analysis on a security alert.

    Contains the AI-generated analysis, recommendations, and metadata.
    """

    # Analysis content
    summary: str  # Brief summary of the threat
    description: str  # Detailed description of what happened
    severity_assessment: str  # AI's assessment of severity
    confidence: int  # 0-100 confidence in the analysis

    # Recommendations
    recommended_actions: list[str] = field(default_factory=list)
    immediate_actions: list[str] = field(default_factory=list)  # High priority
    investigation_steps: list[str] = field(default_factory=list)

    # Classification
    threat_type: str = ""  # malware, ransomware, apt, insider, etc.
    attack_stage: str = ""  # initial_access, execution, persistence, etc.
    potential_impact: str = ""  # data_theft, ransomware, lateral_movement, etc.

    # Context
    similar_threats: list[str] = field(default_factory=list)  # Known similar threats
    cve_references: list[str] = field(default_factory=list)  # Related CVEs
    mitre_mapping: list[str] = field(default_factory=list)  # MITRE ATT&CK techniques

    # Metadata
    provider: str = ""  # AI provider used
    model: str = ""  # Model used
    tokens_used: int = 0
    analysis_time_ms: int = 0

    # Raw response
    raw_response: Optional[dict[str, Any]] = None

    def to_formatted_text(self) -> str:
        """
        Format the analysis as readable text for tickets/chat.

        Returns:
            Formatted analysis text.
        """
        lines = []

        lines.append(f"**Summary:** {self.summary}")
        lines.append("")
        lines.append(f"**Analysis:** {self.description}")
        lines.append("")

        if self.immediate_actions:
            lines.append("**Immediate Actions Required:**")
            for i, action in enumerate(self.immediate_actions, 1):
                lines.append(f"{i}. {action}")
            lines.append("")

        if self.recommended_actions:
            lines.append("**Recommended Actions:**")
            for i, action in enumerate(self.recommended_actions, 1):
                lines.append(f"{i}. {action}")
            lines.append("")

        if self.investigation_steps:
            lines.append("**Investigation Steps:**")
            for i, step in enumerate(self.investigation_steps, 1):
                lines.append(f"{i}. {step}")

        return "\n".join(lines)


class BaseAIAdapter(ABC):
    """
    Abstract base class for AI provider adapters.

    Implement this interface for each AI provider (Claude, OpenAI, Gemini, etc.).
    """

    # System prompt for security analysis
    SECURITY_ANALYST_PROMPT = """You are an expert cybersecurity analyst working for a Managed Security Service Provider (MSP).
Your role is to analyze security alerts from EDR platforms and provide clear, actionable guidance for security technicians.

When analyzing alerts, you should:
1. Explain what the detection means in plain language
2. Assess the severity and potential impact
3. Identify the type of threat (malware, ransomware, APT, etc.)
4. Map to MITRE ATT&CK techniques when applicable
5. Provide specific, prioritized recommendations
6. Suggest investigation steps

Be concise but thorough. Prioritize actionable guidance over theoretical explanations.
Always err on the side of caution - if something looks suspicious, recommend investigation."""

    def __init__(self, api_key: str, model: str = "", **kwargs):
        """
        Initialize the AI adapter.

        Args:
            api_key: API key for authentication.
            model: Model to use for analysis.
            **kwargs: Additional provider-specific configuration.
        """
        self.api_key = api_key
        self.model = model
        self.config = kwargs

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name (e.g., 'claude', 'openai', 'gemini')."""
        pass

    @property
    @abstractmethod
    def default_model(self) -> str:
        """Return the default model for this provider."""
        pass

    @abstractmethod
    async def analyze_alert(
        self,
        alert: Alert,
        enrichment_data: Optional[dict[str, Any]] = None,
        additional_context: str = "",
    ) -> AIAnalysisResult:
        """
        Analyze a security alert using AI.

        Args:
            alert: The normalized alert to analyze.
            enrichment_data: Optional threat intelligence enrichment data.
            additional_context: Additional context to include in the prompt.

        Returns:
            AIAnalysisResult with analysis and recommendations.

        Raises:
            Exception: If analysis fails.
        """
        pass

    def _build_alert_prompt(
        self,
        alert: Alert,
        enrichment_data: Optional[dict[str, Any]] = None,
        additional_context: str = "",
    ) -> str:
        """
        Build the prompt for alert analysis.

        Args:
            alert: The alert to analyze.
            enrichment_data: Optional enrichment data.
            additional_context: Additional context.

        Returns:
            Formatted prompt string.
        """
        prompt_parts = [
            "Analyze the following security alert and provide your assessment:\n",
            f"**Source:** {alert.source.upper()}",
            f"**Severity:** {alert.severity.upper()}",
            f"**Timestamp:** {alert.timestamp.isoformat()}",
            "",
            "**Endpoint Information:**",
            f"- Hostname: {alert.hostname}",
            f"- IP: {alert.endpoint_ip}",
            f"- OS: {alert.endpoint_os}",
            f"- User: {alert.endpoint_user}",
            f"- Client: {alert.client_name or alert.site_name}",
            "",
            "**Threat Details:**",
            f"- Threat Name: {alert.threat_name}",
            f"- Classification: {alert.threat_classification}",
        ]

        if alert.file_path:
            prompt_parts.extend([
                "",
                "**File Information:**",
                f"- Path: {alert.file_path}",
                f"- SHA256: {alert.file_hash_sha256}",
            ])

        if alert.process_name or alert.command_line:
            prompt_parts.extend([
                "",
                "**Process Information:**",
                f"- Process: {alert.process_name}",
                f"- Command Line: {alert.command_line}",
                f"- Parent Process: {alert.parent_process_name}",
            ])

        if alert.remote_ip or alert.remote_domain:
            prompt_parts.extend([
                "",
                "**Network Indicators:**",
                f"- Remote IP: {alert.remote_ip}",
                f"- Remote Domain: {alert.remote_domain}",
                f"- Remote Port: {alert.remote_port}",
            ])

        if alert.mitre_tactics or alert.mitre_techniques:
            prompt_parts.extend([
                "",
                "**MITRE ATT&CK:**",
                f"- Tactics: {', '.join(alert.mitre_tactics)}",
                f"- Techniques: {', '.join(alert.mitre_techniques)}",
            ])

        if enrichment_data:
            prompt_parts.extend([
                "",
                "**Threat Intelligence:**",
            ])
            if "virustotal" in enrichment_data:
                vt = enrichment_data["virustotal"]
                prompt_parts.append(f"- VirusTotal: {vt.get('summary', 'No data')}")
            if "alienvault" in enrichment_data:
                av = enrichment_data["alienvault"]
                prompt_parts.append(f"- AlienVault: {av.get('summary', 'No data')}")

        if additional_context:
            prompt_parts.extend([
                "",
                "**Additional Context:**",
                additional_context,
            ])

        prompt_parts.extend([
            "",
            "Please provide:",
            "1. A brief summary (1-2 sentences)",
            "2. A detailed analysis of what this detection means",
            "3. Your severity assessment",
            "4. Immediate actions required (if any)",
            "5. Recommended follow-up actions",
            "6. Investigation steps",
        ])

        return "\n".join(prompt_parts)

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
