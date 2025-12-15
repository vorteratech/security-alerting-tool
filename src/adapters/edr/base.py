"""
Base EDR adapter interface.

Defines the abstract interface for EDR platform integrations
(SentinelOne, CrowdStrike, etc.).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class Alert:
    """
    Normalized alert from any EDR platform.

    This provides a common structure for alerts regardless of the source EDR.
    """

    # Identification
    id: str  # Internal UUID
    source: str  # EDR source: "sentinelone", "crowdstrike"
    source_alert_id: str  # Original alert ID from EDR
    timestamp: datetime  # When alert occurred
    received_at: datetime = field(default_factory=datetime.utcnow)

    # Severity
    severity: str = "medium"  # critical, high, medium, low, info
    confidence: Optional[int] = None  # 0-100 confidence score

    # Endpoint information
    hostname: str = ""
    endpoint_ip: str = ""
    endpoint_os: str = ""
    endpoint_os_version: str = ""
    endpoint_user: str = ""
    endpoint_domain: str = ""
    agent_id: str = ""  # EDR agent ID

    # Site/Group info (for multi-client MSP)
    site_name: str = ""  # S1 Site or CS Host Group
    site_id: str = ""
    client_name: str = ""  # Derived client name

    # Threat information
    threat_name: str = ""
    threat_classification: str = ""  # malware, ransomware, pup, exploit, etc.
    threat_description: str = ""
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    # File indicators
    file_path: str = ""
    file_name: str = ""
    file_hash_sha256: str = ""
    file_hash_sha1: str = ""
    file_hash_md5: str = ""
    file_size: Optional[int] = None
    file_signed: Optional[bool] = None
    file_signer: str = ""

    # Process information
    process_name: str = ""
    process_id: Optional[int] = None
    process_path: str = ""
    command_line: str = ""
    parent_process_name: str = ""
    parent_process_path: str = ""
    parent_command_line: str = ""

    # Network indicators
    remote_ip: str = ""
    remote_domain: str = ""
    remote_port: Optional[int] = None
    remote_url: str = ""
    network_direction: str = ""  # inbound, outbound

    # Raw data
    raw_data: dict[str, Any] = field(default_factory=dict)

    # Enrichment (populated by enrichment service)
    enrichment: Optional[dict[str, Any]] = None

    # AI analysis (populated by AI service)
    ai_analysis: Optional[dict[str, Any]] = None

    # Output tracking (not persisted)
    ticket_id: Optional[str] = None
    teams_message_id: Optional[str] = None

    def get_iocs(self) -> dict[str, list[str]]:
        """
        Extract indicators of compromise from the alert.

        Returns:
            Dictionary of IOC types to values.
        """
        iocs: dict[str, list[str]] = {
            "hashes": [],
            "ips": [],
            "domains": [],
            "urls": [],
        }

        # Collect hashes
        for hash_val in [self.file_hash_sha256, self.file_hash_sha1, self.file_hash_md5]:
            if hash_val:
                iocs["hashes"].append(hash_val)

        # Collect IPs
        if self.remote_ip:
            iocs["ips"].append(self.remote_ip)

        # Collect domains
        if self.remote_domain:
            iocs["domains"].append(self.remote_domain)

        # Collect URLs
        if self.remote_url:
            iocs["urls"].append(self.remote_url)

        return iocs


class BaseEDRAdapter(ABC):
    """
    Abstract base class for EDR platform adapters.

    Implement this interface for each EDR platform (SentinelOne, CrowdStrike, etc.).
    """

    def __init__(self, api_key: str, api_url: str, **kwargs):
        """
        Initialize the EDR adapter.

        Args:
            api_key: API key for authentication.
            api_url: Base URL for the EDR API.
            **kwargs: Additional provider-specific configuration.
        """
        self.api_key = api_key
        self.api_url = api_url.rstrip("/")
        self.config = kwargs

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name (e.g., 'sentinelone', 'crowdstrike')."""
        pass

    @abstractmethod
    def parse_webhook(self, payload: dict[str, Any]) -> Alert:
        """
        Parse a webhook payload into a normalized Alert.

        Args:
            payload: Raw webhook payload from the EDR platform.

        Returns:
            Normalized Alert object.

        Raises:
            ValueError: If payload cannot be parsed.
        """
        pass

    @abstractmethod
    async def resolve_alert(self, alert_id: str, comment: str = "") -> bool:
        """
        Resolve/dismiss an alert in the EDR platform.

        Args:
            alert_id: The alert ID in the EDR platform.
            comment: Optional comment for the resolution.

        Returns:
            True if successful, False otherwise.
        """
        pass

    @abstractmethod
    async def contain_endpoint(self, agent_id: str, comment: str = "") -> bool:
        """
        Network contain/isolate an endpoint.

        Args:
            agent_id: The agent/endpoint ID in the EDR platform.
            comment: Optional comment for the containment.

        Returns:
            True if successful, False otherwise.
        """
        pass

    @abstractmethod
    async def uncontain_endpoint(self, agent_id: str, comment: str = "") -> bool:
        """
        Remove network containment from an endpoint.

        Args:
            agent_id: The agent/endpoint ID in the EDR platform.
            comment: Optional comment for the uncontainment.

        Returns:
            True if successful, False otherwise.
        """
        pass

    @abstractmethod
    async def get_alert_details(self, alert_id: str) -> Optional[Alert]:
        """
        Get full details for an alert.

        Args:
            alert_id: The alert ID in the EDR platform.

        Returns:
            Alert object with full details, or None if not found.
        """
        pass

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
