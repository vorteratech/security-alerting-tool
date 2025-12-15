"""
Base threat intelligence adapter interface.

Defines the abstract interface for threat intelligence integrations
(VirusTotal, AlienVault, etc.).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class IOCType(Enum):
    """Types of indicators of compromise."""

    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"


@dataclass
class ThreatIntelResult:
    """
    Result of threat intelligence lookup.

    Contains reputation data, detection info, and related intelligence.
    """

    # Lookup metadata
    provider: str  # virustotal, alienvault, etc.
    ioc_type: str  # hash, ip, domain, url
    ioc_value: str  # The actual indicator value
    lookup_time: datetime = field(default_factory=datetime.utcnow)

    # Reputation
    is_malicious: bool = False
    malicious_score: int = 0  # Provider-specific score
    reputation: str = "unknown"  # malicious, suspicious, clean, unknown

    # Detection info (for hashes)
    detection_count: int = 0  # Number of engines detecting
    total_engines: int = 0  # Total number of engines
    detection_names: list[str] = field(default_factory=list)  # Names from AV engines

    # File info (for hashes)
    file_type: str = ""
    file_size: Optional[int] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    # Network info (for IPs/domains)
    country: str = ""
    asn: str = ""
    asn_owner: str = ""
    registrar: str = ""

    # Threat classification
    threat_types: list[str] = field(default_factory=list)  # malware, phishing, c2, etc.
    malware_families: list[str] = field(default_factory=list)  # Specific malware families
    tags: list[str] = field(default_factory=list)  # Provider-specific tags

    # Related intelligence
    related_iocs: list[str] = field(default_factory=list)
    related_campaigns: list[str] = field(default_factory=list)
    cve_references: list[str] = field(default_factory=list)

    # Raw response
    raw_response: Optional[dict[str, Any]] = None

    # Error handling
    error: Optional[str] = None
    success: bool = True

    def get_summary(self) -> str:
        """
        Get a human-readable summary of the threat intel.

        Returns:
            Summary string.
        """
        if not self.success:
            return f"{self.provider}: Error - {self.error}"

        if self.ioc_type in ["hash_md5", "hash_sha1", "hash_sha256"]:
            if self.detection_count > 0:
                return (
                    f"{self.provider}: {self.detection_count}/{self.total_engines} "
                    f"engines detected ({self.reputation})"
                )
            return f"{self.provider}: No detections ({self.reputation})"

        elif self.ioc_type in ["ip", "domain"]:
            parts = [f"{self.provider}: {self.reputation}"]
            if self.country:
                parts.append(f"Country: {self.country}")
            if self.threat_types:
                parts.append(f"Types: {', '.join(self.threat_types)}")
            return " | ".join(parts)

        return f"{self.provider}: {self.reputation}"


@dataclass
class EnrichmentResult:
    """
    Aggregated enrichment results from multiple threat intel sources.
    """

    # Results by provider
    results: dict[str, ThreatIntelResult] = field(default_factory=dict)

    # Aggregated assessment
    is_malicious: bool = False
    highest_severity: str = "unknown"  # malicious, suspicious, clean, unknown
    consensus_score: int = 0  # 0-100 based on multiple sources

    # Aggregated intelligence
    all_threat_types: list[str] = field(default_factory=list)
    all_malware_families: list[str] = field(default_factory=list)
    all_tags: list[str] = field(default_factory=list)

    def add_result(self, result: ThreatIntelResult) -> None:
        """Add a result and update aggregated data."""
        self.results[result.provider] = result

        if result.is_malicious:
            self.is_malicious = True

        # Update severity based on results
        if result.reputation == "malicious":
            self.highest_severity = "malicious"
        elif result.reputation == "suspicious" and self.highest_severity != "malicious":
            self.highest_severity = "suspicious"
        elif result.reputation == "clean" and self.highest_severity == "unknown":
            self.highest_severity = "clean"

        # Aggregate intelligence
        self.all_threat_types.extend(result.threat_types)
        self.all_malware_families.extend(result.malware_families)
        self.all_tags.extend(result.tags)

        # Calculate consensus score
        self._update_consensus_score()

    def _update_consensus_score(self) -> None:
        """Calculate consensus score based on all results."""
        if not self.results:
            self.consensus_score = 0
            return

        malicious_count = sum(1 for r in self.results.values() if r.is_malicious)
        suspicious_count = sum(
            1 for r in self.results.values()
            if r.reputation == "suspicious" and not r.is_malicious
        )

        total = len(self.results)
        self.consensus_score = int(
            ((malicious_count * 100) + (suspicious_count * 50)) / total
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage/serialization."""
        return {
            "is_malicious": self.is_malicious,
            "highest_severity": self.highest_severity,
            "consensus_score": self.consensus_score,
            "results": {
                provider: {
                    "is_malicious": r.is_malicious,
                    "reputation": r.reputation,
                    "detection_count": r.detection_count,
                    "total_engines": r.total_engines,
                    "summary": r.get_summary(),
                }
                for provider, r in self.results.items()
            },
            "threat_types": list(set(self.all_threat_types)),
            "malware_families": list(set(self.all_malware_families)),
        }


class BaseThreatIntelAdapter(ABC):
    """
    Abstract base class for threat intelligence adapters.

    Implement this interface for each threat intel provider
    (VirusTotal, AlienVault, etc.).
    """

    def __init__(self, api_key: str, **kwargs):
        """
        Initialize the threat intel adapter.

        Args:
            api_key: API key for authentication.
            **kwargs: Additional provider-specific configuration.
        """
        self.api_key = api_key
        self.config = kwargs

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name (e.g., 'virustotal', 'alienvault')."""
        pass

    @abstractmethod
    async def lookup_hash(self, hash_value: str) -> ThreatIntelResult:
        """
        Look up a file hash.

        Args:
            hash_value: MD5, SHA1, or SHA256 hash.

        Returns:
            ThreatIntelResult with lookup data.
        """
        pass

    @abstractmethod
    async def lookup_ip(self, ip_address: str) -> ThreatIntelResult:
        """
        Look up an IP address.

        Args:
            ip_address: IPv4 or IPv6 address.

        Returns:
            ThreatIntelResult with lookup data.
        """
        pass

    @abstractmethod
    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        """
        Look up a domain.

        Args:
            domain: Domain name.

        Returns:
            ThreatIntelResult with lookup data.
        """
        pass

    async def lookup_url(self, url: str) -> ThreatIntelResult:
        """
        Look up a URL.

        Args:
            url: Full URL.

        Returns:
            ThreatIntelResult with lookup data.

        Note:
            Default implementation returns not supported.
            Override in adapters that support URL lookup.
        """
        return ThreatIntelResult(
            provider=self.provider_name,
            ioc_type="url",
            ioc_value=url,
            success=False,
            error="URL lookup not supported by this provider",
        )

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
