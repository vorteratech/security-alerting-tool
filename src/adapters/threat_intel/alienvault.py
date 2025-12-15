"""
AlienVault OTX (Open Threat Exchange) adapter.

Provides lookups for:
- File hashes (MD5, SHA1, SHA256)
- IP addresses
- Domains
- URLs

AlienVault OTX is free to use with an API key.
"""

from datetime import datetime
from typing import Optional

import httpx

from ...config.logging import get_logger
from .base import BaseThreatIntelAdapter, ThreatIntelResult

logger = get_logger(__name__)


class AlienVaultAdapter(BaseThreatIntelAdapter):
    """
    AlienVault OTX API adapter.

    Requires an OTX API key (free registration at otx.alienvault.com).
    """

    API_BASE = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str, **kwargs):
        """
        Initialize the AlienVault adapter.

        Args:
            api_key: AlienVault OTX API key.
            **kwargs: Additional configuration.
        """
        super().__init__(api_key, **kwargs)
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def provider_name(self) -> str:
        return "alienvault"

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.API_BASE,
                headers={
                    "X-OTX-API-KEY": self.api_key,
                    "Accept": "application/json",
                },
                timeout=30.0,
            )
        return self._client

    async def lookup_hash(self, hash_value: str) -> ThreatIntelResult:
        """
        Look up a file hash in AlienVault OTX.

        Args:
            hash_value: MD5, SHA1, or SHA256 hash.

        Returns:
            ThreatIntelResult with lookup data.
        """
        # Determine hash type
        hash_len = len(hash_value)
        if hash_len == 32:
            hash_type = "MD5"
            ioc_type = "hash_md5"
        elif hash_len == 40:
            hash_type = "SHA1"
            ioc_type = "hash_sha1"
        elif hash_len == 64:
            hash_type = "SHA256"
            ioc_type = "hash_sha256"
        else:
            return ThreatIntelResult(
                provider=self.provider_name,
                ioc_type="hash",
                ioc_value=hash_value,
                success=False,
                error=f"Invalid hash length: {hash_len}",
            )

        try:
            client = await self._get_client()

            # Get general info
            response = await client.get(f"/indicators/file/{hash_value}/general")

            if response.status_code == 404:
                return ThreatIntelResult(
                    provider=self.provider_name,
                    ioc_type=ioc_type,
                    ioc_value=hash_value,
                    reputation="unknown",
                    success=True,
                )

            response.raise_for_status()
            data = response.json()

            return self._parse_file_response(data, ioc_type, hash_value)

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return ThreatIntelResult(
                    provider=self.provider_name,
                    ioc_type=ioc_type,
                    ioc_value=hash_value,
                    reputation="unknown",
                    success=True,
                )
            logger.error("AlienVault hash lookup failed", hash=hash_value, error=str(e))
            return ThreatIntelResult(
                provider=self.provider_name,
                ioc_type=ioc_type,
                ioc_value=hash_value,
                success=False,
                error=str(e),
            )
        except Exception as e:
            logger.error("AlienVault hash lookup failed", hash=hash_value, error=str(e))
            return ThreatIntelResult(
                provider=self.provider_name,
                ioc_type=ioc_type,
                ioc_value=hash_value,
                success=False,
                error=str(e),
            )

    def _parse_file_response(
        self,
        data: dict,
        ioc_type: str,
        hash_value: str,
    ) -> ThreatIntelResult:
        """Parse AlienVault file response."""
        # Get pulse count (number of threat reports mentioning this)
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        pulses = data.get("pulse_info", {}).get("pulses", [])

        # Determine reputation based on pulse count
        if pulse_count >= 5:
            reputation = "malicious"
            is_malicious = True
        elif pulse_count >= 2:
            reputation = "suspicious"
            is_malicious = False
        elif pulse_count >= 1:
            reputation = "suspicious"
            is_malicious = False
        else:
            reputation = "clean"
            is_malicious = False

        # Extract malware families and threat types from pulses
        malware_families = []
        threat_types = []
        tags = []
        related_campaigns = []

        for pulse in pulses[:10]:  # Limit processing
            if pulse.get("name"):
                related_campaigns.append(pulse["name"])
            for tag in pulse.get("tags", []):
                if tag and tag not in tags:
                    tags.append(tag)
            # Extract malware family from pulse tags
            for tag in pulse.get("tags", []):
                tag_lower = tag.lower()
                if any(x in tag_lower for x in ["malware", "trojan", "ransomware", "rat", "backdoor"]):
                    if tag not in threat_types:
                        threat_types.append(tag)

        # Get AV detection info if available
        analysis = data.get("analysis", {})
        av_results = analysis.get("analysis", {}).get("plugins", {}).get("avast", {}).get("results", {})

        detection_names = []
        if av_results.get("detection"):
            detection_names.append(av_results["detection"])

        return ThreatIntelResult(
            provider=self.provider_name,
            ioc_type=ioc_type,
            ioc_value=hash_value,
            is_malicious=is_malicious,
            malicious_score=pulse_count,
            reputation=reputation,
            detection_count=pulse_count,
            total_engines=1,  # OTX uses pulse count, not engines
            detection_names=detection_names,
            file_type=analysis.get("analysis", {}).get("info", {}).get("file_type", ""),
            threat_types=threat_types[:5],
            malware_families=malware_families[:5],
            tags=tags[:10],
            related_campaigns=related_campaigns[:5],
            raw_response=data,
            success=True,
        )

    async def lookup_ip(self, ip_address: str) -> ThreatIntelResult:
        """
        Look up an IP address in AlienVault OTX.

        Args:
            ip_address: IPv4 or IPv6 address.

        Returns:
            ThreatIntelResult with lookup data.
        """
        # Determine IP version
        ip_type = "IPv6" if ":" in ip_address else "IPv4"

        try:
            client = await self._get_client()
            response = await client.get(f"/indicators/{ip_type}/{ip_address}/general")

            if response.status_code == 404:
                return ThreatIntelResult(
                    provider=self.provider_name,
                    ioc_type="ip",
                    ioc_value=ip_address,
                    reputation="unknown",
                    success=True,
                )

            response.raise_for_status()
            data = response.json()

            return self._parse_ip_response(data, ip_address)

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return ThreatIntelResult(
                    provider=self.provider_name,
                    ioc_type="ip",
                    ioc_value=ip_address,
                    reputation="unknown",
                    success=True,
                )
            logger.error("AlienVault IP lookup failed", ip=ip_address, error=str(e))
            return ThreatIntelResult(
                provider=self.provider_name,
                ioc_type="ip",
                ioc_value=ip_address,
                success=False,
                error=str(e),
            )
        except Exception as e:
            logger.error("AlienVault IP lookup failed", ip=ip_address, error=str(e))
            return ThreatIntelResult(
                provider=self.provider_name,
                ioc_type="ip",
                ioc_value=ip_address,
                success=False,
                error=str(e),
            )

    def _parse_ip_response(self, data: dict, ip_address: str) -> ThreatIntelResult:
        """Parse AlienVault IP response."""
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        pulses = data.get("pulse_info", {}).get("pulses", [])

        # Determine reputation
        if pulse_count >= 5:
            reputation = "malicious"
            is_malicious = True
        elif pulse_count >= 2:
            reputation = "suspicious"
            is_malicious = False
        elif pulse_count >= 1:
            reputation = "suspicious"
            is_malicious = False
        else:
            reputation = "clean"
            is_malicious = False

        # Extract tags and campaigns
        tags = []
        related_campaigns = []
        threat_types = []

        for pulse in pulses[:10]:
            if pulse.get("name"):
                related_campaigns.append(pulse["name"])
            for tag in pulse.get("tags", []):
                if tag and tag not in tags:
                    tags.append(tag)
                tag_lower = tag.lower()
                if any(x in tag_lower for x in ["c2", "c&c", "botnet", "malware", "phishing"]):
                    if tag not in threat_types:
                        threat_types.append(tag)

        return ThreatIntelResult(
            provider=self.provider_name,
            ioc_type="ip",
            ioc_value=ip_address,
            is_malicious=is_malicious,
            malicious_score=pulse_count,
            reputation=reputation,
            detection_count=pulse_count,
            total_engines=1,
            country=data.get("country_code", "") or data.get("country_name", ""),
            asn=data.get("asn", ""),
            threat_types=threat_types[:5],
            tags=tags[:10],
            related_campaigns=related_campaigns[:5],
            raw_response=data,
            success=True,
        )

    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        """
        Look up a domain in AlienVault OTX.

        Args:
            domain: Domain name.

        Returns:
            ThreatIntelResult with lookup data.
        """
        try:
            client = await self._get_client()
            response = await client.get(f"/indicators/domain/{domain}/general")

            if response.status_code == 404:
                return ThreatIntelResult(
                    provider=self.provider_name,
                    ioc_type="domain",
                    ioc_value=domain,
                    reputation="unknown",
                    success=True,
                )

            response.raise_for_status()
            data = response.json()

            return self._parse_domain_response(data, domain)

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return ThreatIntelResult(
                    provider=self.provider_name,
                    ioc_type="domain",
                    ioc_value=domain,
                    reputation="unknown",
                    success=True,
                )
            logger.error("AlienVault domain lookup failed", domain=domain, error=str(e))
            return ThreatIntelResult(
                provider=self.provider_name,
                ioc_type="domain",
                ioc_value=domain,
                success=False,
                error=str(e),
            )
        except Exception as e:
            logger.error("AlienVault domain lookup failed", domain=domain, error=str(e))
            return ThreatIntelResult(
                provider=self.provider_name,
                ioc_type="domain",
                ioc_value=domain,
                success=False,
                error=str(e),
            )

    def _parse_domain_response(self, data: dict, domain: str) -> ThreatIntelResult:
        """Parse AlienVault domain response."""
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        pulses = data.get("pulse_info", {}).get("pulses", [])

        # Determine reputation
        if pulse_count >= 5:
            reputation = "malicious"
            is_malicious = True
        elif pulse_count >= 2:
            reputation = "suspicious"
            is_malicious = False
        elif pulse_count >= 1:
            reputation = "suspicious"
            is_malicious = False
        else:
            reputation = "clean"
            is_malicious = False

        # Extract tags and campaigns
        tags = []
        related_campaigns = []
        threat_types = []

        for pulse in pulses[:10]:
            if pulse.get("name"):
                related_campaigns.append(pulse["name"])
            for tag in pulse.get("tags", []):
                if tag and tag not in tags:
                    tags.append(tag)
                tag_lower = tag.lower()
                if any(x in tag_lower for x in ["c2", "c&c", "phishing", "malware", "dga"]):
                    if tag not in threat_types:
                        threat_types.append(tag)

        # Get whois info if available
        whois = data.get("whois", {})

        return ThreatIntelResult(
            provider=self.provider_name,
            ioc_type="domain",
            ioc_value=domain,
            is_malicious=is_malicious,
            malicious_score=pulse_count,
            reputation=reputation,
            detection_count=pulse_count,
            total_engines=1,
            registrar=whois.get("registrar", ""),
            threat_types=threat_types[:5],
            tags=tags[:10],
            related_campaigns=related_campaigns[:5],
            raw_response=data,
            success=True,
        )

    async def lookup_url(self, url: str) -> ThreatIntelResult:
        """
        Look up a URL in AlienVault OTX.

        Args:
            url: Full URL.

        Returns:
            ThreatIntelResult with lookup data.
        """
        try:
            client = await self._get_client()
            response = await client.get(f"/indicators/url/{url}/general")

            if response.status_code == 404:
                return ThreatIntelResult(
                    provider=self.provider_name,
                    ioc_type="url",
                    ioc_value=url,
                    reputation="unknown",
                    success=True,
                )

            response.raise_for_status()
            data = response.json()

            pulse_count = data.get("pulse_info", {}).get("count", 0)

            if pulse_count >= 3:
                reputation = "malicious"
                is_malicious = True
            elif pulse_count >= 1:
                reputation = "suspicious"
                is_malicious = False
            else:
                reputation = "clean"
                is_malicious = False

            return ThreatIntelResult(
                provider=self.provider_name,
                ioc_type="url",
                ioc_value=url,
                is_malicious=is_malicious,
                malicious_score=pulse_count,
                reputation=reputation,
                detection_count=pulse_count,
                total_engines=1,
                raw_response=data,
                success=True,
            )

        except Exception as e:
            logger.error("AlienVault URL lookup failed", url=url, error=str(e))
            return ThreatIntelResult(
                provider=self.provider_name,
                ioc_type="url",
                ioc_value=url,
                success=False,
                error=str(e),
            )

    async def test_connectivity(self) -> bool:
        """
        Test API connectivity to AlienVault OTX.

        Returns:
            True if connection is successful.
        """
        try:
            client = await self._get_client()
            # Get user info to verify API key
            response = await client.get("/users/me")
            response.raise_for_status()

            logger.info("AlienVault OTX connectivity test passed")
            return True
        except Exception as e:
            logger.error("AlienVault OTX connectivity test failed", error=str(e))
            raise

    async def close(self) -> None:
        """Clean up HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
