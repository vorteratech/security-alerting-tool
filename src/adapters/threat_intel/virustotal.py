"""
VirusTotal threat intelligence adapter.

Provides lookups for:
- File hashes (MD5, SHA1, SHA256)
- IP addresses
- Domains
- URLs
"""

from datetime import datetime
from typing import Optional

import httpx

from ...config.logging import get_logger
from .base import BaseThreatIntelAdapter, ThreatIntelResult

logger = get_logger(__name__)


class VirusTotalAdapter(BaseThreatIntelAdapter):
    """
    VirusTotal API v3 adapter.

    Requires a VirusTotal API key. Free tier has rate limits:
    - 4 requests per minute
    - 500 requests per day
    """

    API_BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, **kwargs):
        """
        Initialize the VirusTotal adapter.

        Args:
            api_key: VirusTotal API key.
            **kwargs: Additional configuration.
        """
        super().__init__(api_key, **kwargs)
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def provider_name(self) -> str:
        return "virustotal"

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.API_BASE,
                headers={
                    "x-apikey": self.api_key,
                    "Accept": "application/json",
                },
                timeout=30.0,
            )
        return self._client

    async def lookup_hash(self, hash_value: str) -> ThreatIntelResult:
        """
        Look up a file hash in VirusTotal.

        Args:
            hash_value: MD5, SHA1, or SHA256 hash.

        Returns:
            ThreatIntelResult with lookup data.
        """
        # Determine hash type
        hash_len = len(hash_value)
        if hash_len == 32:
            ioc_type = "hash_md5"
        elif hash_len == 40:
            ioc_type = "hash_sha1"
        elif hash_len == 64:
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
            response = await client.get(f"/files/{hash_value}")

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
            logger.error("VirusTotal hash lookup failed", hash=hash_value, error=str(e))
            return ThreatIntelResult(
                provider=self.provider_name,
                ioc_type=ioc_type,
                ioc_value=hash_value,
                success=False,
                error=str(e),
            )
        except Exception as e:
            logger.error("VirusTotal hash lookup failed", hash=hash_value, error=str(e))
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
        """Parse VirusTotal file response."""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        # Determine reputation
        if malicious > 5:
            reputation = "malicious"
            is_malicious = True
        elif malicious > 0 or suspicious > 3:
            reputation = "suspicious"
            is_malicious = False
        elif total > 0:
            reputation = "clean"
            is_malicious = False
        else:
            reputation = "unknown"
            is_malicious = False

        # Get detection names
        results = attributes.get("last_analysis_results", {})
        detection_names = [
            r.get("result", "")
            for r in results.values()
            if r.get("category") == "malicious" and r.get("result")
        ]

        # Parse timestamps
        first_seen = None
        last_seen = None
        if attributes.get("first_submission_date"):
            first_seen = datetime.utcfromtimestamp(attributes["first_submission_date"])
        if attributes.get("last_analysis_date"):
            last_seen = datetime.utcfromtimestamp(attributes["last_analysis_date"])

        # Get threat classification
        popular_threat = attributes.get("popular_threat_classification", {})
        threat_types = []
        if popular_threat.get("suggested_threat_label"):
            threat_types.append(popular_threat["suggested_threat_label"])

        malware_families = []
        for family in popular_threat.get("popular_threat_name", []):
            if family.get("value"):
                malware_families.append(family["value"])

        return ThreatIntelResult(
            provider=self.provider_name,
            ioc_type=ioc_type,
            ioc_value=hash_value,
            is_malicious=is_malicious,
            malicious_score=malicious,
            reputation=reputation,
            detection_count=malicious + suspicious,
            total_engines=total,
            detection_names=detection_names[:10],  # Limit to 10
            file_type=attributes.get("type_description", ""),
            file_size=attributes.get("size"),
            first_seen=first_seen,
            last_seen=last_seen,
            threat_types=threat_types,
            malware_families=malware_families[:5],
            tags=attributes.get("tags", [])[:10],
            raw_response=data,
            success=True,
        )

    async def lookup_ip(self, ip_address: str) -> ThreatIntelResult:
        """
        Look up an IP address in VirusTotal.

        Args:
            ip_address: IPv4 or IPv6 address.

        Returns:
            ThreatIntelResult with lookup data.
        """
        try:
            client = await self._get_client()
            response = await client.get(f"/ip_addresses/{ip_address}")

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
            logger.error("VirusTotal IP lookup failed", ip=ip_address, error=str(e))
            return ThreatIntelResult(
                provider=self.provider_name,
                ioc_type="ip",
                ioc_value=ip_address,
                success=False,
                error=str(e),
            )
        except Exception as e:
            logger.error("VirusTotal IP lookup failed", ip=ip_address, error=str(e))
            return ThreatIntelResult(
                provider=self.provider_name,
                ioc_type="ip",
                ioc_value=ip_address,
                success=False,
                error=str(e),
            )

    def _parse_ip_response(self, data: dict, ip_address: str) -> ThreatIntelResult:
        """Parse VirusTotal IP response."""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        # Determine reputation
        if malicious > 3:
            reputation = "malicious"
            is_malicious = True
        elif malicious > 0 or suspicious > 2:
            reputation = "suspicious"
            is_malicious = False
        elif total > 0:
            reputation = "clean"
            is_malicious = False
        else:
            reputation = "unknown"
            is_malicious = False

        return ThreatIntelResult(
            provider=self.provider_name,
            ioc_type="ip",
            ioc_value=ip_address,
            is_malicious=is_malicious,
            malicious_score=malicious,
            reputation=reputation,
            detection_count=malicious + suspicious,
            total_engines=total,
            country=attributes.get("country", ""),
            asn=str(attributes.get("asn", "")),
            asn_owner=attributes.get("as_owner", ""),
            tags=attributes.get("tags", [])[:10],
            raw_response=data,
            success=True,
        )

    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        """
        Look up a domain in VirusTotal.

        Args:
            domain: Domain name.

        Returns:
            ThreatIntelResult with lookup data.
        """
        try:
            client = await self._get_client()
            response = await client.get(f"/domains/{domain}")

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
            logger.error("VirusTotal domain lookup failed", domain=domain, error=str(e))
            return ThreatIntelResult(
                provider=self.provider_name,
                ioc_type="domain",
                ioc_value=domain,
                success=False,
                error=str(e),
            )
        except Exception as e:
            logger.error("VirusTotal domain lookup failed", domain=domain, error=str(e))
            return ThreatIntelResult(
                provider=self.provider_name,
                ioc_type="domain",
                ioc_value=domain,
                success=False,
                error=str(e),
            )

    def _parse_domain_response(self, data: dict, domain: str) -> ThreatIntelResult:
        """Parse VirusTotal domain response."""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        # Determine reputation
        if malicious > 3:
            reputation = "malicious"
            is_malicious = True
        elif malicious > 0 or suspicious > 2:
            reputation = "suspicious"
            is_malicious = False
        elif total > 0:
            reputation = "clean"
            is_malicious = False
        else:
            reputation = "unknown"
            is_malicious = False

        # Get registrar info
        whois = attributes.get("whois", "")
        registrar = ""
        for line in whois.split("\n"):
            if "Registrar:" in line:
                registrar = line.split(":", 1)[1].strip()
                break

        return ThreatIntelResult(
            provider=self.provider_name,
            ioc_type="domain",
            ioc_value=domain,
            is_malicious=is_malicious,
            malicious_score=malicious,
            reputation=reputation,
            detection_count=malicious + suspicious,
            total_engines=total,
            registrar=registrar,
            tags=attributes.get("tags", [])[:10],
            raw_response=data,
            success=True,
        )

    async def lookup_url(self, url: str) -> ThreatIntelResult:
        """
        Look up a URL in VirusTotal.

        Args:
            url: Full URL.

        Returns:
            ThreatIntelResult with lookup data.
        """
        import base64

        try:
            # VT uses base64-encoded URL as identifier
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

            client = await self._get_client()
            response = await client.get(f"/urls/{url_id}")

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

            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0

            if malicious > 3:
                reputation = "malicious"
                is_malicious = True
            elif malicious > 0 or suspicious > 2:
                reputation = "suspicious"
                is_malicious = False
            elif total > 0:
                reputation = "clean"
                is_malicious = False
            else:
                reputation = "unknown"
                is_malicious = False

            return ThreatIntelResult(
                provider=self.provider_name,
                ioc_type="url",
                ioc_value=url,
                is_malicious=is_malicious,
                malicious_score=malicious,
                reputation=reputation,
                detection_count=malicious + suspicious,
                total_engines=total,
                tags=attributes.get("tags", [])[:10],
                raw_response=data,
                success=True,
            )

        except Exception as e:
            logger.error("VirusTotal URL lookup failed", url=url, error=str(e))
            return ThreatIntelResult(
                provider=self.provider_name,
                ioc_type="url",
                ioc_value=url,
                success=False,
                error=str(e),
            )

    async def test_connectivity(self) -> bool:
        """
        Test API connectivity to VirusTotal.

        Returns:
            True if connection is successful.
        """
        try:
            client = await self._get_client()
            # Look up a known safe hash (empty file)
            response = await client.get(
                "/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
            # 404 is OK (means API key works), only auth errors fail
            if response.status_code in (200, 404):
                logger.info("VirusTotal connectivity test passed")
                return True
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error("VirusTotal connectivity test failed", error=str(e))
            raise

    async def close(self) -> None:
        """Clean up HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
