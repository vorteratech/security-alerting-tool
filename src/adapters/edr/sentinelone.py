"""
SentinelOne EDR adapter.

Handles:
- Parsing webhook payloads from SentinelOne
- Normalizing alerts to common format
- API calls for resolve and containment actions
"""

from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

import httpx

from ...config.logging import get_logger
from .base import Alert, BaseEDRAdapter

logger = get_logger(__name__)


class SentinelOneAdapter(BaseEDRAdapter):
    """
    SentinelOne EDR adapter implementation.

    Supports:
    - Webhook parsing for threat events
    - Threat resolution via API
    - Network containment via API
    """

    def __init__(self, api_key: str, api_url: str, **kwargs):
        """
        Initialize the SentinelOne adapter.

        Args:
            api_key: SentinelOne API token.
            api_url: SentinelOne console URL (e.g., https://usea1.sentinelone.net).
            **kwargs: Additional configuration.
        """
        super().__init__(api_key, api_url, **kwargs)
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def provider_name(self) -> str:
        return "sentinelone"

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=f"{self.api_url}/web/api/v2.1",
                headers={
                    "Authorization": f"ApiToken {self.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )
        return self._client

    def parse_webhook(self, payload: dict[str, Any]) -> Alert:
        """
        Parse a SentinelOne webhook payload into a normalized Alert.

        SentinelOne webhook structure varies by event type. This handles
        threat-related events.

        Args:
            payload: Raw webhook payload from SentinelOne.

        Returns:
            Normalized Alert object.

        Raises:
            ValueError: If payload cannot be parsed.
        """
        try:
            # Handle different payload structures
            data = payload.get("data", payload)

            # Get threat info
            threat_info = data.get("threatInfo", {})
            agent_info = data.get("agentRealtimeInfo", {}) or data.get("agentDetectionInfo", {})

            # Get indicators (file hashes, etc.)
            indicators = data.get("indicators", [])
            file_indicator = next(
                (i for i in indicators if i.get("category") == "file"),
                {}
            )

            # Parse timestamp
            timestamp_str = (
                threat_info.get("createdAt") or
                data.get("createdAt") or
                datetime.utcnow().isoformat()
            )
            if isinstance(timestamp_str, str):
                # Handle S1 timestamp format
                timestamp = datetime.fromisoformat(
                    timestamp_str.replace("Z", "+00:00")
                )
            else:
                timestamp = datetime.utcnow()

            # Map S1 severity to our format
            confidence = threat_info.get("confidenceLevel", "").lower()
            severity_map = {
                "malicious": "critical",
                "suspicious": "high",
                "high": "high",
                "medium": "medium",
                "low": "low",
            }
            severity = severity_map.get(confidence, "medium")

            # Build the normalized alert
            alert = Alert(
                id=str(uuid4()),
                source="sentinelone",
                source_alert_id=str(data.get("id", "")),
                timestamp=timestamp,
                severity=severity,
                confidence=self._confidence_to_score(confidence),

                # Endpoint info
                hostname=agent_info.get("agentComputerName", ""),
                endpoint_ip=agent_info.get("agentIpAddress", ""),
                endpoint_os=agent_info.get("agentOsName", ""),
                endpoint_os_version=agent_info.get("agentOsRevision", ""),
                endpoint_user=agent_info.get("agentLastLoggedInUserName", ""),
                endpoint_domain=agent_info.get("agentDomain", ""),
                agent_id=str(agent_info.get("agentId", "")),

                # Site info
                site_name=agent_info.get("siteName", ""),
                site_id=str(agent_info.get("siteId", "")),
                client_name=agent_info.get("siteName", ""),  # Use site as client

                # Threat info
                threat_name=threat_info.get("threatName", ""),
                threat_classification=threat_info.get("classification", ""),
                threat_description=threat_info.get("description", ""),
                mitre_tactics=self._extract_mitre(threat_info, "tactics"),
                mitre_techniques=self._extract_mitre(threat_info, "techniques"),

                # File indicators
                file_path=file_indicator.get("filePath", "") or threat_info.get("filePath", ""),
                file_name=file_indicator.get("fileName", "") or threat_info.get("originatorProcess", ""),
                file_hash_sha256=file_indicator.get("sha256", "") or threat_info.get("sha256", ""),
                file_hash_sha1=file_indicator.get("sha1", "") or threat_info.get("sha1", ""),
                file_hash_md5=file_indicator.get("md5", "") or threat_info.get("md5", ""),
                file_size=file_indicator.get("fileSize"),
                file_signed=threat_info.get("signedStatus") == "signed",
                file_signer=threat_info.get("publisher", ""),

                # Process info
                process_name=threat_info.get("originatorProcess", ""),
                process_id=threat_info.get("processId"),
                process_path=threat_info.get("processPath", ""),
                command_line=threat_info.get("commandLineArguments", ""),
                parent_process_name=threat_info.get("parentProcessName", ""),

                # Network (if available)
                remote_ip=data.get("networkInfo", {}).get("dstIp", ""),
                remote_domain=data.get("networkInfo", {}).get("dstDns", ""),
                remote_port=data.get("networkInfo", {}).get("dstPort"),

                # Raw data for reference
                raw_data=payload,
            )

            logger.info(
                "Parsed SentinelOne alert",
                alert_id=alert.source_alert_id,
                threat_name=alert.threat_name,
                hostname=alert.hostname,
            )

            return alert

        except Exception as e:
            logger.error("Failed to parse SentinelOne webhook", error=str(e))
            raise ValueError(f"Failed to parse SentinelOne webhook: {e}")

    def _confidence_to_score(self, confidence: str) -> int:
        """Convert S1 confidence level to numeric score."""
        mapping = {
            "malicious": 95,
            "suspicious": 70,
            "high": 80,
            "medium": 50,
            "low": 30,
        }
        return mapping.get(confidence.lower(), 50)

    def _extract_mitre(self, threat_info: dict, field: str) -> list[str]:
        """Extract MITRE tactics or techniques from threat info."""
        mitre_data = threat_info.get("mitreTactics", []) if field == "tactics" else []
        if not mitre_data:
            mitre_data = threat_info.get("mitreTechniques", []) if field == "techniques" else []

        if isinstance(mitre_data, list):
            return [str(item) for item in mitre_data if item]
        return []

    async def resolve_alert(self, alert_id: str, comment: str = "") -> bool:
        """
        Mark a threat as resolved in SentinelOne.

        Args:
            alert_id: The threat ID in SentinelOne.
            comment: Optional analyst comment.

        Returns:
            True if successful.
        """
        try:
            client = await self._get_client()

            # S1 uses "incidents/analyst-verdict" to mark threats as resolved
            response = await client.post(
                "/threats/analyst-verdict",
                json={
                    "filter": {
                        "ids": [alert_id]
                    },
                    "data": {
                        "analystVerdict": "false_positive"  # or "true_positive", "suspicious", "undefined"
                    }
                }
            )
            response.raise_for_status()

            # Also add note if comment provided
            if comment:
                await client.post(
                    "/threats/notes",
                    json={
                        "filter": {"ids": [alert_id]},
                        "data": {"text": comment}
                    }
                )

            logger.info("Resolved SentinelOne threat", threat_id=alert_id)
            return True

        except Exception as e:
            logger.error("Failed to resolve SentinelOne threat", threat_id=alert_id, error=str(e))
            raise

    async def contain_endpoint(self, agent_id: str, comment: str = "") -> bool:
        """
        Network isolate an endpoint in SentinelOne.

        Args:
            agent_id: The agent ID in SentinelOne.
            comment: Optional comment.

        Returns:
            True if successful.
        """
        try:
            client = await self._get_client()

            response = await client.post(
                "/agents/actions/disconnect",
                json={
                    "filter": {
                        "ids": [agent_id]
                    }
                }
            )
            response.raise_for_status()

            # Add note if comment provided
            if comment:
                await client.post(
                    "/agents/actions/notes",
                    json={
                        "filter": {"ids": [agent_id]},
                        "data": {"text": f"Network contained: {comment}"}
                    }
                )

            logger.info("Contained endpoint in SentinelOne", agent_id=agent_id)
            return True

        except Exception as e:
            logger.error("Failed to contain endpoint", agent_id=agent_id, error=str(e))
            raise

    async def uncontain_endpoint(self, agent_id: str, comment: str = "") -> bool:
        """
        Remove network isolation from an endpoint.

        Args:
            agent_id: The agent ID in SentinelOne.
            comment: Optional comment.

        Returns:
            True if successful.
        """
        try:
            client = await self._get_client()

            response = await client.post(
                "/agents/actions/connect",
                json={
                    "filter": {
                        "ids": [agent_id]
                    }
                }
            )
            response.raise_for_status()

            logger.info("Uncontained endpoint in SentinelOne", agent_id=agent_id)
            return True

        except Exception as e:
            logger.error("Failed to uncontain endpoint", agent_id=agent_id, error=str(e))
            raise

    async def get_alert_details(self, alert_id: str) -> Optional[Alert]:
        """
        Get full details for a threat.

        Args:
            alert_id: The threat ID in SentinelOne.

        Returns:
            Alert object with full details, or None if not found.
        """
        try:
            client = await self._get_client()

            response = await client.get(
                "/threats",
                params={"ids": [alert_id]}
            )
            response.raise_for_status()

            data = response.json()
            threats = data.get("data", [])

            if not threats:
                return None

            # Parse the threat data
            return self.parse_webhook({"data": threats[0]})

        except Exception as e:
            logger.error("Failed to get threat details", threat_id=alert_id, error=str(e))
            return None

    async def test_connectivity(self) -> bool:
        """
        Test API connectivity to SentinelOne.

        Returns:
            True if connection is successful.
        """
        try:
            client = await self._get_client()

            # Simple API call to test auth
            response = await client.get("/system/status")
            response.raise_for_status()

            logger.info("SentinelOne connectivity test passed")
            return True

        except Exception as e:
            logger.error("SentinelOne connectivity test failed", error=str(e))
            raise

    async def close(self) -> None:
        """Clean up HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
