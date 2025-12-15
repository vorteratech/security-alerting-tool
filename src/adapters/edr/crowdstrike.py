"""
CrowdStrike Falcon EDR adapter.

Handles:
- Parsing webhook payloads from CrowdStrike
- Normalizing alerts to common format
- API calls for resolve and containment actions

Note: CrowdStrike uses OAuth2 authentication with client_id and client_secret.
"""

from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

import httpx

from ...config.logging import get_logger
from .base import Alert, BaseEDRAdapter

logger = get_logger(__name__)


class CrowdStrikeAdapter(BaseEDRAdapter):
    """
    CrowdStrike Falcon EDR adapter implementation.

    Supports:
    - Webhook parsing for detection events
    - Detection status updates via API
    - Real-time response (RTR) for containment
    """

    # CrowdStrike API base URLs by cloud
    CLOUD_URLS = {
        "us-1": "https://api.crowdstrike.com",
        "us-2": "https://api.us-2.crowdstrike.com",
        "eu-1": "https://api.eu-1.crowdstrike.com",
        "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
    }

    def __init__(
        self,
        api_key: str,  # client_id
        api_url: str,
        api_secret: str = "",  # client_secret
        cloud: str = "us-1",
        **kwargs
    ):
        """
        Initialize the CrowdStrike adapter.

        Args:
            api_key: CrowdStrike OAuth2 client_id.
            api_url: CrowdStrike API URL (or use cloud parameter).
            api_secret: CrowdStrike OAuth2 client_secret.
            cloud: Cloud region (us-1, us-2, eu-1, us-gov-1).
            **kwargs: Additional configuration.
        """
        # Use cloud URL if api_url not specified
        if not api_url or api_url == "auto":
            api_url = self.CLOUD_URLS.get(cloud, self.CLOUD_URLS["us-1"])

        super().__init__(api_key, api_url, **kwargs)
        self.client_id = api_key
        self.client_secret = api_secret
        self._client: Optional[httpx.AsyncClient] = None
        self._access_token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

    @property
    def provider_name(self) -> str:
        return "crowdstrike"

    async def _get_access_token(self) -> str:
        """Get or refresh OAuth2 access token."""
        # Check if we have a valid token
        if self._access_token and self._token_expiry:
            if datetime.utcnow() < self._token_expiry:
                return self._access_token

        # Request new token
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.api_url}/oauth2/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()

            data = response.json()
            self._access_token = data["access_token"]
            # Token typically expires in 30 minutes, refresh at 25
            expires_in = data.get("expires_in", 1800)
            from datetime import timedelta
            self._token_expiry = datetime.utcnow() + timedelta(seconds=expires_in - 300)

            return self._access_token

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create authenticated HTTP client."""
        token = await self._get_access_token()

        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.api_url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )
        else:
            # Update token in existing client
            self._client.headers["Authorization"] = f"Bearer {token}"

        return self._client

    def parse_webhook(self, payload: dict[str, Any]) -> Alert:
        """
        Parse a CrowdStrike webhook payload into a normalized Alert.

        CrowdStrike sends DetectionSummaryEvent for detections.

        Args:
            payload: Raw webhook payload from CrowdStrike.

        Returns:
            Normalized Alert object.

        Raises:
            ValueError: If payload cannot be parsed.
        """
        try:
            # Handle streaming API format
            metadata = payload.get("metadata", {})
            body = payload.get("body", payload.get("event", payload))

            # Parse timestamp
            timestamp_str = (
                body.get("timestamp") or
                metadata.get("eventCreationTime") or
                datetime.utcnow().isoformat()
            )
            if isinstance(timestamp_str, str):
                try:
                    timestamp = datetime.fromisoformat(
                        timestamp_str.replace("Z", "+00:00")
                    )
                except ValueError:
                    # Try epoch format
                    timestamp = datetime.utcfromtimestamp(int(timestamp_str) / 1000)
            elif isinstance(timestamp_str, (int, float)):
                timestamp = datetime.utcfromtimestamp(timestamp_str / 1000)
            else:
                timestamp = datetime.utcnow()

            # Map CS severity (1-5) to our format
            cs_severity = body.get("severity", 3)
            severity_map = {
                5: "critical",
                4: "high",
                3: "medium",
                2: "low",
                1: "info",
            }
            severity = severity_map.get(cs_severity, "medium")

            # Extract detection ID
            detection_id = (
                body.get("detection_id") or
                body.get("composite_id") or
                body.get("id", "")
            )

            # Build the normalized alert
            alert = Alert(
                id=str(uuid4()),
                source="crowdstrike",
                source_alert_id=str(detection_id),
                timestamp=timestamp,
                severity=severity,
                confidence=self._severity_to_confidence(cs_severity),

                # Endpoint info
                hostname=body.get("computer_name", "") or body.get("hostname", ""),
                endpoint_ip=body.get("local_ip", "") or body.get("agent_local_ip", ""),
                endpoint_os=body.get("platform", "") or body.get("os_version", ""),
                endpoint_os_version=body.get("os_version", ""),
                endpoint_user=body.get("user_name", "") or body.get("user_id", ""),
                endpoint_domain=body.get("machine_domain", ""),
                agent_id=body.get("device_id", "") or body.get("agent_id", ""),

                # Host group as site
                site_name=body.get("host_groups", [""])[0] if body.get("host_groups") else "",
                client_name=body.get("host_groups", [""])[0] if body.get("host_groups") else "",

                # Threat info
                threat_name=body.get("detect_name", "") or body.get("display_name", ""),
                threat_classification=body.get("tactic", "") or body.get("scenario", ""),
                threat_description=body.get("detect_description", "") or body.get("description", ""),
                mitre_tactics=[body.get("tactic", "")] if body.get("tactic") else [],
                mitre_techniques=[body.get("technique", "")] if body.get("technique") else [],

                # File indicators
                file_path=body.get("file_path", "") or body.get("filepath", ""),
                file_name=body.get("file_name", "") or body.get("filename", ""),
                file_hash_sha256=body.get("sha256", "") or body.get("sha256_hash", ""),
                file_hash_sha1=body.get("sha1", ""),
                file_hash_md5=body.get("md5", "") or body.get("md5_hash", ""),

                # Process info
                process_name=body.get("process_name", "") or body.get("file_name", ""),
                process_id=body.get("process_id") or body.get("target_process_id"),
                command_line=body.get("cmdline", "") or body.get("command_line", ""),
                parent_process_name=body.get("parent_process_name", ""),
                parent_command_line=body.get("parent_cmdline", ""),

                # Network indicators
                remote_ip=body.get("external_ip", "") or body.get("remote_ip", ""),
                remote_domain=body.get("domain_name", ""),
                remote_port=body.get("remote_port"),

                # Raw data
                raw_data=payload,
            )

            logger.info(
                "Parsed CrowdStrike detection",
                detection_id=alert.source_alert_id,
                threat_name=alert.threat_name,
                hostname=alert.hostname,
            )

            return alert

        except Exception as e:
            logger.error("Failed to parse CrowdStrike webhook", error=str(e))
            raise ValueError(f"Failed to parse CrowdStrike webhook: {e}")

    def _severity_to_confidence(self, severity: int) -> int:
        """Convert CS severity to confidence score."""
        # CS severity 1-5 maps to confidence
        return min(severity * 20, 100)

    async def resolve_alert(self, alert_id: str, comment: str = "") -> bool:
        """
        Update detection status to closed in CrowdStrike.

        Args:
            alert_id: The detection ID in CrowdStrike.
            comment: Optional comment.

        Returns:
            True if successful.
        """
        try:
            client = await self._get_client()

            # Update detection status
            response = await client.patch(
                "/detects/entities/detects/v2",
                json={
                    "ids": [alert_id],
                    "status": "closed",
                    "comment": comment or "Closed via Security Alerting Tool"
                }
            )
            response.raise_for_status()

            logger.info("Resolved CrowdStrike detection", detection_id=alert_id)
            return True

        except Exception as e:
            logger.error("Failed to resolve detection", detection_id=alert_id, error=str(e))
            raise

    async def contain_endpoint(self, agent_id: str, comment: str = "") -> bool:
        """
        Network contain a host in CrowdStrike.

        Args:
            agent_id: The device/agent ID in CrowdStrike.
            comment: Optional comment.

        Returns:
            True if successful.
        """
        try:
            client = await self._get_client()

            # Contain the host
            response = await client.post(
                "/devices/entities/devices-actions/v2",
                params={"action_name": "contain"},
                json={
                    "ids": [agent_id]
                }
            )
            response.raise_for_status()

            logger.info("Contained host in CrowdStrike", device_id=agent_id)
            return True

        except Exception as e:
            logger.error("Failed to contain host", device_id=agent_id, error=str(e))
            raise

    async def uncontain_endpoint(self, agent_id: str, comment: str = "") -> bool:
        """
        Lift containment from a host.

        Args:
            agent_id: The device/agent ID in CrowdStrike.
            comment: Optional comment.

        Returns:
            True if successful.
        """
        try:
            client = await self._get_client()

            # Lift containment
            response = await client.post(
                "/devices/entities/devices-actions/v2",
                params={"action_name": "lift_containment"},
                json={
                    "ids": [agent_id]
                }
            )
            response.raise_for_status()

            logger.info("Lifted containment in CrowdStrike", device_id=agent_id)
            return True

        except Exception as e:
            logger.error("Failed to lift containment", device_id=agent_id, error=str(e))
            raise

    async def get_alert_details(self, alert_id: str) -> Optional[Alert]:
        """
        Get full details for a detection.

        Args:
            alert_id: The detection ID in CrowdStrike.

        Returns:
            Alert object with full details, or None if not found.
        """
        try:
            client = await self._get_client()

            # Get detection details
            response = await client.get(
                "/detects/entities/summaries/GET/v1",
                params={"ids": [alert_id]}
            )
            response.raise_for_status()

            data = response.json()
            resources = data.get("resources", [])

            if not resources:
                return None

            # Parse the detection
            return self.parse_webhook({"body": resources[0]})

        except Exception as e:
            logger.error("Failed to get detection details", detection_id=alert_id, error=str(e))
            return None

    async def test_connectivity(self) -> bool:
        """
        Test API connectivity to CrowdStrike.

        Returns:
            True if connection is successful.
        """
        try:
            # This will test OAuth2 authentication
            await self._get_access_token()

            client = await self._get_client()

            # Simple API call to verify
            response = await client.get("/sensors/queries/installers/v1", params={"limit": 1})
            response.raise_for_status()

            logger.info("CrowdStrike connectivity test passed")
            return True

        except Exception as e:
            logger.error("CrowdStrike connectivity test failed", error=str(e))
            raise

    async def close(self) -> None:
        """Clean up HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
        self._access_token = None
        self._token_expiry = None
