"""
Alert Processing Service.

Orchestrates the complete alert processing pipeline:
1. Receive and parse webhook from EDR
2. Enrich with threat intelligence
3. Analyze with AI
4. Create ticket in PSA
5. Post to chat with action buttons
"""

import json
from dataclasses import asdict
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..adapters.edr.base import Alert
from ..adapters.edr import SentinelOneAdapter, CrowdStrikeAdapter
from ..config.logging import get_logger
from ..config.settings import Settings
from ..database.models import AuditLog, IntegrationSetting
from ..security.encryption import create_encryption_service

logger = get_logger(__name__)


class AlertProcessor:
    """
    Main service for processing security alerts.

    Coordinates the flow from EDR webhook to final notification.
    """

    def __init__(self, settings: Settings, db_session: AsyncSession):
        """
        Initialize the alert processor.

        Args:
            settings: Application settings.
            db_session: Database session for loading integrations.
        """
        self.settings = settings
        self.db = db_session
        self._adapters: dict[str, Any] = {}
        self._encryption = None

    async def _get_encryption(self):
        """Get encryption service."""
        if self._encryption is None:
            self._encryption = create_encryption_service(
                self.settings.master_encryption_key
            )
        return self._encryption

    async def _load_integration(
        self,
        integration_type: str,
        provider: str
    ) -> Optional[IntegrationSetting]:
        """Load integration settings from database."""
        from sqlalchemy import select, and_

        query = select(IntegrationSetting).where(
            and_(
                IntegrationSetting.integration_type == integration_type,
                IntegrationSetting.provider == provider,
                IntegrationSetting.enabled == True,
            )
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def _get_edr_adapter(self, source: str):
        """Get or create EDR adapter for the given source."""
        if source in self._adapters:
            return self._adapters[source]

        integration = await self._load_integration("edr", source)
        if not integration:
            logger.warning(f"No enabled integration found for EDR: {source}")
            return None

        encryption = await self._get_encryption()
        config = json.loads(integration.config_json) if integration.config_json else {}

        # Decrypt API key
        api_key = ""
        if integration.api_key_encrypted:
            api_key = encryption.decrypt(integration.api_key_encrypted)

        api_secret = ""
        if integration.api_secret_encrypted:
            api_secret = encryption.decrypt(integration.api_secret_encrypted)

        if source == "sentinelone":
            adapter = SentinelOneAdapter(
                api_key=api_key,
                api_url=config.get("api_url", ""),
                **config
            )
        elif source == "crowdstrike":
            adapter = CrowdStrikeAdapter(
                api_key=api_key,
                api_url=config.get("api_url", "auto"),
                api_secret=api_secret,
                cloud=config.get("cloud", "us-1"),
                **config
            )
        else:
            logger.error(f"Unknown EDR source: {source}")
            return None

        self._adapters[source] = adapter
        return adapter

    async def process_webhook(
        self,
        source: str,
        payload: dict[str, Any],
    ) -> Optional[Alert]:
        """
        Process an incoming webhook from an EDR platform.

        This is the main entry point for alert processing.

        Args:
            source: EDR source ("sentinelone" or "crowdstrike").
            payload: Raw webhook payload.

        Returns:
            Processed Alert object, or None if processing failed.
        """
        logger.info("Processing webhook", source=source)

        try:
            # 1. Parse the webhook into a normalized Alert
            alert = await self._parse_webhook(source, payload)
            if not alert:
                return None

            # 2. Enrich with threat intelligence
            alert = await self._enrich_alert(alert)

            # 3. Analyze with AI
            alert = await self._analyze_alert(alert)

            # 4. Create ticket in PSA
            alert = await self._create_ticket(alert)

            # 5. Post to chat
            alert = await self._post_to_chat(alert)

            # 6. Log successful processing
            await self._log_action(
                action_type="webhook_processed",
                alert=alert,
                result="success",
                details={"ticket_id": alert.ticket_id},
            )

            logger.info(
                "Alert processed successfully",
                alert_id=alert.id,
                source_alert_id=alert.source_alert_id,
                ticket_id=alert.ticket_id,
            )

            return alert

        except Exception as e:
            logger.error(
                "Failed to process webhook",
                source=source,
                error=str(e),
                exc_info=e,
            )
            await self._log_action(
                action_type="webhook_processed",
                alert=None,
                result="failure",
                details={"error": str(e), "source": source},
            )
            raise

    async def _parse_webhook(
        self,
        source: str,
        payload: dict[str, Any],
    ) -> Optional[Alert]:
        """Parse webhook using the appropriate adapter."""
        if source == "sentinelone":
            adapter = SentinelOneAdapter(api_key="", api_url="")
            return adapter.parse_webhook(payload)
        elif source == "crowdstrike":
            adapter = CrowdStrikeAdapter(api_key="", api_url="")
            return adapter.parse_webhook(payload)
        else:
            logger.error(f"Unknown webhook source: {source}")
            return None

    async def _enrich_alert(self, alert: Alert) -> Alert:
        """
        Enrich alert with threat intelligence.

        Looks up IOCs in configured threat intel providers.
        """
        from .enrichment import EnrichmentService

        try:
            enrichment_service = EnrichmentService(self.settings, self.db)
            enrichment_result = await enrichment_service.enrich_alert(alert)
            await enrichment_service.close()

            # Store enrichment data in alert
            alert.enrichment = enrichment_result.to_dict()

            logger.info(
                "Alert enriched",
                alert_id=alert.id,
                is_malicious=enrichment_result.is_malicious,
                severity=enrichment_result.highest_severity,
                providers=list(enrichment_result.results.keys()),
            )

        except Exception as e:
            logger.warning(
                "Enrichment failed, continuing without",
                alert_id=alert.id,
                error=str(e),
            )
            # Don't fail the whole pipeline if enrichment fails
            alert.enrichment = None

        return alert

    async def _analyze_alert(self, alert: Alert) -> Alert:
        """
        Analyze alert with AI.

        Sends alert data to configured AI provider for analysis.
        """
        from .ai_analyzer import AIAnalyzerService

        try:
            ai_service = AIAnalyzerService(self.settings, self.db)
            result = await ai_service.analyze_alert(
                alert=alert,
                enrichment_data=alert.enrichment,
            )
            await ai_service.close()

            if result:
                # Store AI analysis in alert
                alert.ai_analysis = {
                    "summary": result.summary,
                    "description": result.description,
                    "severity_assessment": result.severity_assessment,
                    "confidence": result.confidence,
                    "recommended_actions": result.recommended_actions,
                    "immediate_actions": result.immediate_actions,
                    "investigation_steps": result.investigation_steps,
                    "provider": result.provider,
                    "model": result.model,
                }

                logger.info(
                    "AI analysis complete",
                    alert_id=alert.id,
                    provider=result.provider,
                    severity=result.severity_assessment,
                )
            else:
                logger.warning("No AI provider configured, skipping analysis")
                alert.ai_analysis = None

        except Exception as e:
            logger.warning(
                "AI analysis failed, continuing without",
                alert_id=alert.id,
                error=str(e),
            )
            alert.ai_analysis = None

        return alert

    async def _create_ticket(self, alert: Alert) -> Alert:
        """
        Create ticket in PSA.

        Creates a new ticket with alert details.
        """
        # TODO: Implement PSA integration in Phase 5
        # For now, return alert as-is
        logger.debug("PSA integration not yet implemented")
        return alert

    async def _post_to_chat(self, alert: Alert) -> Alert:
        """
        Post alert to chat platform.

        Sends formatted alert card with action buttons.
        """
        # TODO: Implement chat integration in Phase 5
        # For now, return alert as-is
        logger.debug("Chat integration not yet implemented")
        return alert

    async def _log_action(
        self,
        action_type: str,
        alert: Optional[Alert],
        result: str,
        details: Optional[dict] = None,
    ) -> None:
        """Log an action to the audit log."""
        try:
            audit_entry = AuditLog(
                action_type=action_type,
                alert_source=alert.source if alert else None,
                alert_id=alert.source_alert_id if alert else None,
                hostname=alert.hostname if alert else None,
                client_name=alert.client_name if alert else None,
                performed_by="system",
                result=result,
                details=json.dumps(details) if details else None,
            )
            self.db.add(audit_entry)
            await self.db.flush()
        except Exception as e:
            logger.error("Failed to log action", error=str(e))

    async def resolve_alert(
        self,
        source: str,
        alert_id: str,
        performed_by: str,
        comment: str = "",
    ) -> bool:
        """
        Resolve an alert in the EDR platform.

        Args:
            source: EDR source.
            alert_id: Alert ID in the EDR.
            performed_by: Who triggered the action.
            comment: Optional resolution comment.

        Returns:
            True if successful.
        """
        logger.info("Resolving alert", source=source, alert_id=alert_id)

        adapter = await self._get_edr_adapter(source)
        if not adapter:
            raise ValueError(f"No adapter available for {source}")

        try:
            success = await adapter.resolve_alert(alert_id, comment)

            await self._log_action(
                action_type="resolve",
                alert=None,
                result="success" if success else "failure",
                details={
                    "source": source,
                    "alert_id": alert_id,
                    "performed_by": performed_by,
                },
            )

            return success

        except Exception as e:
            await self._log_action(
                action_type="resolve",
                alert=None,
                result="failure",
                details={
                    "source": source,
                    "alert_id": alert_id,
                    "performed_by": performed_by,
                    "error": str(e),
                },
            )
            raise

    async def contain_endpoint(
        self,
        source: str,
        agent_id: str,
        performed_by: str,
        hostname: str = "",
        comment: str = "",
    ) -> bool:
        """
        Network contain an endpoint.

        Args:
            source: EDR source.
            agent_id: Agent/device ID in the EDR.
            performed_by: Who triggered the action.
            hostname: Hostname for logging.
            comment: Optional comment.

        Returns:
            True if successful.
        """
        logger.info("Containing endpoint", source=source, agent_id=agent_id)

        adapter = await self._get_edr_adapter(source)
        if not adapter:
            raise ValueError(f"No adapter available for {source}")

        try:
            success = await adapter.contain_endpoint(agent_id, comment)

            await self._log_action(
                action_type="contain",
                alert=None,
                result="success" if success else "failure",
                details={
                    "source": source,
                    "agent_id": agent_id,
                    "hostname": hostname,
                    "performed_by": performed_by,
                },
            )

            return success

        except Exception as e:
            await self._log_action(
                action_type="contain",
                alert=None,
                result="failure",
                details={
                    "source": source,
                    "agent_id": agent_id,
                    "hostname": hostname,
                    "performed_by": performed_by,
                    "error": str(e),
                },
            )
            raise

    async def close(self) -> None:
        """Clean up resources."""
        for adapter in self._adapters.values():
            if hasattr(adapter, "close"):
                await adapter.close()
        self._adapters.clear()


# Factory function for creating processor
async def create_alert_processor(
    settings: Settings,
    db_session: AsyncSession,
) -> AlertProcessor:
    """
    Create an alert processor instance.

    Args:
        settings: Application settings.
        db_session: Database session.

    Returns:
        Configured AlertProcessor.
    """
    return AlertProcessor(settings, db_session)
