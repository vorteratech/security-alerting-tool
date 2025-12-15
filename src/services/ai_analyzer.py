"""
AI Analysis Service.

Orchestrates security alert analysis using configured AI providers.
"""

import json
from typing import Any, Optional

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..adapters.edr.base import Alert
from ..adapters.ai.base import BaseAIAdapter, AIAnalysisResult
from ..adapters.ai.claude import ClaudeAdapter
from ..adapters.ai.openai_adapter import OpenAIAdapter
from ..adapters.ai.gemini import GeminiAdapter
from ..config.logging import get_logger
from ..config.settings import Settings
from ..database.models import IntegrationSetting
from ..security.encryption import create_encryption_service

logger = get_logger(__name__)


class AIAnalyzerService:
    """
    Service for analyzing alerts with AI.

    Selects and uses the configured AI provider for analysis.
    """

    # Map provider names to adapter classes
    ADAPTERS = {
        "claude": ClaudeAdapter,
        "openai": OpenAIAdapter,
        "gemini": GeminiAdapter,
    }

    def __init__(self, settings: Settings, db_session: AsyncSession):
        """
        Initialize the AI analyzer service.

        Args:
            settings: Application settings.
            db_session: Database session.
        """
        self.settings = settings
        self.db = db_session
        self._adapter: Optional[BaseAIAdapter] = None
        self._encryption = None

    async def _get_encryption(self):
        """Get encryption service."""
        if self._encryption is None:
            self._encryption = create_encryption_service(
                self.settings.master_encryption_key
            )
        return self._encryption

    async def _load_adapter(self) -> Optional[BaseAIAdapter]:
        """Load the configured AI adapter."""
        if self._adapter is not None:
            return self._adapter

        # First try to get the primary AI provider
        query = select(IntegrationSetting).where(
            and_(
                IntegrationSetting.integration_type == "ai",
                IntegrationSetting.enabled == True,
                IntegrationSetting.is_primary == True,
            )
        )
        result = await self.db.execute(query)
        setting = result.scalar_one_or_none()

        # If no primary, get any enabled AI provider
        if not setting:
            query = select(IntegrationSetting).where(
                and_(
                    IntegrationSetting.integration_type == "ai",
                    IntegrationSetting.enabled == True,
                )
            )
            result = await self.db.execute(query)
            setting = result.scalar_one_or_none()

        if not setting:
            logger.warning("No AI provider configured")
            return None

        provider = setting.provider
        if provider not in self.ADAPTERS:
            logger.warning(f"Unknown AI provider: {provider}")
            return None

        try:
            encryption = await self._get_encryption()

            # Decrypt API key
            api_key = ""
            if setting.api_key_encrypted:
                api_key = encryption.decrypt(setting.api_key_encrypted)

            if not api_key:
                logger.warning(f"No API key for {provider}")
                return None

            # Get config
            config = json.loads(setting.config_json) if setting.config_json else {}
            model = config.get("model", "")

            # Create adapter
            adapter_class = self.ADAPTERS[provider]
            self._adapter = adapter_class(api_key=api_key, model=model, **config)

            logger.info(f"Loaded AI adapter: {provider}", model=model or "default")
            return self._adapter

        except Exception as e:
            logger.error(f"Failed to load {provider} adapter", error=str(e))
            return None

    async def analyze_alert(
        self,
        alert: Alert,
        enrichment_data: Optional[dict[str, Any]] = None,
    ) -> Optional[AIAnalysisResult]:
        """
        Analyze an alert using the configured AI provider.

        Args:
            alert: The alert to analyze.
            enrichment_data: Optional threat intel enrichment data.

        Returns:
            AIAnalysisResult with analysis, or None if no provider configured.
        """
        adapter = await self._load_adapter()
        if not adapter:
            return None

        try:
            result = await adapter.analyze_alert(
                alert=alert,
                enrichment_data=enrichment_data,
            )

            logger.info(
                "AI analysis complete",
                alert_id=alert.id,
                provider=result.provider,
                severity=result.severity_assessment,
            )

            return result

        except Exception as e:
            logger.error(
                "AI analysis failed",
                alert_id=alert.id,
                error=str(e),
            )
            return None

    async def close(self) -> None:
        """Clean up adapter."""
        if self._adapter:
            await self._adapter.close()
            self._adapter = None
