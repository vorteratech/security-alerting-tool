"""
Threat Intelligence Enrichment Service.

Orchestrates IOC lookups across multiple threat intel providers
and aggregates results.
"""

import asyncio
import json
from typing import Any, Optional

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..adapters.edr.base import Alert
from ..adapters.threat_intel.base import (
    BaseThreatIntelAdapter,
    EnrichmentResult,
    ThreatIntelResult,
)
from ..adapters.threat_intel.virustotal import VirusTotalAdapter
from ..adapters.threat_intel.alienvault import AlienVaultAdapter
from ..config.logging import get_logger
from ..config.settings import Settings
from ..database.models import IntegrationSetting
from ..security.encryption import create_encryption_service

logger = get_logger(__name__)


class EnrichmentService:
    """
    Service for enriching alerts with threat intelligence.

    Queries configured threat intel providers for IOCs found in alerts.
    """

    # Map provider names to adapter classes
    ADAPTERS = {
        "virustotal": VirusTotalAdapter,
        "alienvault": AlienVaultAdapter,
    }

    def __init__(self, settings: Settings, db_session: AsyncSession):
        """
        Initialize the enrichment service.

        Args:
            settings: Application settings.
            db_session: Database session.
        """
        self.settings = settings
        self.db = db_session
        self._adapters: dict[str, BaseThreatIntelAdapter] = {}
        self._encryption = None

    async def _get_encryption(self):
        """Get encryption service."""
        if self._encryption is None:
            self._encryption = create_encryption_service(
                self.settings.master_encryption_key
            )
        return self._encryption

    async def _load_adapters(self) -> None:
        """Load enabled threat intel adapters from database."""
        if self._adapters:
            return  # Already loaded

        query = select(IntegrationSetting).where(
            and_(
                IntegrationSetting.integration_type == "threat_intel",
                IntegrationSetting.enabled == True,
            )
        )
        result = await self.db.execute(query)
        settings = result.scalars().all()

        encryption = await self._get_encryption()

        for setting in settings:
            provider = setting.provider
            if provider not in self.ADAPTERS:
                logger.warning(f"Unknown threat intel provider: {provider}")
                continue

            try:
                # Decrypt API key
                api_key = ""
                if setting.api_key_encrypted:
                    api_key = encryption.decrypt(setting.api_key_encrypted)

                if not api_key:
                    logger.warning(f"No API key for {provider}, skipping")
                    continue

                # Get additional config
                config = json.loads(setting.config_json) if setting.config_json else {}

                # Create adapter
                adapter_class = self.ADAPTERS[provider]
                self._adapters[provider] = adapter_class(api_key=api_key, **config)

                logger.info(f"Loaded threat intel adapter: {provider}")

            except Exception as e:
                logger.error(f"Failed to load {provider} adapter", error=str(e))

    async def enrich_alert(self, alert: Alert) -> EnrichmentResult:
        """
        Enrich an alert with threat intelligence.

        Looks up all IOCs from the alert in configured providers.

        Args:
            alert: The alert to enrich.

        Returns:
            EnrichmentResult with aggregated data.
        """
        await self._load_adapters()

        if not self._adapters:
            logger.warning("No threat intel adapters configured")
            return EnrichmentResult()

        enrichment = EnrichmentResult()
        iocs = alert.get_iocs()

        # Collect all lookup tasks
        tasks = []

        # Hash lookups
        for hash_value in iocs.get("hashes", []):
            if hash_value:
                for provider, adapter in self._adapters.items():
                    tasks.append(
                        self._lookup_with_timeout(
                            adapter.lookup_hash(hash_value),
                            provider,
                            "hash",
                            hash_value,
                        )
                    )

        # IP lookups
        for ip in iocs.get("ips", []):
            if ip and not self._is_private_ip(ip):
                for provider, adapter in self._adapters.items():
                    tasks.append(
                        self._lookup_with_timeout(
                            adapter.lookup_ip(ip),
                            provider,
                            "ip",
                            ip,
                        )
                    )

        # Domain lookups
        for domain in iocs.get("domains", []):
            if domain:
                for provider, adapter in self._adapters.items():
                    tasks.append(
                        self._lookup_with_timeout(
                            adapter.lookup_domain(domain),
                            provider,
                            "domain",
                            domain,
                        )
                    )

        if not tasks:
            logger.debug("No IOCs to enrich")
            return enrichment

        # Execute all lookups concurrently
        logger.info(f"Enriching alert with {len(tasks)} lookups")
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for result in results:
            if isinstance(result, Exception):
                logger.warning(f"Enrichment lookup failed: {result}")
                continue
            if isinstance(result, ThreatIntelResult):
                enrichment.add_result(result)

        logger.info(
            "Enrichment complete",
            results_count=len(enrichment.results),
            is_malicious=enrichment.is_malicious,
            severity=enrichment.highest_severity,
        )

        return enrichment

    async def _lookup_with_timeout(
        self,
        coro,
        provider: str,
        ioc_type: str,
        ioc_value: str,
        timeout: float = 15.0,
    ) -> ThreatIntelResult:
        """
        Execute a lookup with timeout.

        Args:
            coro: The lookup coroutine.
            provider: Provider name for error handling.
            ioc_type: IOC type for error handling.
            ioc_value: IOC value for error handling.
            timeout: Timeout in seconds.

        Returns:
            ThreatIntelResult.
        """
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(f"{provider} lookup timed out for {ioc_type}: {ioc_value}")
            return ThreatIntelResult(
                provider=provider,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                success=False,
                error="Lookup timed out",
            )
        except Exception as e:
            logger.error(f"{provider} lookup failed for {ioc_type}: {ioc_value}", error=str(e))
            return ThreatIntelResult(
                provider=provider,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                success=False,
                error=str(e),
            )

    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is private/internal."""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False

    async def lookup_hash(self, hash_value: str) -> EnrichmentResult:
        """
        Look up a single hash across all providers.

        Args:
            hash_value: Hash to look up.

        Returns:
            EnrichmentResult with all provider results.
        """
        await self._load_adapters()

        enrichment = EnrichmentResult()
        tasks = [
            self._lookup_with_timeout(
                adapter.lookup_hash(hash_value),
                provider,
                "hash",
                hash_value,
            )
            for provider, adapter in self._adapters.items()
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, ThreatIntelResult):
                enrichment.add_result(result)

        return enrichment

    async def lookup_ip(self, ip_address: str) -> EnrichmentResult:
        """
        Look up a single IP across all providers.

        Args:
            ip_address: IP to look up.

        Returns:
            EnrichmentResult with all provider results.
        """
        await self._load_adapters()

        enrichment = EnrichmentResult()
        tasks = [
            self._lookup_with_timeout(
                adapter.lookup_ip(ip_address),
                provider,
                "ip",
                ip_address,
            )
            for provider, adapter in self._adapters.items()
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, ThreatIntelResult):
                enrichment.add_result(result)

        return enrichment

    async def lookup_domain(self, domain: str) -> EnrichmentResult:
        """
        Look up a single domain across all providers.

        Args:
            domain: Domain to look up.

        Returns:
            EnrichmentResult with all provider results.
        """
        await self._load_adapters()

        enrichment = EnrichmentResult()
        tasks = [
            self._lookup_with_timeout(
                adapter.lookup_domain(domain),
                provider,
                "domain",
                domain,
            )
            for provider, adapter in self._adapters.items()
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, ThreatIntelResult):
                enrichment.add_result(result)

        return enrichment

    async def close(self) -> None:
        """Clean up adapters."""
        for adapter in self._adapters.values():
            await adapter.close()
        self._adapters.clear()
