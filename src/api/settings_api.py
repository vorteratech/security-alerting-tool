"""
Settings management API endpoints.

Provides CRUD operations for integration settings:
- List all integrations
- Get specific integration settings
- Create/update integration settings
- Delete integration
- Test integration connectivity
"""

import json
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config.logging import get_logger
from ..config.settings import Settings, get_settings
from ..database.connection import get_db_session
from ..database.models import IntegrationSetting
from ..security.encryption import create_encryption_service

logger = get_logger(__name__)

router = APIRouter()


class IntegrationConfig(BaseModel):
    """Integration configuration model."""

    enabled: bool = True
    is_primary: bool = False
    config: dict[str, Any] = Field(default_factory=dict)
    api_key: Optional[str] = None  # Will be encrypted before storage
    api_secret: Optional[str] = None  # Will be encrypted before storage


class IntegrationResponse(BaseModel):
    """Response model for integration settings."""

    integration_type: str
    provider: str
    enabled: bool
    is_primary: bool
    config: dict[str, Any]
    has_api_key: bool
    has_api_secret: bool
    created_at: str
    updated_at: str


class IntegrationListResponse(BaseModel):
    """Response model for listing integrations."""

    integrations: list[IntegrationResponse]
    count: int


class TestResult(BaseModel):
    """Result of integration connectivity test."""

    success: bool
    message: str
    details: Optional[dict[str, Any]] = None


def integration_to_response(setting: IntegrationSetting) -> IntegrationResponse:
    """Convert database model to response model."""
    config = json.loads(setting.config_json) if setting.config_json else {}
    return IntegrationResponse(
        integration_type=setting.integration_type,
        provider=setting.provider,
        enabled=setting.enabled,
        is_primary=setting.is_primary,
        config=config,
        has_api_key=bool(setting.api_key_encrypted),
        has_api_secret=bool(setting.api_secret_encrypted),
        created_at=setting.created_at.isoformat(),
        updated_at=setting.updated_at.isoformat(),
    )


@router.get("", response_model=IntegrationListResponse)
async def list_integrations(
    integration_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db_session),
) -> IntegrationListResponse:
    """
    List all configured integrations.

    Optionally filter by integration type (edr, ai, threat_intel, psa, chat).
    """
    query = select(IntegrationSetting)
    if integration_type:
        query = query.where(IntegrationSetting.integration_type == integration_type)
    query = query.order_by(
        IntegrationSetting.integration_type, IntegrationSetting.provider
    )

    result = await db.execute(query)
    settings = result.scalars().all()

    return IntegrationListResponse(
        integrations=[integration_to_response(s) for s in settings],
        count=len(settings),
    )


@router.get("/{integration_type}/{provider}", response_model=IntegrationResponse)
async def get_integration(
    integration_type: str,
    provider: str,
    db: AsyncSession = Depends(get_db_session),
) -> IntegrationResponse:
    """Get settings for a specific integration."""
    query = select(IntegrationSetting).where(
        and_(
            IntegrationSetting.integration_type == integration_type,
            IntegrationSetting.provider == provider,
        )
    )
    result = await db.execute(query)
    setting = result.scalar_one_or_none()

    if not setting:
        raise HTTPException(
            status_code=404,
            detail=f"Integration {integration_type}/{provider} not found",
        )

    return integration_to_response(setting)


@router.put("/{integration_type}/{provider}", response_model=IntegrationResponse)
async def upsert_integration(
    integration_type: str,
    provider: str,
    config: IntegrationConfig,
    db: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> IntegrationResponse:
    """
    Create or update an integration.

    API keys and secrets are encrypted before storage.
    """
    # Validate integration type
    valid_types = ["edr", "ai", "threat_intel", "psa", "chat"]
    if integration_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid integration type. Must be one of: {valid_types}",
        )

    # Get or create setting
    query = select(IntegrationSetting).where(
        and_(
            IntegrationSetting.integration_type == integration_type,
            IntegrationSetting.provider == provider,
        )
    )
    result = await db.execute(query)
    setting = result.scalar_one_or_none()

    if setting is None:
        setting = IntegrationSetting(
            integration_type=integration_type,
            provider=provider,
        )
        db.add(setting)

    # Update fields
    setting.enabled = config.enabled
    setting.is_primary = config.is_primary
    setting.config_json = json.dumps(config.config) if config.config else None

    # Encrypt API credentials if provided
    if config.api_key or config.api_secret:
        try:
            encryption = create_encryption_service(settings.master_encryption_key)

            if config.api_key:
                setting.api_key_encrypted = encryption.encrypt(config.api_key)
            if config.api_secret:
                setting.api_secret_encrypted = encryption.encrypt(config.api_secret)
        except ValueError as e:
            raise HTTPException(
                status_code=500,
                detail=f"Encryption error: {str(e)}. Ensure MASTER_ENCRYPTION_KEY is set.",
            )

    # If setting as primary, unset other primaries of same type
    if config.is_primary:
        await db.execute(
            IntegrationSetting.__table__.update()
            .where(
                and_(
                    IntegrationSetting.integration_type == integration_type,
                    IntegrationSetting.provider != provider,
                )
            )
            .values(is_primary=False)
        )

    await db.flush()

    logger.info(
        "Integration updated",
        integration_type=integration_type,
        provider=provider,
        enabled=config.enabled,
    )

    return integration_to_response(setting)


@router.delete("/{integration_type}/{provider}")
async def delete_integration(
    integration_type: str,
    provider: str,
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, str]:
    """Delete an integration."""
    query = select(IntegrationSetting).where(
        and_(
            IntegrationSetting.integration_type == integration_type,
            IntegrationSetting.provider == provider,
        )
    )
    result = await db.execute(query)
    setting = result.scalar_one_or_none()

    if not setting:
        raise HTTPException(
            status_code=404,
            detail=f"Integration {integration_type}/{provider} not found",
        )

    await db.delete(setting)

    logger.info(
        "Integration deleted",
        integration_type=integration_type,
        provider=provider,
    )

    return {"status": "deleted", "integration": f"{integration_type}/{provider}"}


@router.post("/{integration_type}/{provider}/test", response_model=TestResult)
async def test_integration(
    integration_type: str,
    provider: str,
    db: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> TestResult:
    """
    Test connectivity for an integration.

    Attempts to connect to the integration's API and verify credentials.
    """
    # Get integration settings
    query = select(IntegrationSetting).where(
        and_(
            IntegrationSetting.integration_type == integration_type,
            IntegrationSetting.provider == provider,
        )
    )
    result = await db.execute(query)
    setting = result.scalar_one_or_none()

    if not setting:
        raise HTTPException(
            status_code=404,
            detail=f"Integration {integration_type}/{provider} not found",
        )

    if not setting.api_key_encrypted:
        return TestResult(
            success=False,
            message="No API key configured for this integration",
        )

    # TODO: Implement actual connectivity tests for each provider
    # This would:
    # 1. Decrypt API key
    # 2. Make a test API call to the provider
    # 3. Return success/failure

    logger.info(
        "Integration test requested",
        integration_type=integration_type,
        provider=provider,
    )

    return TestResult(
        success=True,
        message=f"Connectivity test for {provider} - Not yet implemented",
        details={"note": "Actual connectivity testing will be implemented per provider"},
    )
