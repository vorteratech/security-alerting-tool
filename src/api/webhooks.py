"""
Webhook endpoints for receiving alerts from EDR platforms.

Handles incoming webhooks from:
- SentinelOne
- CrowdStrike Falcon
"""

import hashlib
import hmac
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ..config.logging import get_logger
from ..config.settings import Settings, get_settings
from ..database.connection import get_db_session
from ..services.alert_processor import AlertProcessor

logger = get_logger(__name__)

router = APIRouter()


class WebhookResponse(BaseModel):
    """Standard webhook response."""

    status: str
    message: str
    alert_id: Optional[str] = None


def verify_webhook_signature(
    payload: bytes,
    signature: str,
    secret: str,
    algorithm: str = "sha256",
) -> bool:
    """
    Verify webhook signature using HMAC.

    Args:
        payload: Raw request body.
        signature: Signature from header.
        secret: Webhook secret.
        algorithm: Hash algorithm (sha256 or sha1).

    Returns:
        True if signature is valid.
    """
    if algorithm == "sha256":
        expected = hmac.new(
            secret.encode(), payload, hashlib.sha256
        ).hexdigest()
    else:
        expected = hmac.new(
            secret.encode(), payload, hashlib.sha1
        ).hexdigest()

    # Handle signatures with algorithm prefix (e.g., "sha256=...")
    if "=" in signature:
        signature = signature.split("=", 1)[1]

    return hmac.compare_digest(expected, signature)


async def process_alert_background(
    source: str,
    payload: dict[str, Any],
    settings: Settings,
    db: AsyncSession,
) -> None:
    """
    Process alert in background task.

    This allows the webhook to return immediately while processing continues.
    """
    try:
        processor = AlertProcessor(settings, db)
        await processor.process_webhook(source, payload)
        await processor.close()
    except Exception as e:
        logger.error(
            "Background alert processing failed",
            source=source,
            error=str(e),
            exc_info=e,
        )


@router.post("/sentinelone", response_model=WebhookResponse)
async def sentinelone_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_webhook_signature: Optional[str] = Header(None, alias="X-Signature"),
    settings: Settings = Depends(get_settings),
    db: AsyncSession = Depends(get_db_session),
) -> WebhookResponse:
    """
    Receive alerts from SentinelOne.

    SentinelOne sends detection events via webhook when configured
    in the S1 console under Settings > Integrations > Webhooks.
    """
    # Get raw body for signature verification
    body = await request.body()

    # Verify signature if enabled and secret is configured
    if settings.security.verify_webhooks and settings.s1_webhook_secret:
        if not x_webhook_signature:
            logger.warning("SentinelOne webhook missing signature header")
            raise HTTPException(status_code=401, detail="Missing signature")

        if not verify_webhook_signature(
            body, x_webhook_signature, settings.s1_webhook_secret
        ):
            logger.warning("SentinelOne webhook signature verification failed")
            raise HTTPException(status_code=401, detail="Invalid signature")

    # Parse JSON payload
    try:
        payload: dict[str, Any] = await request.json()
    except Exception as e:
        logger.error("Failed to parse SentinelOne webhook payload", error=str(e))
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    alert_id = payload.get("data", {}).get("id", "unknown")

    logger.info(
        "Received SentinelOne webhook",
        event_type=payload.get("eventType"),
        alert_id=alert_id,
    )

    # Process alert - currently synchronous, can be made async with background_tasks
    try:
        processor = AlertProcessor(settings, db)
        alert = await processor.process_webhook("sentinelone", payload)
        await processor.close()

        return WebhookResponse(
            status="processed",
            message="SentinelOne alert processed successfully",
            alert_id=alert.source_alert_id if alert else alert_id,
        )
    except Exception as e:
        logger.error("Failed to process SentinelOne alert", error=str(e))
        # Return success to EDR so it doesn't retry, but log the error
        return WebhookResponse(
            status="received",
            message="Alert received but processing failed",
            alert_id=alert_id,
        )


@router.post("/crowdstrike", response_model=WebhookResponse)
async def crowdstrike_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_cs_signature: Optional[str] = Header(None, alias="X-CS-Signature"),
    settings: Settings = Depends(get_settings),
    db: AsyncSession = Depends(get_db_session),
) -> WebhookResponse:
    """
    Receive alerts from CrowdStrike Falcon.

    CrowdStrike sends detection events via webhook when configured
    in the Falcon console under Support > API Clients and Keys > Webhooks.
    """
    # Get raw body for signature verification
    body = await request.body()

    # Verify signature if enabled and secret is configured
    if settings.security.verify_webhooks and settings.cs_webhook_secret:
        if not x_cs_signature:
            logger.warning("CrowdStrike webhook missing signature header")
            raise HTTPException(status_code=401, detail="Missing signature")

        if not verify_webhook_signature(
            body, x_cs_signature, settings.cs_webhook_secret
        ):
            logger.warning("CrowdStrike webhook signature verification failed")
            raise HTTPException(status_code=401, detail="Invalid signature")

    # Parse JSON payload
    try:
        payload: dict[str, Any] = await request.json()
    except Exception as e:
        logger.error("Failed to parse CrowdStrike webhook payload", error=str(e))
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    alert_id = payload.get("body", {}).get("detection_id", "unknown")

    logger.info(
        "Received CrowdStrike webhook",
        event_type=payload.get("metadata", {}).get("eventType"),
        detection_id=alert_id,
    )

    # Process alert
    try:
        processor = AlertProcessor(settings, db)
        alert = await processor.process_webhook("crowdstrike", payload)
        await processor.close()

        return WebhookResponse(
            status="processed",
            message="CrowdStrike alert processed successfully",
            alert_id=alert.source_alert_id if alert else alert_id,
        )
    except Exception as e:
        logger.error("Failed to process CrowdStrike alert", error=str(e))
        # Return success to EDR so it doesn't retry, but log the error
        return WebhookResponse(
            status="received",
            message="Alert received but processing failed",
            alert_id=alert_id,
        )
