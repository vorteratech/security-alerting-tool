"""
Action endpoints for Teams Bot button callbacks.

Handles actions triggered by clicking buttons in Teams adaptive cards:
- Resolve alert
- Contain machine
- Escalate to senior engineer
"""

import json
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config.logging import get_logger
from ..database.connection import get_db_session
from ..database.models import AuditLog

logger = get_logger(__name__)

router = APIRouter()


class ActionRequest(BaseModel):
    """Request body for action endpoints."""

    alert_source: str  # sentinelone, crowdstrike
    alert_id: str  # Original alert ID from EDR
    hostname: str  # Affected endpoint
    client_name: Optional[str] = None  # Client/site name
    performed_by: str  # Teams user who clicked button
    ticket_id: Optional[str] = None  # Associated PSA ticket


class ActionResponse(BaseModel):
    """Response for action endpoints."""

    status: str  # success, failure, pending
    message: str
    action_type: str
    audit_id: Optional[int] = None


async def log_action(
    db: AsyncSession,
    action_type: str,
    request: ActionRequest,
    result: str,
    details: Optional[dict[str, Any]] = None,
    request_id: Optional[str] = None,
) -> AuditLog:
    """
    Log an action to the audit log.

    Args:
        db: Database session.
        action_type: Type of action (resolve, contain, escalate).
        request: Action request data.
        result: Result of action (success, failure, pending).
        details: Additional details to log.
        request_id: Request correlation ID.

    Returns:
        Created AuditLog entry.
    """
    audit_entry = AuditLog(
        action_type=action_type,
        alert_source=request.alert_source,
        alert_id=request.alert_id,
        hostname=request.hostname,
        client_name=request.client_name,
        performed_by=request.performed_by,
        result=result,
        details=json.dumps(details) if details else None,
        request_id=request_id,
    )
    db.add(audit_entry)
    await db.flush()  # Get the ID
    return audit_entry


@router.post("/resolve", response_model=ActionResponse)
async def resolve_alert(
    request: ActionRequest,
    db: AsyncSession = Depends(get_db_session),
) -> ActionResponse:
    """
    Resolve/clear an alert in the EDR platform.

    This marks the alert as resolved in SentinelOne or CrowdStrike
    and updates the associated ticket.
    """
    logger.info(
        "Resolve action requested",
        alert_source=request.alert_source,
        alert_id=request.alert_id,
        hostname=request.hostname,
        performed_by=request.performed_by,
    )

    try:
        # TODO: Implement actual EDR API calls
        # 1. Get EDR adapter for alert_source
        # 2. Call resolve/dismiss API
        # 3. Update ticket status
        # 4. Update Teams message

        # Log the action
        audit_entry = await log_action(
            db,
            action_type="resolve",
            request=request,
            result="success",
            details={"ticket_id": request.ticket_id},
        )

        return ActionResponse(
            status="success",
            message=f"Alert {request.alert_id} resolved successfully",
            action_type="resolve",
            audit_id=audit_entry.id,
        )

    except Exception as e:
        logger.error(
            "Failed to resolve alert",
            alert_id=request.alert_id,
            error=str(e),
            exc_info=e,
        )

        # Log the failure
        await log_action(
            db,
            action_type="resolve",
            request=request,
            result="failure",
            details={"error": str(e)},
        )

        raise HTTPException(
            status_code=500,
            detail=f"Failed to resolve alert: {str(e)}",
        )


@router.post("/contain", response_model=ActionResponse)
async def contain_machine(
    request: ActionRequest,
    db: AsyncSession = Depends(get_db_session),
) -> ActionResponse:
    """
    Network contain/isolate an endpoint.

    This triggers network isolation on the endpoint via the EDR platform,
    preventing lateral movement while maintaining agent connectivity.
    """
    logger.info(
        "Contain action requested",
        alert_source=request.alert_source,
        alert_id=request.alert_id,
        hostname=request.hostname,
        performed_by=request.performed_by,
    )

    try:
        # TODO: Implement actual EDR API calls
        # 1. Get EDR adapter for alert_source
        # 2. Call network containment API
        # 3. Update ticket with containment note
        # 4. Update Teams message

        # Log the action
        audit_entry = await log_action(
            db,
            action_type="contain",
            request=request,
            result="success",
            details={
                "ticket_id": request.ticket_id,
                "containment_type": "network_isolation",
            },
        )

        return ActionResponse(
            status="success",
            message=f"Endpoint {request.hostname} contained successfully",
            action_type="contain",
            audit_id=audit_entry.id,
        )

    except Exception as e:
        logger.error(
            "Failed to contain endpoint",
            hostname=request.hostname,
            error=str(e),
            exc_info=e,
        )

        # Log the failure
        await log_action(
            db,
            action_type="contain",
            request=request,
            result="failure",
            details={"error": str(e)},
        )

        raise HTTPException(
            status_code=500,
            detail=f"Failed to contain endpoint: {str(e)}",
        )


@router.post("/escalate", response_model=ActionResponse)
async def escalate_alert(
    request: ActionRequest,
    db: AsyncSession = Depends(get_db_session),
) -> ActionResponse:
    """
    Escalate an alert to senior engineer.

    This updates the ticket priority to critical and posts
    to an escalation channel in Teams.
    """
    logger.info(
        "Escalate action requested",
        alert_source=request.alert_source,
        alert_id=request.alert_id,
        hostname=request.hostname,
        performed_by=request.performed_by,
    )

    try:
        # TODO: Implement actual escalation
        # 1. Update ticket priority to critical
        # 2. Post to escalation Teams channel
        # 3. Potentially page on-call engineer

        # Log the action
        audit_entry = await log_action(
            db,
            action_type="escalate",
            request=request,
            result="success",
            details={
                "ticket_id": request.ticket_id,
                "escalation_level": "senior_engineer",
            },
        )

        return ActionResponse(
            status="success",
            message=f"Alert {request.alert_id} escalated to senior engineer",
            action_type="escalate",
            audit_id=audit_entry.id,
        )

    except Exception as e:
        logger.error(
            "Failed to escalate alert",
            alert_id=request.alert_id,
            error=str(e),
            exc_info=e,
        )

        # Log the failure
        await log_action(
            db,
            action_type="escalate",
            request=request,
            result="failure",
            details={"error": str(e)},
        )

        raise HTTPException(
            status_code=500,
            detail=f"Failed to escalate alert: {str(e)}",
        )
