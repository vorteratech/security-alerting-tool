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
from ..config.settings import Settings, get_settings
from ..database.connection import get_db_session
from ..database.models import AuditLog
from ..services import AlertProcessor, PSAService, NotificationService

logger = get_logger(__name__)

router = APIRouter()


class ActionRequest(BaseModel):
    """Request body for action endpoints."""

    alert_source: str  # sentinelone, crowdstrike
    alert_id: str  # Original alert ID from EDR
    hostname: str  # Affected endpoint
    agent_id: Optional[str] = None  # Agent/device ID (for containment)
    client_name: Optional[str] = None  # Client/site name
    performed_by: str  # Teams user who clicked button
    ticket_id: Optional[str] = None  # Associated PSA ticket
    channel_id: Optional[str] = None  # Teams channel for notifications


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
    settings: Settings = Depends(get_settings),
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

    processor = AlertProcessor(settings, db)

    try:
        # 1. Resolve in EDR
        success = await processor.resolve_alert(
            source=request.alert_source,
            alert_id=request.alert_id,
            performed_by=request.performed_by,
            comment=f"Resolved via Security Alerting Tool by {request.performed_by}",
        )

        if not success:
            raise Exception("EDR returned failure status")

        # 2. Update ticket if we have one
        if request.ticket_id:
            try:
                psa_service = PSAService(settings, db)
                await psa_service.add_note_to_ticket(
                    ticket_id=request.ticket_id,
                    content=(
                        f"Alert resolved in EDR\n\n"
                        f"Resolved by: {request.performed_by}\n"
                        f"Alert ID: {request.alert_id}\n"
                        f"Hostname: {request.hostname}"
                    ),
                    is_internal=False,
                    author=request.performed_by,
                )
                # Close the ticket
                await psa_service.close_ticket(
                    ticket_id=request.ticket_id,
                    resolution_note=f"Alert resolved by {request.performed_by}",
                )
                await psa_service.close()
            except Exception as e:
                logger.warning("Failed to update ticket", error=str(e))

        # 3. Send notification if we have channel
        if request.channel_id:
            try:
                notification = NotificationService(settings, db)
                await notification.send_text_message(
                    channel_id=request.channel_id,
                    text=(
                        f"**Alert Resolved**\n\n"
                        f"Alert on **{request.hostname}** has been resolved by {request.performed_by}"
                    ),
                )
                await notification.close()
            except Exception as e:
                logger.warning("Failed to send notification", error=str(e))

        # 4. Log the action
        audit_entry = await log_action(
            db,
            action_type="resolve",
            request=request,
            result="success",
            details={"ticket_id": request.ticket_id, "edr_success": success},
        )

        await db.commit()

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
        await db.commit()

        raise HTTPException(
            status_code=500,
            detail=f"Failed to resolve alert: {str(e)}",
        )
    finally:
        await processor.close()


@router.post("/contain", response_model=ActionResponse)
async def contain_machine(
    request: ActionRequest,
    settings: Settings = Depends(get_settings),
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

    processor = AlertProcessor(settings, db)

    try:
        # Use agent_id if provided, otherwise use alert_id as fallback
        agent_id = request.agent_id or request.alert_id

        # 1. Contain endpoint in EDR
        success = await processor.contain_endpoint(
            source=request.alert_source,
            agent_id=agent_id,
            performed_by=request.performed_by,
            hostname=request.hostname,
            comment=f"Contained via Security Alerting Tool by {request.performed_by}",
        )

        if not success:
            raise Exception("EDR returned failure status")

        # 2. Update ticket if we have one
        if request.ticket_id:
            try:
                psa_service = PSAService(settings, db)
                await psa_service.add_note_to_ticket(
                    ticket_id=request.ticket_id,
                    content=(
                        f"ENDPOINT CONTAINED\n\n"
                        f"Hostname: {request.hostname}\n"
                        f"Agent ID: {agent_id}\n"
                        f"Contained by: {request.performed_by}\n\n"
                        f"The endpoint has been network isolated. "
                        f"It can only communicate with the EDR cloud."
                    ),
                    is_internal=False,
                    author=request.performed_by,
                )
                await psa_service.close()
            except Exception as e:
                logger.warning("Failed to update ticket", error=str(e))

        # 3. Send notification if we have channel
        if request.channel_id:
            try:
                notification = NotificationService(settings, db)
                await notification.send_containment_notification(
                    alert=None,
                    contained_by=request.performed_by,
                    success=True,
                    channel_id=request.channel_id,
                    hostname=request.hostname,
                )
                await notification.close()
            except Exception as e:
                logger.warning("Failed to send notification", error=str(e))

        # 4. Log the action
        audit_entry = await log_action(
            db,
            action_type="contain",
            request=request,
            result="success",
            details={
                "ticket_id": request.ticket_id,
                "containment_type": "network_isolation",
                "agent_id": agent_id,
                "edr_success": success,
            },
        )

        await db.commit()

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
        await db.commit()

        # Send failure notification
        if request.channel_id:
            try:
                notification = NotificationService(settings, db)
                await notification.send_containment_notification(
                    alert=None,
                    contained_by=request.performed_by,
                    success=False,
                    channel_id=request.channel_id,
                    hostname=request.hostname,
                )
                await notification.close()
            except Exception:
                pass

        raise HTTPException(
            status_code=500,
            detail=f"Failed to contain endpoint: {str(e)}",
        )
    finally:
        await processor.close()


@router.post("/escalate", response_model=ActionResponse)
async def escalate_alert(
    request: ActionRequest,
    settings: Settings = Depends(get_settings),
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
        # 1. Update ticket priority and add escalation note
        if request.ticket_id:
            try:
                from ..adapters.psa.base import TicketPriority

                psa_service = PSAService(settings, db)
                # Update ticket to critical priority
                await psa_service.update_ticket(
                    ticket_id=request.ticket_id,
                    priority=TicketPriority.CRITICAL,
                )
                # Add escalation note
                await psa_service.add_note_to_ticket(
                    ticket_id=request.ticket_id,
                    content=(
                        f"ALERT ESCALATED\n\n"
                        f"Escalated by: {request.performed_by}\n"
                        f"Alert: {request.alert_id}\n"
                        f"Hostname: {request.hostname}\n\n"
                        f"This alert requires immediate attention from a senior engineer."
                    ),
                    is_internal=False,
                    author=request.performed_by,
                )
                await psa_service.close()
            except Exception as e:
                logger.warning("Failed to update ticket", error=str(e))

        # 2. Send escalation notification
        if request.channel_id:
            try:
                notification = NotificationService(settings, db)
                await notification.send_text_message(
                    channel_id=request.channel_id,
                    text=(
                        f"**ESCALATION - Immediate Attention Required**\n\n"
                        f"Alert on **{request.hostname}** has been escalated by {request.performed_by}\n\n"
                        f"**Source:** {request.alert_source.upper()}\n"
                        f"**Alert ID:** {request.alert_id}\n"
                        f"**Client:** {request.client_name or 'N/A'}\n\n"
                        f"*A senior engineer should review this alert immediately.*"
                    ),
                )
                await notification.close()
            except Exception as e:
                logger.warning("Failed to send notification", error=str(e))

        # 3. Log the action
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

        await db.commit()

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
        await db.commit()

        raise HTTPException(
            status_code=500,
            detail=f"Failed to escalate alert: {str(e)}",
        )


@router.post("/uncontain", response_model=ActionResponse)
async def uncontain_machine(
    request: ActionRequest,
    settings: Settings = Depends(get_settings),
    db: AsyncSession = Depends(get_db_session),
) -> ActionResponse:
    """
    Remove network containment from an endpoint.

    This lifts the network isolation, restoring normal network connectivity.
    """
    logger.info(
        "Uncontain action requested",
        alert_source=request.alert_source,
        alert_id=request.alert_id,
        hostname=request.hostname,
        performed_by=request.performed_by,
    )

    processor = AlertProcessor(settings, db)

    try:
        agent_id = request.agent_id or request.alert_id

        # 1. Uncontain endpoint in EDR
        adapter = await processor._get_edr_adapter(request.alert_source)
        if not adapter:
            raise ValueError(f"No adapter available for {request.alert_source}")

        success = await adapter.uncontain_endpoint(
            agent_id=agent_id,
            comment=f"Uncontained via Security Alerting Tool by {request.performed_by}",
        )

        if not success:
            raise Exception("EDR returned failure status")

        # 2. Update ticket if we have one
        if request.ticket_id:
            try:
                psa_service = PSAService(settings, db)
                await psa_service.add_note_to_ticket(
                    ticket_id=request.ticket_id,
                    content=(
                        f"CONTAINMENT LIFTED\n\n"
                        f"Hostname: {request.hostname}\n"
                        f"Agent ID: {agent_id}\n"
                        f"Released by: {request.performed_by}\n\n"
                        f"Network isolation has been removed. "
                        f"The endpoint now has normal network connectivity."
                    ),
                    is_internal=False,
                    author=request.performed_by,
                )
                await psa_service.close()
            except Exception as e:
                logger.warning("Failed to update ticket", error=str(e))

        # 3. Send notification
        if request.channel_id:
            try:
                notification = NotificationService(settings, db)
                await notification.send_text_message(
                    channel_id=request.channel_id,
                    text=(
                        f"**Containment Lifted**\n\n"
                        f"Endpoint **{request.hostname}** has been released from network isolation by {request.performed_by}"
                    ),
                )
                await notification.close()
            except Exception as e:
                logger.warning("Failed to send notification", error=str(e))

        # 4. Log the action
        audit_entry = await log_action(
            db,
            action_type="uncontain",
            request=request,
            result="success",
            details={
                "ticket_id": request.ticket_id,
                "agent_id": agent_id,
                "edr_success": success,
            },
        )

        await db.commit()

        return ActionResponse(
            status="success",
            message=f"Endpoint {request.hostname} released from containment",
            action_type="uncontain",
            audit_id=audit_entry.id,
        )

    except Exception as e:
        logger.error(
            "Failed to uncontain endpoint",
            hostname=request.hostname,
            error=str(e),
            exc_info=e,
        )

        await log_action(
            db,
            action_type="uncontain",
            request=request,
            result="failure",
            details={"error": str(e)},
        )
        await db.commit()

        raise HTTPException(
            status_code=500,
            detail=f"Failed to uncontain endpoint: {str(e)}",
        )
    finally:
        await processor.close()
