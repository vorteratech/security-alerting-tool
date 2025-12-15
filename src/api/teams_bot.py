"""
Microsoft Teams Bot webhook endpoint.

Handles incoming Bot Framework activities, particularly action button callbacks
from Adaptive Cards.
"""

import hmac
import hashlib
import json
from typing import Any

from fastapi import APIRouter, Request, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ..config.logging import get_logger
from ..config.settings import Settings, get_settings
from ..database.connection import get_db_session
from ..services import AlertProcessor, NotificationService, PSAService

logger = get_logger(__name__)

router = APIRouter(prefix="/bot", tags=["teams-bot"])


async def verify_bot_framework_request(request: Request) -> bool:
    """
    Verify the request is from Microsoft Bot Framework.

    In production, this should validate the JWT token from Azure AD.
    For now, we do basic validation.
    """
    # Check for required headers
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        logger.warning("Missing or invalid Authorization header")
        return False

    # In production, validate JWT token against Azure AD
    # This requires fetching keys from https://login.botframework.com/v1/.well-known/openidconfiguration
    # For development, we'll accept the request

    return True


@router.post("/messages")
async def handle_bot_message(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: AsyncSession = Depends(get_db_session),
):
    """
    Handle incoming Bot Framework activity.

    This is the main endpoint that Teams calls when users interact with the bot,
    including clicking action buttons on Adaptive Cards.
    """
    try:
        # Parse the activity
        body = await request.json()
        activity_type = body.get("type", "")

        logger.info(
            "Received Bot Framework activity",
            activity_type=activity_type,
            conversation_id=body.get("conversation", {}).get("id", ""),
        )

        if activity_type == "invoke":
            # This is an action button click
            return await handle_adaptive_card_action(body, settings, db)

        elif activity_type == "message":
            # Regular message - acknowledge receipt
            return {"type": "message", "text": "Use the action buttons on alert cards to interact."}

        elif activity_type == "conversationUpdate":
            # Bot was added to a conversation
            members_added = body.get("membersAdded", [])
            for member in members_added:
                if member.get("id") == body.get("recipient", {}).get("id"):
                    # Bot itself was added
                    logger.info("Bot added to conversation")
            return {}

        else:
            # Unknown activity type - acknowledge
            return {}

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    except Exception as e:
        logger.error("Error handling bot message", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


async def handle_adaptive_card_action(
    activity: dict[str, Any],
    settings: Settings,
    db: AsyncSession,
) -> dict[str, Any]:
    """
    Handle an action button click from an Adaptive Card.

    Args:
        activity: The Bot Framework activity.
        settings: Application settings.
        db: Database session.

    Returns:
        Response to send back to Teams.
    """
    # Get action data from the card
    action_data = activity.get("value", {})
    action_type = action_data.get("action", "")
    alert_id = action_data.get("alert_id", "")
    source = action_data.get("source", "")
    hostname = action_data.get("hostname", "")
    ticket_id = action_data.get("ticket_id", "")

    # Get user info
    from_user = activity.get("from", {})
    user_name = from_user.get("name", "Unknown User")

    # Get conversation info for replies
    conversation_id = activity.get("conversation", {}).get("id", "")
    activity_id = activity.get("replyToId", activity.get("id", ""))

    logger.info(
        "Processing Teams action",
        action=action_type,
        alert_id=alert_id,
        source=source,
        user=user_name,
    )

    try:
        if action_type == "resolve":
            result = await handle_resolve_action(
                alert_id=alert_id,
                source=source,
                hostname=hostname,
                performed_by=user_name,
                ticket_id=ticket_id,
                conversation_id=conversation_id,
                settings=settings,
                db=db,
            )

        elif action_type == "contain":
            result = await handle_contain_action(
                alert_id=alert_id,
                source=source,
                hostname=hostname,
                performed_by=user_name,
                ticket_id=ticket_id,
                conversation_id=conversation_id,
                settings=settings,
                db=db,
            )

        elif action_type == "escalate":
            result = await handle_escalate_action(
                alert_id=alert_id,
                source=source,
                hostname=hostname,
                performed_by=user_name,
                ticket_id=ticket_id,
                conversation_id=conversation_id,
                settings=settings,
                db=db,
            )

        else:
            logger.warning(f"Unknown action type: {action_type}")
            result = {"success": False, "message": f"Unknown action: {action_type}"}

        # Return invoke response
        return {
            "status": 200,
            "body": {
                "type": "message",
                "text": result.get("message", "Action completed"),
            },
        }

    except Exception as e:
        logger.error(
            "Failed to process action",
            action=action_type,
            error=str(e),
        )
        return {
            "status": 500,
            "body": {
                "type": "message",
                "text": f"Action failed: {str(e)}",
            },
        }


async def handle_resolve_action(
    alert_id: str,
    source: str,
    hostname: str,
    performed_by: str,
    ticket_id: str,
    conversation_id: str,
    settings: Settings,
    db: AsyncSession,
) -> dict[str, Any]:
    """Handle the resolve action."""
    from ..services import AlertProcessor

    processor = AlertProcessor(settings, db)

    try:
        success = await processor.resolve_alert(
            source=source,
            alert_id=alert_id,
            performed_by=performed_by,
            comment=f"Resolved via Teams by {performed_by}",
        )

        if success:
            # Add note to ticket if we have one
            if ticket_id:
                psa = PSAService(settings, db)
                await psa.add_note_to_ticket(
                    ticket_id=ticket_id,
                    content=f"Alert resolved via Teams by {performed_by}",
                    is_internal=False,
                    author=performed_by,
                )
                await psa.close()

            # Send notification
            notification = NotificationService(settings, db)
            await notification.send_text_message(
                channel_id=conversation_id,
                text=f"**Resolved** - Alert on {hostname} resolved by {performed_by}",
            )
            await notification.close()

            return {
                "success": True,
                "message": f"Alert resolved successfully by {performed_by}",
            }
        else:
            return {
                "success": False,
                "message": "Failed to resolve alert in EDR",
            }

    finally:
        await processor.close()


async def handle_contain_action(
    alert_id: str,
    source: str,
    hostname: str,
    performed_by: str,
    ticket_id: str,
    conversation_id: str,
    settings: Settings,
    db: AsyncSession,
) -> dict[str, Any]:
    """Handle the contain endpoint action."""
    from ..services import AlertProcessor

    processor = AlertProcessor(settings, db)

    try:
        # Note: We need the agent_id, not alert_id for containment
        # In a real scenario, we'd look this up from the alert
        # For now, we'll use the alert_id which may need mapping
        success = await processor.contain_endpoint(
            source=source,
            agent_id=alert_id,  # This should ideally be the actual agent_id
            performed_by=performed_by,
            hostname=hostname,
            comment=f"Contained via Teams by {performed_by}",
        )

        if success:
            # Add note to ticket
            if ticket_id:
                psa = PSAService(settings, db)
                await psa.add_note_to_ticket(
                    ticket_id=ticket_id,
                    content=f"Endpoint {hostname} network isolated by {performed_by}",
                    is_internal=False,
                    author=performed_by,
                )
                await psa.close()

            # Send notification
            notification = NotificationService(settings, db)
            await notification.send_containment_notification(
                alert=None,  # We don't have the full alert here
                contained_by=performed_by,
                success=True,
                channel_id=conversation_id,
                hostname=hostname,
            )
            await notification.close()

            return {
                "success": True,
                "message": f"Endpoint {hostname} has been network isolated by {performed_by}",
            }
        else:
            return {
                "success": False,
                "message": "Failed to contain endpoint in EDR",
            }

    finally:
        await processor.close()


async def handle_escalate_action(
    alert_id: str,
    source: str,
    hostname: str,
    performed_by: str,
    ticket_id: str,
    conversation_id: str,
    settings: Settings,
    db: AsyncSession,
) -> dict[str, Any]:
    """Handle the escalate action."""
    try:
        # Update ticket priority and add note
        if ticket_id:
            from ..adapters.psa.base import TicketPriority

            psa = PSAService(settings, db)
            await psa.add_note_to_ticket(
                ticket_id=ticket_id,
                content=f"ESCALATED by {performed_by}\n\nThis alert requires senior engineer review.",
                is_internal=False,
                author=performed_by,
            )
            await psa.close()

        # Send escalation notification
        notification = NotificationService(settings, db)
        text = (
            f"**ESCALATION**\n\n"
            f"Alert on **{hostname}** has been escalated by {performed_by}\n"
            f"Source: {source.upper()}\n"
            f"Alert ID: {alert_id}\n\n"
            f"*Awaiting senior engineer review*"
        )
        await notification.send_text_message(
            channel_id=conversation_id,
            text=text,
        )
        await notification.close()

        return {
            "success": True,
            "message": f"Alert escalated by {performed_by}",
        }

    except Exception as e:
        logger.error("Escalation failed", error=str(e))
        return {
            "success": False,
            "message": f"Escalation failed: {str(e)}",
        }


# Endpoint for Teams to verify the bot messaging endpoint
@router.get("/messages")
async def verify_endpoint():
    """Health check endpoint for Bot Framework."""
    return {"status": "ok", "message": "Security Alerting Bot is running"}
