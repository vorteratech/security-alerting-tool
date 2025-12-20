"""
Authentication module for the Security Alerting Tool.

Provides simple password-based authentication with session cookies.
"""

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

from ..config.logging import get_logger
from ..config.settings import get_settings

logger = get_logger(__name__)

router = APIRouter()

# In-memory session store (for simplicity - could use Redis or DB for production)
_sessions: dict[str, datetime] = {}

# Session duration
SESSION_DURATION = timedelta(hours=24)


class AuthStatus(BaseModel):
    """Authentication status response."""
    authenticated: bool
    message: str = ""


def _get_session_secret() -> str:
    """Get or generate session signing secret."""
    settings = get_settings()
    secret = settings.security.session_secret
    if not secret:
        # Fall back to using part of the encryption key if no session secret
        if settings.master_encryption_key:
            secret = settings.master_encryption_key[:32]
        else:
            # Generate a random secret (will change on restart)
            secret = secrets.token_hex(16)
    return secret


def _hash_password(password: str) -> str:
    """Hash a password for comparison."""
    secret = _get_session_secret()
    return hashlib.sha256(f"{password}:{secret}".encode()).hexdigest()


def _create_session() -> str:
    """Create a new session and return the session token."""
    token = secrets.token_urlsafe(32)
    _sessions[token] = datetime.utcnow() + SESSION_DURATION

    # Clean up expired sessions
    now = datetime.utcnow()
    expired = [k for k, v in _sessions.items() if v < now]
    for k in expired:
        del _sessions[k]

    return token


def _validate_session(token: Optional[str]) -> bool:
    """Check if a session token is valid."""
    if not token:
        return False

    expiry = _sessions.get(token)
    if not expiry:
        return False

    if datetime.utcnow() > expiry:
        del _sessions[token]
        return False

    return True


def _invalidate_session(token: str) -> None:
    """Invalidate a session."""
    if token in _sessions:
        del _sessions[token]


def get_app_password() -> str:
    """Get the configured app password."""
    settings = get_settings()
    return settings.security.app_password


def is_auth_enabled() -> bool:
    """Check if authentication is enabled (password is set)."""
    password = get_app_password()
    return bool(password and password.strip())


async def require_auth(
    request: Request,
    session_token: Optional[str] = Cookie(default=None, alias="session"),
) -> bool:
    """
    Dependency that requires authentication.

    Raises HTTPException 401 if not authenticated.
    """
    # If no password is set, allow access
    if not is_auth_enabled():
        return True

    # Check session
    if _validate_session(session_token):
        return True

    # Not authenticated - redirect to login for browser requests
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        raise HTTPException(
            status_code=303,
            headers={"Location": "/login"}
        )

    # For API requests, return 401
    raise HTTPException(
        status_code=401,
        detail="Authentication required"
    )


async def check_auth(
    session_token: Optional[str] = Cookie(default=None, alias="session"),
) -> bool:
    """
    Dependency that checks authentication without raising.

    Returns True if authenticated, False otherwise.
    """
    if not is_auth_enabled():
        return True
    return _validate_session(session_token)


@router.post("/login")
async def login(
    response: Response,
    password: str = Form(...),
):
    """
    Authenticate with password and create session.
    """
    app_password = get_app_password()

    if not app_password:
        # No password set - redirect to home
        return RedirectResponse(url="/", status_code=303)

    if password == app_password:
        # Create session
        token = _create_session()

        # Set cookie
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(
            key="session",
            value=token,
            httponly=True,
            secure=False,  # Set to True in production with HTTPS
            samesite="lax",
            max_age=int(SESSION_DURATION.total_seconds()),
        )

        logger.info("User logged in successfully")
        return response

    logger.warning("Failed login attempt")
    # Invalid password - redirect back to login with error
    return RedirectResponse(url="/login?error=1", status_code=303)


@router.post("/logout")
async def logout(
    response: Response,
    session_token: Optional[str] = Cookie(default=None, alias="session"),
):
    """
    Log out and invalidate session.
    """
    if session_token:
        _invalidate_session(session_token)

    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("session")

    logger.info("User logged out")
    return response


@router.get("/auth/status")
async def auth_status(
    is_authenticated: bool = Depends(check_auth),
) -> AuthStatus:
    """
    Check current authentication status.
    """
    return AuthStatus(
        authenticated=is_authenticated,
        message="Authenticated" if is_authenticated else "Not authenticated"
    )
