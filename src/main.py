"""
Security Alerting Tool - Main Application Entry Point.

FastAPI application for processing EDR alerts, enriching with threat intelligence,
analyzing with AI, and dispatching to PSA and chat platforms.
"""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from .api import webhooks, actions, settings_api, teams_bot, auth
from .api.auth import is_auth_enabled, check_auth
from .config.logging import get_logger, setup_logging
from .config.settings import get_settings
from .database.connection import close_db, init_db

# Initialize logger
logger = get_logger(__name__)

# Paths that don't require authentication
PUBLIC_PATHS = {
    "/health",
    "/login",
    "/webhooks",
    "/static",
    "/favicon.ico",
}


class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce authentication on protected routes."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Check if path is public (doesn't require auth)
        is_public = False
        for public_path in PUBLIC_PATHS:
            if path == public_path or path.startswith(f"{public_path}/"):
                is_public = True
                break

        # If auth is not enabled, allow all requests
        if not is_auth_enabled():
            return await call_next(request)

        # If path is public, allow
        if is_public:
            return await call_next(request)

        # Check authentication via session cookie
        session_token = request.cookies.get("session")
        is_authenticated = await check_auth(session_token)

        if is_authenticated:
            return await call_next(request)

        # Not authenticated - redirect to login for browser, 401 for API
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            return RedirectResponse(url="/login", status_code=303)

        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication required"}
        )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager.

    Handles startup and shutdown events.
    """
    # Startup
    settings = get_settings()
    setup_logging(settings)

    logger.info(
        "Starting Security Alerting Tool",
        version="0.1.0",
        host=settings.server.host,
        port=settings.server.port,
    )

    # Initialize database
    await init_db(settings.database.path)
    logger.info("Database initialized", path=settings.database.path)

    yield

    # Shutdown
    logger.info("Shutting down Security Alerting Tool")
    await close_db()


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application.
    """
    settings = get_settings()

    app = FastAPI(
        title="Security Alerting Tool",
        description=(
            "MSP security alerting tool that processes EDR detections, "
            "enriches with threat intelligence, analyzes with AI, "
            "and creates tickets and chat alerts."
        ),
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.server.debug else None,
        redoc_url="/redoc" if settings.server.debug else None,
    )

    # CORS middleware (configure as needed for Teams Bot)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Restrict in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Authentication middleware (must be added after CORS)
    app.add_middleware(AuthMiddleware)

    # Include routers
    app.include_router(auth.router, tags=["Auth"])
    app.include_router(webhooks.router, prefix="/webhooks", tags=["Webhooks"])
    app.include_router(actions.router, prefix="/actions", tags=["Actions"])
    app.include_router(settings_api.router, prefix="/api/settings", tags=["Settings"])
    app.include_router(teams_bot.router, prefix="/api/v1", tags=["Teams Bot"])

    # Mount static files
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Template directory for HTML pages
    templates_dir = Path(__file__).parent / "templates"

    # Login page route
    @app.get("/login", tags=["Auth"])
    async def login_page():
        """Serve the login page."""
        template_path = templates_dir / "login.html"
        if template_path.exists():
            return FileResponse(str(template_path), media_type="text/html")
        return JSONResponse(
            status_code=404,
            content={"detail": "Login page not found"}
        )

    # Settings page route
    @app.get("/", tags=["UI"])
    @app.get("/settings", tags=["UI"])
    async def settings_page():
        """Serve the settings configuration page."""
        template_path = templates_dir / "settings.html"
        if template_path.exists():
            return FileResponse(str(template_path), media_type="text/html")
        return JSONResponse(
            status_code=404,
            content={"detail": "Settings page not found"}
        )

    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(
            "Unhandled exception",
            error=str(exc),
            path=request.url.path,
            method=request.method,
            exc_info=exc,
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )

    # Health check endpoint
    @app.get("/health", tags=["Health"])
    async def health_check():
        """Health check endpoint for monitoring."""
        return {
            "status": "healthy",
            "version": "0.1.0",
            "service": "security-alerting-tool",
        }

    return app


# Create the application instance
app = create_app()


def main():
    """Run the application using uvicorn."""
    import uvicorn

    settings = get_settings()
    setup_logging(settings)

    uvicorn.run(
        "src.main:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=settings.server.debug,
        log_level=settings.logging.level.lower(),
    )


if __name__ == "__main__":
    main()
