"""SQLAlchemy database models for settings and audit logging."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all database models."""

    pass


class IntegrationSetting(Base):
    """
    Stores configuration for each integration (EDR, AI, threat intel, PSA, chat).

    API keys are stored encrypted using AES-256-GCM.
    """

    __tablename__ = "integration_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Integration identification
    integration_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # edr, ai, threat_intel, psa, chat
    provider: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # sentinelone, crowdstrike, claude, etc.

    # Status
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_primary: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )  # Primary provider for this type

    # Configuration (JSON string for provider-specific settings)
    config_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Encrypted credentials (AES-256-GCM encrypted, base64 encoded)
    api_key_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    api_secret_encrypted: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # For providers needing key+secret

    # Additional encrypted fields for complex auth (e.g., OAuth tokens)
    extra_credentials_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Metadata
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return (
            f"<IntegrationSetting(type={self.integration_type}, "
            f"provider={self.provider}, enabled={self.enabled})>"
        )


class AuditLog(Base):
    """
    Audit log for compliance tracking.

    Records all actions taken via the system (resolve, contain, escalate, config changes).
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Timestamp
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False, index=True
    )

    # Action details
    action_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # resolve, contain, escalate, config_change, webhook_received, etc.

    # Alert context (if applicable)
    alert_source: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # sentinelone, crowdstrike
    alert_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )  # Original alert ID from EDR
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    client_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Who performed the action
    performed_by: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )  # Teams user email/name, or "system"

    # Result
    result: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # success, failure, pending

    # Additional context (JSON string)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Request tracking
    request_id: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )  # For correlating related actions

    def __repr__(self) -> str:
        return (
            f"<AuditLog(action={self.action_type}, "
            f"result={self.result}, timestamp={self.timestamp})>"
        )
