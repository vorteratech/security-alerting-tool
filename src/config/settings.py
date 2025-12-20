"""Settings management using Pydantic and YAML configuration."""

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ServerSettings(BaseModel):
    """Server configuration."""

    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False


class LoggingSettings(BaseModel):
    """Logging configuration."""

    level: str = "INFO"
    format: str = "json"  # json or text


class DatabaseSettings(BaseModel):
    """Database configuration."""

    path: str = "./data/settings.db"


class SecuritySettings(BaseModel):
    """Security configuration."""

    verify_webhooks: bool = True
    encryption_key_env: str = "MASTER_ENCRYPTION_KEY"
    app_password: str = ""  # Password for web UI access
    session_secret: str = ""  # Secret for signing session cookies


class DefaultsSettings(BaseModel):
    """Default provider settings."""

    ai_provider: str = "claude"
    threat_intel_providers: list[str] = Field(default_factory=lambda: ["virustotal", "alienvault"])


class YAMLConfig(BaseModel):
    """Configuration loaded from YAML file."""

    server: ServerSettings = Field(default_factory=ServerSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    defaults: DefaultsSettings = Field(default_factory=DefaultsSettings)


class Settings(BaseSettings):
    """
    Application settings combining YAML config and environment variables.

    Environment variables take precedence over YAML config.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Environment variables (sensitive - not in YAML)
    master_encryption_key: Optional[str] = Field(default=None, alias="MASTER_ENCRYPTION_KEY")
    s1_webhook_secret: Optional[str] = Field(default=None, alias="S1_WEBHOOK_SECRET")
    cs_webhook_secret: Optional[str] = Field(default=None, alias="CS_WEBHOOK_SECRET")
    teams_bot_app_id: Optional[str] = Field(default=None, alias="TEAMS_BOT_APP_ID")
    teams_bot_app_secret: Optional[str] = Field(default=None, alias="TEAMS_BOT_APP_SECRET")

    # Action callback URL (base URL for Teams bot action callbacks)
    action_callback_base_url: str = Field(
        default="http://localhost:8000/api/v1/actions",
        alias="ACTION_CALLBACK_URL"
    )

    # YAML configuration (loaded separately)
    _yaml_config: Optional[YAMLConfig] = None

    def __init__(self, config_path: Optional[str] = None, **kwargs):
        super().__init__(**kwargs)
        self._load_yaml_config(config_path)

    def _load_yaml_config(self, config_path: Optional[str] = None) -> None:
        """Load configuration from YAML file."""
        if config_path is None:
            # Look for config.yaml in common locations
            possible_paths = [
                Path("config.yaml"),
                Path("./config.yaml"),
                Path("/app/config.yaml"),
                Path.home() / ".security-alerting-tool" / "config.yaml",
            ]
            for path in possible_paths:
                if path.exists():
                    config_path = str(path)
                    break

        if config_path and Path(config_path).exists():
            with open(config_path, "r") as f:
                yaml_data = yaml.safe_load(f) or {}
            self._yaml_config = YAMLConfig(**yaml_data)
        else:
            self._yaml_config = YAMLConfig()

    @property
    def server(self) -> ServerSettings:
        """Get server settings."""
        return self._yaml_config.server if self._yaml_config else ServerSettings()

    @property
    def logging(self) -> LoggingSettings:
        """Get logging settings."""
        return self._yaml_config.logging if self._yaml_config else LoggingSettings()

    @property
    def database(self) -> DatabaseSettings:
        """Get database settings."""
        return self._yaml_config.database if self._yaml_config else DatabaseSettings()

    @property
    def security(self) -> SecuritySettings:
        """Get security settings."""
        return self._yaml_config.security if self._yaml_config else SecuritySettings()

    @property
    def defaults(self) -> DefaultsSettings:
        """Get default provider settings."""
        return self._yaml_config.defaults if self._yaml_config else DefaultsSettings()

    def get_encryption_key(self) -> bytes:
        """
        Get the master encryption key as bytes.

        Raises:
            ValueError: If encryption key is not set or invalid.
        """
        if not self.master_encryption_key:
            raise ValueError(
                "MASTER_ENCRYPTION_KEY environment variable is not set. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

        try:
            # Key should be a 64-character hex string (32 bytes)
            key_bytes = bytes.fromhex(self.master_encryption_key)
            if len(key_bytes) != 32:
                raise ValueError("Encryption key must be exactly 32 bytes (64 hex characters)")
            return key_bytes
        except ValueError as e:
            raise ValueError(f"Invalid encryption key format: {e}")


@lru_cache()
def get_settings(config_path: Optional[str] = None) -> Settings:
    """
    Get cached settings instance.

    Args:
        config_path: Optional path to config.yaml file.

    Returns:
        Settings instance.
    """
    return Settings(config_path=config_path)
