"""Pytest configuration and fixtures."""

import asyncio
import os
from typing import AsyncGenerator, Generator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

# Set test environment
os.environ["MASTER_ENCRYPTION_KEY"] = "0" * 64  # Test key


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an event loop for the test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    from src.database.connection import close_db, get_db, init_db

    # Use in-memory database for tests
    await init_db(":memory:")

    async with get_db() as session:
        yield session

    await close_db()


@pytest.fixture
def sample_s1_webhook_payload() -> dict:
    """Sample SentinelOne webhook payload."""
    return {
        "eventType": "threat",
        "data": {
            "id": "test-alert-123",
            "threatInfo": {
                "threatName": "Cobalt Strike Beacon",
                "classification": "Malware",
                "confidenceLevel": "high",
                "analystVerdict": "undefined",
            },
            "agentRealtimeInfo": {
                "agentComputerName": "WORKSTATION-01",
                "agentOsName": "Windows 11 Pro",
                "agentOsRevision": "22631",
                "siteName": "Acme Corp",
                "agentIpAddress": "192.168.1.100",
            },
            "indicators": [
                {
                    "category": "file",
                    "sha256": "a" * 64,
                    "sha1": "b" * 40,
                    "md5": "c" * 32,
                    "filePath": "C:\\Users\\jsmith\\Downloads\\update.exe",
                }
            ],
        },
    }


@pytest.fixture
def sample_cs_webhook_payload() -> dict:
    """Sample CrowdStrike webhook payload."""
    return {
        "metadata": {
            "eventType": "DetectionSummaryEvent",
            "version": "1.0",
        },
        "body": {
            "detection_id": "ldt:test-detection-456",
            "severity": 4,
            "computer_name": "SERVER-01",
            "user_name": "admin",
            "os_version": "Windows Server 2022",
            "local_ip": "10.0.0.50",
            "file_name": "malware.exe",
            "file_path": "\\Device\\HarddiskVolume3\\Windows\\Temp\\malware.exe",
            "sha256": "d" * 64,
            "cmdline": "cmd.exe /c malware.exe",
            "tactic": "Execution",
            "technique": "T1059",
        },
    }


@pytest.fixture
def encryption_service():
    """Create an encryption service for testing."""
    from src.security.encryption import EncryptionService

    test_key = bytes.fromhex("0" * 64)
    return EncryptionService(test_key)
